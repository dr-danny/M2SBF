"""Stdlib unittest suite for research.inputs.

Covers: fail-closed lock verification (missing file, byte mismatch, hash
mismatch, path escape); NAICS/control-id normalization helpers; ATT&CK
active/subtechnique-rollup/reconnaissance-resource-development-drop
normalization; exact-id no-enhancement-inheritance CTID control coverage
with version-override quarantine; per-record path-credit and
max-across-paths incident credit computation; duplicate-incident-id
grouping; safe (non-extractall) tar.gz member iteration including a
malformed-JSON member and a path-traversal member; and the NIST LOW
control catalog / module-order / related-edge join logic against small
synthetic OSCAL-shaped fixtures. A final integration test exercises
``load_inputs`` end to end against the real pinned bundle when it is
available on disk, and is skipped (not failed) otherwise.
"""

from __future__ import annotations

import io
import json
import os
import tarfile
import unittest
from pathlib import Path

from research import inputs

REAL_INPUT_ROOT = Path(os.environ.get("M2SBF_INPUT_ROOT", "research-data"))
REAL_RESEARCH_DIR = Path(__file__).resolve().parents[1]


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


class VerifyLockTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(self._get_tmp_dir())
        self.target = self.tmp / "file.json"
        self.target.write_text('{"a": 1}', encoding="utf-8")
        self.sha = inputs._sha256_file(self.target)
        self.size = self.target.stat().st_size
        self.lock = {
            "files": [
                {
                    "role": "thing",
                    "path": "file.json",
                    "sha256": self.sha,
                    "bytes": self.size,
                }
            ]
        }

    def _get_tmp_dir(self) -> str:
        import tempfile

        d = tempfile.mkdtemp(prefix="verify_lock_test_")
        self.addCleanup(lambda: __import__("shutil").rmtree(d, ignore_errors=True))
        return d

    def test_valid_lock_resolves_role_to_path(self) -> None:
        resolved = inputs.verify_lock(self.tmp, self.lock)
        self.assertEqual(resolved["thing"].resolve(), self.target.resolve())

    def test_missing_file_raises(self) -> None:
        bad_lock = {
            "files": [
                {"role": "thing", "path": "nope.json", "sha256": self.sha, "bytes": 1}
            ]
        }
        with self.assertRaises(inputs.LockVerificationError):
            inputs.verify_lock(self.tmp, bad_lock)

    def test_byte_length_mismatch_raises(self) -> None:
        bad_lock = {
            "files": [
                {
                    "role": "thing",
                    "path": "file.json",
                    "sha256": self.sha,
                    "bytes": self.size + 1,
                }
            ]
        }
        with self.assertRaises(inputs.LockVerificationError):
            inputs.verify_lock(self.tmp, bad_lock)

    def test_hash_mismatch_raises(self) -> None:
        bad_lock = {
            "files": [
                {
                    "role": "thing",
                    "path": "file.json",
                    "sha256": "0" * 64,
                    "bytes": self.size,
                }
            ]
        }
        with self.assertRaises(inputs.LockVerificationError):
            inputs.verify_lock(self.tmp, bad_lock)

    def test_path_escape_raises(self) -> None:
        # A sibling file outside the verification root, referenced via '..'.
        outside = self.tmp.parent / "outside_escape_test.json"
        outside.write_text('{"z": 1}', encoding="utf-8")
        self.addCleanup(lambda: outside.unlink(missing_ok=True))
        escape_sha = inputs._sha256_file(outside)
        escape_lock = {
            "files": [
                {
                    "role": "thing",
                    "path": f"../{outside.name}",
                    "sha256": escape_sha,
                    "bytes": outside.stat().st_size,
                }
            ]
        }
        with self.assertRaises(inputs.LockVerificationError):
            inputs.verify_lock(self.tmp, escape_lock)

    def test_missing_files_list_raises(self) -> None:
        with self.assertRaises(inputs.LockVerificationError):
            inputs.verify_lock(self.tmp, {})


class NaicsPrefixTests(unittest.TestCase):
    def test_six_digit_code_yields_two_digit_prefix(self) -> None:
        self.assertEqual(inputs.naics_prefix("541611"), "54")

    def test_none_and_short_and_nondigit_are_rejected(self) -> None:
        self.assertIsNone(inputs.naics_prefix(None))
        self.assertIsNone(inputs.naics_prefix("5"))
        self.assertIsNone(inputs.naics_prefix("NA"))
        self.assertIsNone(inputs.naics_prefix(541611))

    def test_sector_lookup_matches_spec_shape(self) -> None:
        sectors = {
            "professional": ["54"],
            "manufacturing": ["31", "32", "33"],
        }
        lookup = inputs.sector_lookup_from_spec(sectors)
        self.assertEqual(lookup["54"], "professional")
        self.assertEqual(lookup["32"], "manufacturing")
        self.assertNotIn("44", lookup)


class ControlIdNormalizationTests(unittest.TestCase):
    def test_zero_padded_family_number_forms(self) -> None:
        self.assertEqual(inputs.normalize_ctid_control_id("CM-03"), "cm-3")
        self.assertEqual(inputs.normalize_ctid_control_id("AC-02"), "ac-2")
        self.assertEqual(inputs.normalize_ctid_control_id("SC-12"), "sc-12")

    def test_enhancement_shaped_and_junk_ids_reject(self) -> None:
        self.assertIsNone(inputs.normalize_ctid_control_id("AC-2(1)"))
        self.assertIsNone(inputs.normalize_ctid_control_id(""))
        self.assertIsNone(inputs.normalize_ctid_control_id(None))
        self.assertIsNone(inputs.normalize_ctid_control_id("not-an-id"))


class AttackNormalizeAndRollupTests(unittest.TestCase):
    def setUp(self) -> None:
        # A tiny synthetic active/inactive/subtechnique/tactic universe.
        self.attack_index = {
            "T1001": {  # active base technique, ordinary tactic
                "stix_id": "s-1001",
                "is_subtechnique": False,
                "active": True,
                "tactics": {"exfiltration"},
            },
            "T1001.001": {  # active subtechnique of T1001
                "stix_id": "s-1001-001",
                "is_subtechnique": True,
                "active": True,
                "tactics": {"exfiltration"},
            },
            "T1595": {  # active, ONLY reconnaissance -> must be dropped
                "stix_id": "s-1595",
                "is_subtechnique": False,
                "active": True,
                "tactics": {"reconnaissance"},
            },
            "T1583": {  # active, both recon and resource-dev -> dropped
                "stix_id": "s-1583",
                "is_subtechnique": False,
                "active": True,
                "tactics": {"reconnaissance", "resource-development"},
            },
            "T1499": {  # active, recon + a real tactic -> retained
                "stix_id": "s-1499",
                "is_subtechnique": False,
                "active": True,
                "tactics": {"reconnaissance", "impact"},
            },
            "T1999": {  # revoked -> inactive
                "stix_id": "s-1999",
                "is_subtechnique": False,
                "active": False,
                "tactics": {"execution"},
            },
            "T1998.001": {  # subtechnique whose parent is inactive
                "stix_id": "s-1998-001",
                "is_subtechnique": True,
                "active": True,
                "tactics": {"execution"},
            },
            "T1998": {
                "stix_id": "s-1998",
                "is_subtechnique": False,
                "active": False,
                "tactics": {"execution"},
            },
        }
        self.parent_of = {"T1001.001": "T1001", "T1998.001": "T1998"}

    def test_base_active_technique_passes_through(self) -> None:
        canonical, reason = inputs.normalize_and_rollup(
            "T1001", self.attack_index, self.parent_of
        )
        self.assertEqual(canonical, "T1001")
        self.assertIsNone(reason)

    def test_subtechnique_rolls_up_to_active_parent(self) -> None:
        canonical, reason = inputs.normalize_and_rollup(
            "T1001.001", self.attack_index, self.parent_of
        )
        self.assertEqual(canonical, "T1001")
        self.assertIsNone(reason)

    def test_unknown_id_is_quarantined(self) -> None:
        canonical, reason = inputs.normalize_and_rollup(
            "T9999", self.attack_index, self.parent_of
        )
        self.assertIsNone(canonical)
        self.assertEqual(reason, "unknown_attack_id")

    def test_inactive_technique_is_quarantined(self) -> None:
        canonical, reason = inputs.normalize_and_rollup(
            "T1999", self.attack_index, self.parent_of
        )
        self.assertIsNone(canonical)
        self.assertEqual(reason, "inactive_attack_id")

    def test_subtechnique_with_inactive_parent_is_quarantined(self) -> None:
        canonical, reason = inputs.normalize_and_rollup(
            "T1998.001", self.attack_index, self.parent_of
        )
        self.assertIsNone(canonical)
        self.assertEqual(reason, "inactive_parent")

    def test_subtechnique_missing_parent_link_is_quarantined(self) -> None:
        index = dict(self.attack_index)
        index["T1700.001"] = {
            "stix_id": "s-1700-001",
            "is_subtechnique": True,
            "active": True,
            "tactics": {"execution"},
        }
        canonical, reason = inputs.normalize_and_rollup("T1700.001", index, {})
        self.assertIsNone(canonical)
        self.assertEqual(reason, "missing_parent_link")

    def test_recon_only_technique_is_dropped(self) -> None:
        canonical, reason = inputs.normalize_and_rollup(
            "T1595", self.attack_index, self.parent_of
        )
        self.assertIsNone(canonical)
        self.assertEqual(reason, "recon_resource_dev_only")

    def test_recon_and_resource_dev_only_technique_is_dropped(self) -> None:
        canonical, reason = inputs.normalize_and_rollup(
            "T1583", self.attack_index, self.parent_of
        )
        self.assertIsNone(canonical)
        self.assertEqual(reason, "recon_resource_dev_only")

    def test_recon_plus_other_tactic_is_retained(self) -> None:
        # Only techniques whose tactics are a nonempty SUBSET of
        # {reconnaissance, resource-development} are dropped; a technique
        # that also carries a real tactic must survive.
        canonical, reason = inputs.normalize_and_rollup(
            "T1499", self.attack_index, self.parent_of
        )
        self.assertEqual(canonical, "T1499")
        self.assertIsNone(reason)


class BuildControlCoverageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.attack_index = {
            "T1001": {"is_subtechnique": False, "active": True, "tactics": {"exfiltration"}},
            "T1001.001": {
                "is_subtechnique": True,
                "active": True,
                "tactics": {"exfiltration"},
            },
            "T1595": {"is_subtechnique": False, "active": True, "tactics": {"reconnaissance"}},
        }
        self.parent_of = {"T1001.001": "T1001"}
        self.mapping = {
            "metadata": {"attack_version": "16.1"},
            "mapping_objects": [
                {
                    "capability_id": "AC-02",
                    "mapping_type": "mitigates",
                    "attack_object_id": "T1001.001",
                    "status": "complete",
                },
                {
                    "capability_id": "AC-02",
                    "mapping_type": "mitigates",
                    "attack_object_id": "T1595",
                    "status": "complete",
                },
                {
                    # enhancement-form capability_id: never normalizes, so
                    "capability_id": "AC-2(1)",
                    "mapping_type": "mitigates",
                    "attack_object_id": "T1001",
                    "status": "complete",
                },
                {
                    # version override that does not match the base version
                    "capability_id": "AC-03",
                    "mapping_type": "mitigates",
                    "attack_object_id": "T1001",
                    "status": "complete",
                    "attack_version": "9.0",
                },
                {
                    # non_mappable rows are ignored entirely
                    "capability_id": None,
                    "mapping_type": None,
                    "attack_object_id": "T1234",
                    "status": "non_mappable",
                },
                {
                    # a row for a control that is not in our LOW selection
                    "capability_id": "ZZ-99",
                    "mapping_type": "mitigates",
                    "attack_object_id": "T1001",
                    "status": "complete",
                },
            ],
        }
        self.control_ids = ["ac-2", "ac-2.1", "ac-3"]

    def test_exact_id_join_and_no_enhancement_inheritance(self) -> None:
        coverage, quarantine = inputs.build_control_coverage(
            self.control_ids, self.mapping, self.attack_index, self.parent_of
        )
        # ac-2 gets its own row, rolled up (T1001.001 -> T1001); the
        # recon-only T1595 row is quarantined and dropped.
        self.assertEqual(coverage["ac-2"], {"T1001"})
        # ac-2.1 (the enhancement) never appears as a literal capability_id
        # in CTID data, so it must NOT inherit ac-2's coverage.
        self.assertEqual(coverage["ac-2.1"], set())
        # ac-3's only row has a mismatched attack_version -> quarantined.
        self.assertEqual(coverage["ac-3"], set())
        self.assertEqual(quarantine.get("recon_resource_dev_only"), 1)
        self.assertEqual(quarantine.get("version_override_invalid"), 1)

    def test_unrelated_control_id_rows_are_ignored(self) -> None:
        coverage, _ = inputs.build_control_coverage(
            self.control_ids, self.mapping, self.attack_index, self.parent_of
        )
        self.assertNotIn("zz-99", coverage)


class ComputeIncidentCreditsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.attack_index = {
            "T1001": {"is_subtechnique": False, "active": True, "tactics": {"exfiltration"}},
            "T1002": {"is_subtechnique": False, "active": True, "tactics": {"exfiltration"}},
            "T1003": {"is_subtechnique": False, "active": True, "tactics": {"impact"}},
            "T1595": {"is_subtechnique": False, "active": True, "tactics": {"reconnaissance"}},
        }
        self.parent_of: dict = {}
        self.veris_index = {
            "action.hacking.variety.Phishing": ["T1001", "T1002"],
            "action.hacking.variety.Backdoor": ["T1001"],
            "action.malware.variety.C2": ["T1003"],
            "action.hacking.variety.OnlyRecon": ["T1595"],
        }
        self.exclude_values = {"Unknown", "Other"}

    def test_path_credit_split_and_max_across_paths(self) -> None:
        action_block = {
            "hacking": {"variety": ["Phishing", "Backdoor"]},
            "malware": {"variety": ["C2"]},
        }
        credits, quarantine = inputs.compute_incident_credits(
            action_block, self.veris_index, self.attack_index, self.parent_of, self.exclude_values
        )
        # Phishing path retains {T1001, T1002} -> credit 0.5 each.
        # Backdoor path retains {T1001} -> credit 1.0.
        # T1001's final credit is MAX(0.5, 1.0) = 1.0, not their sum.
        self.assertAlmostEqual(credits["T1001"], 1.0)
        self.assertAlmostEqual(credits["T1002"], 0.5)
        self.assertAlmostEqual(credits["T1003"], 1.0)
        self.assertEqual(len(quarantine), 0)

    def test_unknown_and_other_enumerations_are_skipped(self) -> None:
        action_block = {"hacking": {"variety": ["Unknown", "Other"]}}
        credits, _ = inputs.compute_incident_credits(
            action_block, self.veris_index, self.attack_index, self.parent_of, self.exclude_values
        )
        self.assertEqual(credits, {})

    def test_recon_only_path_contributes_nothing(self) -> None:
        action_block = {"hacking": {"variety": ["OnlyRecon"]}}
        credits, quarantine = inputs.compute_incident_credits(
            action_block, self.veris_index, self.attack_index, self.parent_of, self.exclude_values
        )
        self.assertEqual(credits, {})
        self.assertEqual(quarantine.get("recon_resource_dev_only"), 1)

    def test_non_variety_and_missing_action_are_ignored(self) -> None:
        credits, _ = inputs.compute_incident_credits(
            None, self.veris_index, self.attack_index, self.parent_of, self.exclude_values
        )
        self.assertEqual(credits, {})
        credits2, _ = inputs.compute_incident_credits(
            {"hacking": {"vector": ["Web application"]}},
            self.veris_index,
            self.attack_index,
            self.parent_of,
            self.exclude_values,
        )
        self.assertEqual(credits2, {})


class DuplicateIncidentIdTests(unittest.TestCase):
    def test_case_normalized_grouping_and_singletons_excluded(self) -> None:
        rows = [
            {"incident_id": "ABC-1", "n": 1},
            {"incident_id": "abc-1", "n": 2},
            {"incident_id": "XYZ-2", "n": 3},
            {"incident_id": "  xyz-2  ", "n": 4},
            {"incident_id": "unique-1", "n": 5},
        ]
        groups = inputs.find_duplicate_incident_id_groups(rows)
        self.assertEqual(set(groups.keys()), {"abc-1", "xyz-2"})
        self.assertEqual(len(groups["abc-1"]), 2)
        self.assertEqual(len(groups["xyz-2"]), 2)


class VcdbTarSafetyTests(unittest.TestCase):
    def _build_tar(self, tmp_dir: Path, members: dict) -> Path:
        tar_path = tmp_dir / "archive.tar.gz"
        with tarfile.open(tar_path, "w:gz") as tf:
            for name, content in members.items():
                data = content.encode("utf-8")
                info = tarfile.TarInfo(name=name)
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))
        return tar_path

    def test_reads_case_insensitive_json_under_all_three_statuses(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            members = {
                "REPO/data/json/validated/one.json": '{"incident_id": "1"}',
                "REPO/data/json/submitted/two.JSON": '{"incident_id": "2"}',
                "REPO/data/json/overridden/three.Json": '{"incident_id": "3"}',
                "REPO/README.md": "not a data file",
                "REPO/data/json/validated/notjson.txt": "ignored",
            }
            tar_path = self._build_tar(tmp, members)
            found = list(inputs.iter_vcdb_members(tar_path))
            names = {n for n, _, _ in found}
            self.assertEqual(len(found), 3)
            self.assertIn("REPO/data/json/validated/one.json", names)
            self.assertIn("REPO/data/json/submitted/two.JSON", names)
            self.assertIn("REPO/data/json/overridden/three.Json", names)
            statuses = {s for _, s, _ in found}
            self.assertEqual(statuses, {"validated", "submitted", "overridden"})

    def test_path_traversal_member_is_skipped(self) -> None:
        self.assertFalse(inputs.is_path_safe("../../etc/passwd"))
        self.assertFalse(inputs.is_path_safe("/etc/passwd"))
        self.assertFalse(
            inputs.is_path_safe("REPO/data/json/validated/../../../evil.json")
        )
        self.assertTrue(inputs.is_path_safe("REPO/data/json/validated/ok.json"))

    def test_malformed_json_member_is_readable_but_fails_to_parse(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            members = {
                "REPO/data/json/validated/bad.json": "{not valid json",
            }
            tar_path = self._build_tar(tmp, members)
            found = list(inputs.iter_vcdb_members(tar_path))
            self.assertEqual(len(found), 1)
            name, status, raw = found[0]
            self.assertEqual(status, "validated")
            with self.assertRaises(json.JSONDecodeError):
                json.loads(raw.decode("utf-8"))


def _synthetic_control(cid: str, sort_id: str, params: int = 0, status: str | None = None):
    props = [{"name": "sort-id", "value": sort_id}]
    if status:
        props.append({"name": "status", "value": status})
    return {
        "id": cid,
        "props": props,
        "params": [{"id": f"{cid}_p{i}"} for i in range(params)],
        "links": [],
    }


class ControlCatalogTests(unittest.TestCase):
    def setUp(self) -> None:
        ac1 = _synthetic_control("ac-1", "ac-01", params=2)
        ac2 = _synthetic_control("ac-2", "ac-02", params=1)
        ac2["controls"] = [_synthetic_control("ac-2.1", "ac-02.01", params=0)]
        ac2["links"] = [{"href": "#ac-3", "rel": "related"}, {"href": "#zz-99", "rel": "related"}]
        ac3 = _synthetic_control("ac-3", "ac-03", params=0)
        ac3["links"] = [{"href": "#ac-2", "rel": "related"}]
        au1 = _synthetic_control("au-1", "au-01", params=1)

        self.catalog = {
            "catalog": {
                "groups": [
                    {"id": "ac", "controls": [ac1, ac2, ac3]},
                    {"id": "au", "controls": [au1]},
                ]
            }
        }
        self.profile = {
            "profile": {
                "imports": [
                    {"include-controls": [{"with-ids": ["ac-1", "ac-2", "ac-2.1", "ac-3", "au-1"]}]}
                ]
            }
        }
        self.resolved = {
            "catalog": {
                "groups": [
                    {"id": "ac", "controls": [ac1, ac2, ac3]},
                    {"id": "au", "controls": [au1]},
                ]
            }
        }
        self.taxonomy = {
            "modules": [
                {"id": "M-IAM", "nist_families": ["AC"]},
                {"id": "M-LOG", "nist_families": ["AU"]},
                {"id": "M-EMPTY", "nist_families": []},
            ]
        }

    def test_natural_control_order_from_sort_id(self) -> None:
        controls, control_order, _ = inputs.build_control_catalog(
            self.catalog, self.profile, self.resolved, self.taxonomy
        )
        self.assertEqual(control_order, ["ac-1", "ac-2", "ac-2.1", "ac-3", "au-1"])
        self.assertEqual(controls["ac-2"]["parameter_count"], 1)
        self.assertEqual(controls["ac-1"]["parameter_count"], 2)
        self.assertEqual(controls["ac-2"]["module"], "M-IAM")
        self.assertEqual(controls["au-1"]["module"], "M-LOG")

    def test_module_order_first_distinct_plus_empty_appended(self) -> None:
        controls, control_order, _ = inputs.build_control_catalog(
            self.catalog, self.profile, self.resolved, self.taxonomy
        )
        module_order = inputs.build_module_order(control_order, controls, self.taxonomy)
        # AC-family controls appear before AU-family controls in
        # control_order, so M-IAM precedes M-LOG; M-EMPTY has no controls
        # at all and is appended afterward.
        self.assertEqual(module_order, ["M-IAM", "M-LOG", "M-EMPTY"])

    def test_related_edges_scoped_to_low_selection(self) -> None:
        _, control_order, catalog_index = inputs.build_control_catalog(
            self.catalog, self.profile, self.resolved, self.taxonomy
        )
        edges, outside_scope = inputs.build_related_edges(control_order, catalog_index)
        self.assertIn(("ac-2", "ac-3"), edges)
        self.assertIn(("ac-3", "ac-2"), edges)
        # ac-2 -> zz-99 is not in the LOW selection, so it must not appear
        # as an edge and must be counted as out-of-scope instead.
        self.assertNotIn(("ac-2", "zz-99"), edges)
        self.assertEqual(outside_scope, 1)

    def test_mismatched_profile_and_resolved_selection_raises(self) -> None:
        bad_resolved = {
            "catalog": {
                "groups": [
                    {"id": "ac", "controls": [_synthetic_control("ac-1", "ac-01")]}
                ]
            }
        }
        with self.assertRaises(ValueError):
            inputs.build_control_catalog(self.catalog, self.profile, bad_resolved, self.taxonomy)

    def test_duplicate_family_assignment_across_modules_raises(self) -> None:
        bad_taxonomy = {
            "modules": [
                {"id": "M-A", "nist_families": ["AC"]},
                {"id": "M-B", "nist_families": ["AC"]},
            ]
        }
        with self.assertRaises(ValueError):
            inputs.family_to_module_map(bad_taxonomy)


class RealDataIntegrationTests(unittest.TestCase):
    """End-to-end check against the real pinned bundle, when available.

    Skipped (not failed) when the pinned bundle or spec files are not
    present on disk, so this suite stays runnable in isolation.
    """

    @classmethod
    def setUpClass(cls) -> None:
        required = [
            REAL_INPUT_ROOT,
            REAL_RESEARCH_DIR / "spec.json",
            REAL_RESEARCH_DIR / "module_taxonomy.json",
            REAL_RESEARCH_DIR / "input-lock.json",
        ]
        if not all(p.exists() for p in required):
            raise unittest.SkipTest("real pinned input bundle not available")
        cls.spec = json.loads((REAL_RESEARCH_DIR / "spec.json").read_text())
        cls.taxonomy = json.loads((REAL_RESEARCH_DIR / "module_taxonomy.json").read_text())
        cls.lock = json.loads((REAL_RESEARCH_DIR / "input-lock.json").read_text())
        cls.result = inputs.load_inputs(REAL_INPUT_ROOT, cls.spec, cls.taxonomy, cls.lock)

    def test_low_selection_is_149_ids_in_natural_order(self) -> None:
        control_order = self.result["control_order"]
        self.assertEqual(len(control_order), 149)
        self.assertEqual(len(set(control_order)), 149)

        def natural_key(cid: str):
            # e.g. "ac-2.1" -> ("ac", 2, 1); "ac-2" -> ("ac", 2, -1) so a
            # base control sorts immediately before its own enhancements.
            base, _, enh = cid.partition(".")
            family, _, num = base.rpartition("-")
            return (family, int(num), int(enh) if enh else -1)

        self.assertEqual(control_order, sorted(control_order, key=natural_key))

    def test_every_module_in_taxonomy_is_present_in_module_order(self) -> None:
        taxonomy_ids = {m["id"] for m in self.taxonomy["modules"]}
        self.assertEqual(set(self.result["module_order"]), taxonomy_ids)

    def test_control_coverage_keys_match_control_order_exactly(self) -> None:
        self.assertEqual(set(self.result["control_coverage"].keys()), set(self.result["control_order"]))

    def test_no_enhancement_control_has_ctid_coverage(self) -> None:
        # Documented CTID scope: base controls only, never enhancements.
        for cid, techs in self.result["control_coverage"].items():
            if "." in cid:
                self.assertEqual(
                    techs, set(), f"enhancement {cid} unexpectedly has CTID coverage"
                )

    def test_module_coverage_equals_union_of_member_controls(self) -> None:
        controls = self.result["controls"]
        module_coverage = self.result["module_coverage"]
        expected: dict = {m: set() for m in self.result["module_order"]}
        for cid, techs in self.result["control_coverage"].items():
            mod = controls[cid]["module"]
            if mod is not None:
                expected[mod] |= techs
        self.assertEqual(module_coverage, expected)

    def test_related_edges_endpoints_are_all_low_selected(self) -> None:
        selected = set(self.result["control_order"])
        for src, dst in self.result["related_edges"]:
            self.assertIn(src, selected)
            self.assertIn(dst, selected)

    def test_records_are_nonempty_and_well_formed(self) -> None:
        records = self.result["records"]
        self.assertGreater(len(records), 0)
        target_sectors = set(self.spec["sectors"].keys())
        for rec in records[:50]:
            self.assertIn(rec["sector"], target_sectors)
            self.assertTrue(rec["source_path"])
            self.assertTrue(rec["incident_id"])
            self.assertIsInstance(rec["credits"], dict)
            self.assertGreater(len(rec["credits"]), 0)
            for tech_id, credit in rec["credits"].items():
                self.assertTrue(tech_id.startswith("T"))
                self.assertGreater(credit, 0.0)
                self.assertLessEqual(credit, 1.0)

    def test_no_duplicate_incident_ids_survive_into_records(self) -> None:
        seen: dict = {}
        for rec in self.result["records"]:
            key = rec["incident_id"].strip().lower()
            self.assertNotIn(key, seen, "a duplicate incident_id leaked into records")
            seen[key] = rec["source_path"]

    def test_audit_counts_are_internally_consistent(self) -> None:
        audit = self.result["audit"]
        total_exclusions = sum(audit["exclusions"].values())
        self.assertEqual(
            audit["counts"]["parsed_ok"] - total_exclusions,
            audit["counts"]["eligible_records"],
        )
        self.assertEqual(len(self.result["records"]), audit["counts"]["eligible_records"])
        self.assertEqual(len(self.result["audit_rows"]), audit["counts"]["source_files_total"])

    def test_audit_rows_have_no_raw_parsed_payload(self) -> None:
        for row in self.result["audit_rows"][:20]:
            self.assertNotIn("_data", row)


if __name__ == "__main__":
    unittest.main()
