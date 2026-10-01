"""Standard-library-only loader for the M2SBF public-data research pipeline.

This module reads the pinned, hash-verified raw inputs under a
``research-inputs`` bundle (NIST OSCAL Rev. 5 catalog/LOW profile, the CTID
NIST<->ATT&CK and VERIS<->ATT&CK mapping files, the MITRE ATT&CK Enterprise
STIX bundle, and the VCDB `full-repository.tar.gz` archive) and turns them
into the plain-data contract consumed by the rest of the research pipeline.

It performs no network access, executes no other repository's scripts, and
writes nothing. Every pinned file is re-verified against ``input-lock.json``
(path containment, byte length, SHA-256) before it is parsed; verification
fails closed -- any mismatch, missing file, or path escape raises
:class:`LockVerificationError` before a single byte of pinned content is
read for real work. The VCDB archive is only ever read member-by-member with
``TarFile.extractfile``; ``extractall`` is never used and any member whose
name would escape the archive root is skipped rather than trusted.

Contents
--------
1. Lock verification (`verify_lock`).
2. NIST OSCAL catalog / LOW-baseline control selection, family/module
   assignment, and natural (sort-id based) control ordering.
3. OSCAL `related`-link projection into a directed control graph, scoped to
   the selected LOW catalog only.
4. ATT&CK Enterprise STIX indexing: active/revoked/deprecated status,
   subtechnique -> parent rollup, and tactic-only reconnaissance /
   resource-development exclusion.
5. CTID `mitigates` (NIST) and `related_to` (VERIS action variety) mapping
   ingestion with per-row version-override and unresolved-ID quarantine.
6. Control coverage and module coverage (canonical active parent technique
   ID sets; no enhancement inheritance, no native-mitigation supplement).
7. Safe VCDB tar.gz ingestion, full source inventory, and eligibility
   pipeline (missing-id -> status -> duplicate-id -> sector -> version ->
   credit computation -> bootstrap eligibility), producing the mapped
   `records` list and a complete `audit` / `audit_rows` trail.

Everything here is a *computed* projection of the pinned inputs. Nothing is
a fitted or hand-copied count: control totals, coverage sizes, and record
counts all fall out of walking the actual pinned JSON/tar content.
"""

from __future__ import annotations

import hashlib
import json
import re
import tarfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import (
    Any,
    Dict,
    Iterable,
    Iterator,
    List,
    Mapping,
    Optional,
    Set,
    Tuple,
)

# ---------------------------------------------------------------------------
# 0. Lock verification (fail closed)
# ---------------------------------------------------------------------------


class LockVerificationError(RuntimeError):
    """Raised when a pinned input fails path/size/hash verification.

    Verification is fail-closed: any missing file, path that would escape
    the input root, byte-length mismatch, or SHA-256 mismatch raises this
    error immediately rather than continuing with an unverified file.
    """


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_lock(root: Path, lock: Mapping[str, Any]) -> Dict[str, Path]:
    """Verify every pinned file named in ``lock`` under ``root``.

    Parameters
    ----------
    root:
        Directory the pinned input bundle lives under (e.g. the
        ``research-inputs`` directory containing ``nist-ctid/`` and
        ``vcdb-veris/``).
    lock:
        Parsed ``input-lock.json`` content: a mapping with a ``files`` list
        of ``{role, path, sha256, bytes, ...}`` entries.

    Returns
    -------
    Mapping from each entry's ``role`` to its verified, resolved
    :class:`~pathlib.Path`.

    Raises
    ------
    LockVerificationError
        If ``root`` is not a directory, a lock entry is malformed, a pinned
        path is missing, a pinned path resolves outside ``root`` (path
        escape), the actual byte length does not match the lock, or the
        actual SHA-256 does not match the lock.
    """
    root = Path(root)
    try:
        root_resolved = root.resolve(strict=True)
    except OSError as exc:
        raise LockVerificationError(f"input root does not exist: {root}") from exc
    if not root_resolved.is_dir():
        raise LockVerificationError(f"input root is not a directory: {root}")

    resolved: Dict[str, Path] = {}
    entries = lock.get("files") if isinstance(lock, Mapping) else None
    if not isinstance(entries, list) or not entries:
        raise LockVerificationError("lock has no 'files' list")

    for entry in entries:
        if not isinstance(entry, Mapping):
            raise LockVerificationError(f"lock entry is not an object: {entry!r}")
        role = entry.get("role")
        rel_path = entry.get("path")
        expected_hash = entry.get("sha256")
        if (not isinstance(role, str) or not role or not isinstance(rel_path, str)
                or not rel_path or not isinstance(expected_hash, str)
                or not re.fullmatch(r"[0-9a-fA-F]{64}", expected_hash)
                or type(entry.get("bytes")) is not int or entry["bytes"] < 0):
            raise LockVerificationError("lock entry requires role, path, SHA256 and nonnegative integer bytes")
        if role in resolved:
            raise LockVerificationError(f"duplicate locked role: {role}")
        if Path(rel_path).is_absolute():
            raise LockVerificationError(f"locked path must be relative: {role}")

        candidate = root_resolved / str(rel_path)
        try:
            candidate_resolved = candidate.resolve(strict=True)
        except OSError as exc:
            raise LockVerificationError(
                f"{role}: pinned file missing on disk: {rel_path!r}"
            ) from exc

        # Fail closed on path escape: the resolved candidate must remain
        # inside the resolved root, regardless of any '..' or symlink
        # trickery in the recorded relative path.
        try:
            candidate_resolved.relative_to(root_resolved)
        except ValueError as exc:
            raise LockVerificationError(
                f"{role}: pinned path escapes the input root: {rel_path!r}"
            ) from exc

        if not candidate_resolved.is_file():
            raise LockVerificationError(f"{role}: not a regular file: {rel_path!r}")

        expected_bytes = entry.get("bytes")
        actual_bytes = candidate_resolved.stat().st_size
        if expected_bytes is not None and actual_bytes != expected_bytes:
            raise LockVerificationError(
                f"{role}: byte length mismatch for {rel_path!r}: "
                f"expected {expected_bytes}, got {actual_bytes}"
            )

        actual_hash = _sha256_file(candidate_resolved)
        if actual_hash.lower() != str(expected_hash).lower():
            raise LockVerificationError(
                f"{role}: sha256 mismatch for {rel_path!r}: "
                f"expected {expected_hash}, got {actual_hash}"
            )

        resolved[role] = candidate_resolved

    return resolved


def _load_json(path: Path) -> Any:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


# ---------------------------------------------------------------------------
# 1. NIST OSCAL catalog / LOW-baseline selection and ordering
# ---------------------------------------------------------------------------


def walk_controls(controls: Iterable[Mapping[str, Any]]) -> Iterator[Mapping[str, Any]]:
    """Recursively yield every control (base and nested enhancement).

    OSCAL nests enhancements (e.g. ``ac-2.1``) inside their base control's
    own ``controls`` array. This walks depth-first so every control object
    -- base and enhancement alike -- is visited exactly once.
    """
    for ctrl in controls:
        yield ctrl
        nested = ctrl.get("controls")
        if nested:
            yield from walk_controls(nested)


def control_prop(ctrl: Mapping[str, Any], name: str) -> Optional[str]:
    """Return the value of the first ``props[]`` entry named ``name``."""
    for prop in ctrl.get("props", []):
        if prop.get("name") == name:
            return prop.get("value")
    return None


def control_related_ids(ctrl: Mapping[str, Any]) -> List[str]:
    """Return the target control ids of this control's OSCAL ``related`` links."""
    out: List[str] = []
    for link in ctrl.get("links", []):
        if link.get("rel") == "related":
            href = link.get("href", "")
            if href.startswith("#"):
                out.append(href[1:])
    return out


def index_catalog(catalog_json: Mapping[str, Any]) -> Dict[str, Dict[str, Any]]:
    """Index every control (base + enhancement) in a full OSCAL catalog.

    Returns a mapping from control id to ``{"node": <control object>,
    "family": <upper-case two/three-letter family code>}``. Statement
    parts, assessment objectives, and parameters are never treated as
    controls because only the recursive ``controls[]`` arrays are walked.
    """
    catalog = catalog_json["catalog"]
    index: Dict[str, Dict[str, Any]] = {}
    for group in catalog.get("groups", []):
        family = str(group["id"]).upper()
        for ctrl in walk_controls(group.get("controls", [])):
            index[ctrl["id"]] = {"node": ctrl, "family": family}
    return index


def low_selected_ids(profile_json: Mapping[str, Any]) -> List[str]:
    """Return the OSCAL control ids explicitly selected by the LOW profile.

    Reads ``profile.imports[].include-controls[].with-ids[]`` only; this
    pinned profile has a single explicit selection with no ``modify``
    section and no ``with-child-controls`` expansion, so nothing beyond
    the literal listed ids is included.
    """
    profile = profile_json["profile"]
    ids: List[str] = []
    seen: Set[str] = set()
    for imp in profile.get("imports", []):
        for inc in imp.get("include-controls", []):
            for cid in inc.get("with-ids", []):
                if cid not in seen:
                    seen.add(cid)
                    ids.append(cid)
    return ids


def resolved_catalog_ids(resolved_json: Mapping[str, Any]) -> Set[str]:
    """Return every control id present in an already-resolved profile catalog."""
    catalog = resolved_json["catalog"]
    ids: Set[str] = set()
    for group in catalog.get("groups", []):
        for ctrl in walk_controls(group.get("controls", [])):
            ids.add(ctrl["id"])
    return ids


def family_to_module_map(taxonomy: Mapping[str, Any]) -> Dict[str, str]:
    """Build a NIST family -> module id map from the taxonomy, or raise.

    Raises
    ------
    ValueError
        If the same family code is listed under two different modules in
        the taxonomy (families must be uniquely assigned).
    """
    mapping: Dict[str, str] = {}
    for module in taxonomy.get("modules", []):
        mod_id = module["id"]
        for fam in module.get("nist_families", []):
            fam_u = str(fam).upper()
            existing = mapping.get(fam_u)
            if existing is not None and existing != mod_id:
                raise ValueError(
                    f"taxonomy family {fam_u!r} is assigned to multiple "
                    f"modules: {existing!r} and {mod_id!r}"
                )
            mapping[fam_u] = mod_id
    return mapping


def build_control_catalog(
    nist_catalog: Mapping[str, Any],
    low_profile: Mapping[str, Any],
    low_resolved: Mapping[str, Any],
    taxonomy: Mapping[str, Any],
) -> Tuple[Dict[str, Dict[str, Any]], List[str], Dict[str, Dict[str, Any]]]:
    """Build the ``controls`` dict and natural ``control_order`` for LOW.

    Cross-checks that the LOW profile's explicit ``with-ids`` selection
    equals the independently-resolved LOW baseline catalog's control-id
    set (both pinned inputs), and that every NIST family is assigned to at
    most one taxonomy module (see :func:`family_to_module_map`).

    Returns
    -------
    ``(controls, control_order, catalog_index)`` where:
        - ``controls``: ``control_id -> {"family", "module",
          "parameter_count"}`` for every LOW-selected control.
          ``parameter_count`` is ``len(control["params"])`` on that exact
          control node (never a placeholder or hand-counted constant).
        - ``control_order``: LOW-selected control ids sorted by their OSCAL
          ``sort-id`` prop (falls back to the id itself if absent), which
          is the natural NIST family/base/enhancement numeric order
          because ``sort-id`` values are zero-padded
          (e.g. ``ac-01`` < ``ac-02`` < ``ac-02.01`` < ``ac-03``).
        - ``catalog_index``: the full-catalog index from
          :func:`index_catalog`, for downstream graph-edge lookups.

    Raises
    ------
    ValueError
        If the LOW profile selection and the resolved LOW catalog id sets
        differ, if a selected id is absent from the full catalog, or if
        the taxonomy assigns one family to multiple modules.
    """
    catalog_index = index_catalog(nist_catalog)
    profile_ids = set(low_selected_ids(low_profile))
    resolved_ids = resolved_catalog_ids(low_resolved)
    if profile_ids != resolved_ids:
        raise ValueError(
            "LOW profile selection does not equal the resolved LOW "
            f"baseline catalog set: {len(profile_ids)} vs {len(resolved_ids)} "
            f"ids; symmetric difference = {sorted(profile_ids ^ resolved_ids)}"
        )

    missing = profile_ids - set(catalog_index)
    if missing:
        raise ValueError(
            f"LOW-selected ids absent from the full catalog: {sorted(missing)}"
        )

    family_to_module = family_to_module_map(taxonomy)

    controls: Dict[str, Dict[str, Any]] = {}
    sort_keys: Dict[str, str] = {}
    for cid in profile_ids:
        entry = catalog_index[cid]
        node = entry["node"]
        family = entry["family"]
        sort_id = control_prop(node, "sort-id") or cid
        controls[cid] = {
            "family": family,
            "module": family_to_module.get(family),
            "parameter_count": len(node.get("params", [])),
        }
        sort_keys[cid] = sort_id

    control_order = sorted(profile_ids, key=lambda cid: (sort_keys[cid], cid))
    return controls, control_order, catalog_index


def build_module_order(
    control_order: List[str],
    controls: Mapping[str, Mapping[str, Any]],
    taxonomy: Mapping[str, Any],
) -> List[str]:
    """First-distinct-module order plus empty (uncovered) modules by ID.

    Walks ``control_order`` and records each module id the first time its
    module appears (natural NIST control order determines module order,
    not a hand-picked sequence). Any taxonomy module that never appears
    (e.g. a module whose ``nist_families`` is empty) is appended afterward,
    sorted by module id, so taxonomy members with no NIST-derived controls
    are still retained and reported.
    """
    order: List[str] = []
    seen: Set[str] = set()
    for cid in control_order:
        mod = controls[cid]["module"]
        if mod is not None and mod not in seen:
            seen.add(mod)
            order.append(mod)
    remaining = sorted(
        m["id"] for m in taxonomy.get("modules", []) if m["id"] not in seen
    )
    order.extend(remaining)
    return order


def build_related_edges(
    control_order: List[str], catalog_index: Mapping[str, Mapping[str, Any]]
) -> Tuple[Set[Tuple[str, str]], int]:
    """Project OSCAL ``related`` links onto the selected LOW catalog only.

    Only ``related`` links whose *source* is itself a LOW-selected control
    are considered (the "explicit OSCAL related-control links whose
    endpoints are both in selected Low catalog" graph scope). A link whose
    target is not also LOW-selected is counted as out-of-scope rather than
    silently dropped.

    Returns
    -------
    ``(related_edges, outside_scope_count)``: the directed
    ``(control_id, control_id)`` edge set (both endpoints in the LOW
    selection; self-links are retained as-is) and the count of related
    links whose target fell outside the LOW selection.
    """
    selected = set(control_order)
    edges: Set[Tuple[str, str]] = set()
    outside_scope = 0
    for cid in control_order:
        node = catalog_index[cid]["node"]
        for target in control_related_ids(node):
            if target in selected:
                edges.add((cid, target))
            else:
                outside_scope += 1
    return edges, outside_scope


# ---------------------------------------------------------------------------
# 2. ATT&CK Enterprise STIX indexing and normalization
# ---------------------------------------------------------------------------

RECON_RESOURCE_DEV_TACTICS: Set[str] = {"reconnaissance", "resource-development"}


def build_attack_index(
    stix_json: Mapping[str, Any],
) -> Tuple[Dict[str, Dict[str, Any]], Dict[str, str]]:
    """Index ATT&CK Enterprise ``attack-pattern`` objects by external ID.

    Returns
    -------
    ``(by_external_id, parent_of)`` where:
        - ``by_external_id``: ``"T####"`` / ``"T####.###"`` -> ``{
          "stix_id", "is_subtechnique", "active", "tactics"}``.
          ``active`` requires the object to be neither ``revoked`` nor
          ``x_mitre_deprecated`` and to include ``enterprise-attack`` in
          its ``x_mitre_domains``. ``tactics`` is the set of
          ``kill_chain_phases[].phase_name`` under the ``mitre-attack``
          kill chain (e.g. ``{"defense-evasion", "privilege-escalation"}``).
        - ``parent_of``: subtechnique external id -> parent technique
          external id, built from explicit ``subtechnique-of``
          relationship objects (STIX ``source_ref``/``target_ref`` resolved
          through the same attack-pattern index), never guessed from the
          ``T####.###`` id string alone.
    """
    objects = stix_json.get("objects", [])
    by_external: Dict[str, Dict[str, Any]] = {}
    stix_to_external: Dict[str, str] = {}

    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue
        external_id = None
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
                external_id = ref["external_id"]
                break
        if not external_id:
            continue
        domains = obj.get("x_mitre_domains") or []
        tactics = {
            phase.get("phase_name")
            for phase in obj.get("kill_chain_phases", [])
            if phase.get("kill_chain_name") == "mitre-attack" and phase.get("phase_name")
        }
        active = (
            not obj.get("revoked")
            and not obj.get("x_mitre_deprecated")
            and "enterprise-attack" in domains
        )
        by_external[external_id] = {
            "stix_id": obj.get("id"),
            "is_subtechnique": bool(obj.get("x_mitre_is_subtechnique")),
            "active": active,
            "tactics": tactics,
        }
        if obj.get("id"):
            stix_to_external[obj["id"]] = external_id

    parent_of: Dict[str, str] = {}
    for obj in objects:
        if obj.get("type") != "relationship":
            continue
        if obj.get("relationship_type") != "subtechnique-of":
            continue
        src = stix_to_external.get(obj.get("source_ref"))
        dst = stix_to_external.get(obj.get("target_ref"))
        if src and dst:
            parent_of[src] = dst

    return by_external, parent_of


def normalize_and_rollup(
    tech_id: str,
    attack_index: Mapping[str, Mapping[str, Any]],
    parent_of: Mapping[str, str],
) -> Tuple[Optional[str], Optional[str]]:
    """Normalize a raw ATT&CK id to its canonical active parent, or quarantine it.

    Applies, in order: (1) the id must resolve to a known, active Enterprise
    technique/subtechnique; (2) a subtechnique is rolled up to its explicit
    ``subtechnique-of`` parent, which must itself be active; (3) the final
    (already-a-base-technique, or rolled-up-to-parent) technique is dropped
    if every one of its tactics is reconnaissance and/or resource-development.

    Returns
    -------
    ``(canonical_id, None)`` on success, or ``(None, reason)`` where
    ``reason`` is one of ``"unknown_attack_id"``, ``"inactive_attack_id"``,
    ``"missing_parent_link"``, ``"inactive_parent"``, or
    ``"recon_resource_dev_only"``.
    """
    entry = attack_index.get(tech_id)
    if entry is None:
        return None, "unknown_attack_id"
    if not entry["active"]:
        return None, "inactive_attack_id"

    if entry["is_subtechnique"]:
        parent_id = parent_of.get(tech_id)
        if not parent_id:
            return None, "missing_parent_link"
        parent_entry = attack_index.get(parent_id)
        if parent_entry is None or not parent_entry["active"]:
            return None, "inactive_parent"
        target_id, target_entry = parent_id, parent_entry
    else:
        target_id, target_entry = tech_id, entry

    tactics = target_entry["tactics"]
    if tactics and tactics.issubset(RECON_RESOURCE_DEV_TACTICS):
        return None, "recon_resource_dev_only"

    return target_id, None


# ---------------------------------------------------------------------------
# 3. CTID mapping ingestion (NIST mitigates, VERIS related_to)
# ---------------------------------------------------------------------------

_CTID_CONTROL_ID_RE = re.compile(r"^([A-Za-z]{2})-0*(\d+)$")


def normalize_ctid_control_id(capability_id: Optional[str]) -> Optional[str]:
    """Normalize a CTID NIST ``capability_id`` to an OSCAL control id.

    ``"CM-03" -> "cm-3"``, ``"AC-02" -> "ac-2"``. CTID never emits
    enhancement-form capability ids (parenthesized enhancement numbers), so
    any id that does not match the plain ``FAMILY-NN`` shape returns
    ``None`` rather than a guessed join key.
    """
    if not capability_id:
        return None
    match = _CTID_CONTROL_ID_RE.match(capability_id.strip())
    if not match:
        return None
    family, num = match.groups()
    return f"{family.lower()}-{int(num)}"


def build_control_coverage(
    control_ids: Iterable[str],
    nist_ctid_mapping: Mapping[str, Any],
    attack_index: Mapping[str, Mapping[str, Any]],
    parent_of: Mapping[str, str],
    expected_attack_version: Optional[str] = None,
) -> Tuple[Dict[str, Set[str]], Dict[str, int]]:
    """Build exact-id, no-enhancement-inheritance CTID control coverage.

    Only rows whose normalized ``capability_id`` exactly equals one of
    ``control_ids`` are used; an enhancement id present in ``control_ids``
    (e.g. an OSCAL ``ac-2.1``) receives coverage only if CTID itself maps
    that literal id (it never does, per CTID's base-control-only scope),
    so enhancements never inherit their base control's coverage.

    Only ``status == "complete"`` and ``mapping_type == "mitigates"`` rows
    are used. A row whose own ``attack_version`` differs from the mapping
    file's base version (or ``expected_attack_version``, if given) is
    quarantined rather than silently accepted (e.g. the pinned
    ``SC-12 -> T1521.003`` row declaring ``"[UNKNOWN_VERSION]"``).

    Returns
    -------
    ``(control_coverage, quarantine_counts)``: ``control_coverage`` maps
    every id in ``control_ids`` to its set of canonical active parent
    technique ids (possibly empty); ``quarantine_counts`` counts rows
    dropped by reason (version mismatch, missing id, or any
    :func:`normalize_and_rollup` quarantine reason).
    """
    metadata = nist_ctid_mapping.get("metadata", {})
    base_version = expected_attack_version or metadata.get("attack_version")

    selected = set(control_ids)
    coverage: Dict[str, Set[str]] = {cid: set() for cid in selected}
    quarantine: Counter = Counter()

    for row in nist_ctid_mapping.get("mapping_objects", []):
        if row.get("status") != "complete" or row.get("mapping_type") != "mitigates":
            continue
        norm_cid = normalize_ctid_control_id(row.get("capability_id"))
        if norm_cid is None or norm_cid not in selected:
            continue

        row_version = row.get("attack_version", base_version)
        if row_version != base_version:
            quarantine["version_override_invalid"] += 1
            continue

        tech_id = row.get("attack_object_id")
        if not tech_id:
            quarantine["missing_attack_id"] += 1
            continue

        canonical, reason = normalize_and_rollup(tech_id, attack_index, parent_of)
        if canonical is None:
            quarantine[reason or "unknown"] += 1
            continue
        coverage[norm_cid].add(canonical)

    return coverage, dict(quarantine)


def build_module_coverage(
    control_coverage: Mapping[str, Set[str]],
    controls: Mapping[str, Mapping[str, Any]],
    module_order: Iterable[str],
) -> Dict[str, Set[str]]:
    """Union each module's member controls' coverage sets.

    Every module in ``module_order`` gets an entry, defaulting to the
    empty set, so a taxonomy module with no NIST-derived controls (or none
    of whose controls have any CTID coverage) is still present and
    reported rather than silently omitted -- missing coverage is not
    treated as zero security value, only as zero *modeled* coverage here.
    """
    module_coverage: Dict[str, Set[str]] = {m: set() for m in module_order}
    for cid, techs in control_coverage.items():
        mod = controls[cid]["module"]
        if mod is None:
            continue
        module_coverage.setdefault(mod, set())
        module_coverage[mod] |= techs
    return module_coverage


def build_veris_action_variety_index(
    veris_mapping: Mapping[str, Any],
    exclude_values: Iterable[str],
    expected_attack_version: Optional[str] = None,
) -> Tuple[Dict[str, List[str]], Dict[str, int]]:
    """Index CTID VERIS ``related_to`` rows by ``action.*.variety`` path.

    Only rows whose ``capability_id`` starts with ``"action."`` and
    contains ``".variety."`` are indexed (attributes and value-chain rows
    are out of scope per ``spec.mapping.variety_only``); rows whose
    trailing enumeration value exactly matches one of ``exclude_values``
    (``"Unknown"``/``"Other"``) are skipped, and version-overridden rows
    are quarantined the same way as :func:`build_control_coverage`.

    Returns
    -------
    ``(index, quarantine_counts)``: ``index`` maps each retained
    ``capability_id`` (e.g. ``"action.social.variety.Phishing"``) to the
    raw list of its mapped ATT&CK object ids (before rollup/dedup, which
    happens per-incident in :func:`compute_incident_credits` because the
    same path can be normalized against different active/inactive states
    across a fixed ATT&CK version -- in practice one fixed state here, but
    kept as a separate step for auditability).
    """
    metadata = veris_mapping.get("metadata", {})
    base_version = expected_attack_version or metadata.get("attack_version")
    exclude = set(exclude_values)

    index: Dict[str, List[str]] = defaultdict(list)
    quarantine: Counter = Counter()

    for row in veris_mapping.get("mapping_objects", []):
        if row.get("status") != "complete" or row.get("mapping_type") != "related_to":
            continue
        cap_id = row.get("capability_id") or ""
        if not cap_id.startswith("action.") or ".variety." not in cap_id:
            continue
        value = cap_id.rsplit(".variety.", 1)[1]
        if value in exclude:
            continue

        row_version = row.get("attack_version", base_version)
        if row_version != base_version:
            quarantine["version_override_invalid"] += 1
            continue

        tech_id = row.get("attack_object_id")
        if not tech_id:
            quarantine["missing_attack_id"] += 1
            continue

        index[cap_id].append(tech_id)

    return dict(index), dict(quarantine)


def compute_incident_credits(
    action_block: Any,
    veris_index: Mapping[str, List[str]],
    attack_index: Mapping[str, Mapping[str, Any]],
    parent_of: Mapping[str, str],
    exclude_values: Iterable[str],
) -> Tuple[Dict[str, float], Counter]:
    """Compute ``{technique_id: credit}`` for one VCDB record's ``action`` block.

    Each present ``action.<category>.variety`` array element that is not a
    literal excluded enumeration (``Unknown``/``Other``) and that has at
    least one CTID VERIS mapping row is one *path*. A path's raw candidate
    technique ids are normalized/rolled-up/tactic-filtered via
    :func:`normalize_and_rollup` and deduplicated into a retained parent
    set; a path whose retained set ends up empty contributes nothing. A
    nonempty retained set of size ``N`` gives every technique in it
    ``path_credit = 1/N`` for that path (``spec.mapping.path_credit``). A
    technique's final incident credit is the **maximum** (never the sum)
    of its credit across all of the incident's paths
    (``spec.mapping.incident_credit``).

    Returns
    -------
    ``(credits, quarantine_counts)``: ``credits`` is empty if the incident
    retained no technique at all (bootstrap-ineligible); ``quarantine_counts``
    tallies :func:`normalize_and_rollup` reasons encountered while building
    this one incident's paths, for audit aggregation by the caller.
    """
    credits: Dict[str, float] = {}
    quarantine: Counter = Counter()
    exclude = set(exclude_values)

    if not isinstance(action_block, dict):
        return credits, quarantine

    for category, fields in action_block.items():
        if not isinstance(fields, dict):
            continue
        varieties = fields.get("variety")
        if not isinstance(varieties, list):
            continue
        for value in varieties:
            if value in exclude:
                continue
            cap_id = f"action.{category}.variety.{value}"
            raw_ids = veris_index.get(cap_id)
            if not raw_ids:
                continue

            retained: Set[str] = set()
            for raw_id in raw_ids:
                canonical, reason = normalize_and_rollup(raw_id, attack_index, parent_of)
                if canonical is None:
                    quarantine[reason or "unknown"] += 1
                    continue
                retained.add(canonical)

            if not retained:
                continue
            path_credit = 1.0 / len(retained)
            for tech in retained:
                if path_credit > credits.get(tech, 0.0):
                    credits[tech] = path_credit

    return credits, quarantine


# ---------------------------------------------------------------------------
# 4. Safe VCDB tar.gz ingestion
# ---------------------------------------------------------------------------

_DATA_JSON_DIR_RE = re.compile(
    r"(^|/)data/json/(submitted|validated|overridden)/", re.IGNORECASE
)


def is_path_safe(member_name: str) -> bool:
    """Reject archive member names that could escape the extraction root.

    Rejects absolute paths and any path containing a literal ``..``
    segment. Used before ``extractfile`` is ever called on a member, and
    ``extractall`` is never used anywhere in this module.
    """
    if not member_name or member_name.startswith("/"):
        return False
    return ".." not in Path(member_name).parts


def iter_vcdb_members(tar_path: Path) -> Iterator[Tuple[str, str, bytes]]:
    """Yield ``(member_name, status, raw_bytes)`` for eligible VCDB source files.

    Only regular files matching ``data/json/{submitted,validated,overridden}/**``
    (case-insensitive directory names and a case-insensitive ``.json``
    suffix, so filenames such as ``9C69AE79-...JSON`` are not silently
    missed) are read, and only via ``TarFile.extractfile`` -- the archive
    is never fully extracted to disk. Members whose recorded name would
    escape the archive root are skipped rather than trusted.
    """
    with tarfile.open(tar_path, mode="r:gz") as tf:
        for member in tf.getmembers():
            if not member.isfile():
                continue
            name = member.name
            if not is_path_safe(name):
                continue
            match = _DATA_JSON_DIR_RE.search(name)
            if not match:
                continue
            if not name.lower().endswith(".json"):
                continue
            status = match.group(2).lower()
            fh = tf.extractfile(member)
            if fh is None:
                continue
            raw = fh.read()
            yield name, status, raw


# ---------------------------------------------------------------------------
# 5. VCDB eligibility pipeline
# ---------------------------------------------------------------------------


def naics_prefix(industry: Any) -> Optional[str]:
    """Return the two-digit NAICS sector prefix of a VERIS ``victim.industry``.

    ``victim.industry`` is a free-text NAICS-shaped string (schema
    ``minLength: 2``). Returns ``None`` for anything that is not a string
    of at least two leading digits (e.g. missing, too short, or a non-numeric
    prefix), rather than guessing a sector.
    """
    if not isinstance(industry, str):
        return None
    text = industry.strip()
    if len(text) < 2:
        return None
    prefix = text[:2]
    return prefix if prefix.isdigit() else None


def sector_lookup_from_spec(sectors: Mapping[str, List[str]]) -> Dict[str, str]:
    """Flatten ``spec.sectors`` (label -> prefixes) into prefix -> label."""
    lookup: Dict[str, str] = {}
    for label, prefixes in sectors.items():
        for prefix in prefixes:
            lookup[prefix] = label
    return lookup


def find_duplicate_incident_id_groups(
    rows: Iterable[Mapping[str, Any]],
) -> Dict[str, List[Mapping[str, Any]]]:
    """Group rows by case-normalized ``incident_id``; return only groups of size > 1.

    Case-normalization is ``incident_id.strip().lower()``. Intended to be
    called only on rows that already passed the missing-id and
    status-eligibility checks, per ``spec.eligibility.duplicate_id_policy``
    (dedup happens across eligible source statuses, before sector/version
    filters).
    """
    groups: Dict[str, List[Mapping[str, Any]]] = defaultdict(list)
    for row in rows:
        key = str(row["incident_id"]).strip().lower()
        groups[key].append(row)
    return {key: members for key, members in groups.items() if len(members) > 1}


def process_vcdb_records(
    tar_path: Path,
    spec: Mapping[str, Any],
    veris_index: Mapping[str, List[str]],
    attack_index: Mapping[str, Mapping[str, Any]],
    parent_of: Mapping[str, str],
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], Dict[str, int]]:
    """Run the full eligibility pipeline over every VCDB archive member.

    Order (dedup strictly before sector/version, per spec): every source
    file is first inventoried (parsed or recorded as a parse error); then,
    among parsed rows, missing-id exclusion, then eligible-source-status
    filtering (``validated``/``overridden`` only), then duplicate
    case-normalized incident-id group exclusion, then target-sector
    filtering, then exact VERIS version filtering, and finally per-record
    technique-credit computation with bootstrap eligibility (a record with
    zero retained technique credit is excluded, not zero-valued).

    Returns
    -------
    ``(records, ledger, incident_path_quarantine)``:
        - ``records``: eligible mapped rows, each
          ``{"source_path", "incident_id", "sector", "credits"}``.
        - ``ledger``: every inventoried source file as a dict with
          ``source_path``, ``status``, ``sha256``, ``bytes``, ``parse_ok``,
          and (when applicable) ``incident_id``, ``schema_version``,
          ``industry``, ``sector``, and the terminal ``reason`` (``
          "eligible"`` or an exclusion reason) -- a full record ledger
          for audit, not just the survivors. The parsed JSON body is kept
          under a private ``"_data"`` key so callers can strip it before
          persisting an audit trail.
        - ``incident_path_quarantine``: aggregate
          :func:`normalize_and_rollup` reason counts encountered while
          computing per-record technique credits.
    """
    eligible_statuses = set(spec["eligibility"]["source_statuses"])
    target_version = spec["eligibility"]["veris_version"]
    exclude_values = set(spec["mapping"]["exclude_enumerations"])
    sectors_lookup = sector_lookup_from_spec(spec["sectors"])

    ledger: List[Dict[str, Any]] = []

    for name, status, raw in iter_vcdb_members(tar_path):
        row: Dict[str, Any] = {
            "source_path": name,
            "status": status,
            "sha256": hashlib.sha256(raw).hexdigest(),
            "bytes": len(raw),
        }
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            row["parse_ok"] = False
            row["reason"] = "parse_error"
            row["error"] = str(exc)
            ledger.append(row)
            continue

        row["parse_ok"] = True
        row["_data"] = data
        incident_id = data.get("incident_id") if isinstance(data, dict) else None
        row["incident_id"] = incident_id
        row["schema_version"] = (
            data.get("schema_version") if isinstance(data, dict) else None
        )
        victim = data.get("victim") if isinstance(data, dict) else None
        row["industry"] = victim.get("industry") if isinstance(victim, dict) else None
        ledger.append(row)

    def _pending(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return [r for r in rows if r["parse_ok"] and "reason" not in r]

    # Missing-id policy.
    for row in _pending(ledger):
        if not isinstance(row.get("incident_id"), str) or not row["incident_id"].strip():
            row["reason"] = "missing_id"

    # Eligible-source-status filter.
    for row in _pending(ledger):
        if row["status"] not in eligible_statuses:
            row["reason"] = "ineligible_status"

    # Duplicate incident-id policy: BEFORE sector/version filters, scoped
    # to rows that are already status-eligible and have a usable id.
    duplicate_groups = find_duplicate_incident_id_groups(_pending(ledger))
    for members in duplicate_groups.values():
        for row in members:
            row["reason"] = "duplicate_incident_id"

    # Target-sector filter.
    for row in _pending(ledger):
        prefix = naics_prefix(row.get("industry"))
        sector = sectors_lookup.get(prefix) if prefix else None
        if sector is None:
            row["reason"] = "sector_out_of_scope"
        else:
            row["sector"] = sector

    # Exact VERIS version filter.
    for row in _pending(ledger):
        if row.get("schema_version") != target_version:
            row["reason"] = "version_mismatch"

    # Credit computation + bootstrap eligibility.
    records: List[Dict[str, Any]] = []
    incident_quarantine: Counter = Counter()
    for row in _pending(ledger):
        action_block = row["_data"].get("action") if isinstance(row["_data"], dict) else None
        credits, quarantine = compute_incident_credits(
            action_block, veris_index, attack_index, parent_of, exclude_values
        )
        incident_quarantine.update(quarantine)
        if not credits:
            row["reason"] = "no_credited_technique"
            continue
        row["reason"] = "eligible"
        records.append(
            {
                "source_path": row["source_path"],
                "incident_id": row["incident_id"],
                "sector": row["sector"],
                "credits": credits,
            }
        )

    return records, ledger, dict(incident_quarantine)


# ---------------------------------------------------------------------------
# 6. Top-level entry point
# ---------------------------------------------------------------------------


def load_inputs(
    input_root: Path,
    spec: Mapping[str, Any],
    taxonomy: Mapping[str, Any],
    lock: Mapping[str, Any],
) -> Dict[str, Any]:
    """Load and join every pinned input into the loader's output contract.

    Parameters
    ----------
    input_root:
        Directory holding the pinned ``nist-ctid/`` and ``vcdb-veris/``
        bundles (verified against ``lock`` before anything is parsed).
    spec:
        Parsed ``research/spec.json`` (sectors, eligibility, mapping rules).
    taxonomy:
        Parsed ``research/module_taxonomy.json`` (module id -> NIST
        families, used for control-to-module assignment).
    lock:
        Parsed ``research/input-lock.json`` (pinned file roles/paths/hashes).

    Returns
    -------
    Dict with keys:
        - ``controls``: ``control_id -> {"family", "module",
          "parameter_count"}`` for the 149-id (as pinned) LOW baseline.
        - ``control_order``: LOW control ids in natural NIST family/base/
          enhancement numeric order.
        - ``module_order``: first-distinct-module order from
          ``control_order``, plus any control-less taxonomy modules
          appended by id.
        - ``control_coverage``: ``control_id -> set[technique_id]``
          (canonical active parent technique ids; exact-id CTID
          ``mitigates`` join, no enhancement inheritance).
        - ``module_coverage``: ``module_id -> set[technique_id]`` (union of
          member controls' coverage).
        - ``related_edges``: ``set[(control_id, control_id)]`` directed
          OSCAL ``related`` edges scoped to the LOW selection.
        - ``records``: eligible mapped VCDB rows, each
          ``{"source_path", "incident_id", "sector", "credits"}``.
        - ``audit``: summary counts, exclusion-reason counts, mapping
          quarantine counts (by stage), and out-of-scope related-link count.
        - ``audit_rows``: the full per-source-file eligibility ledger
          (hash, path, status, terminal reason), for a complete audit
          trail of every parsed source record, not only the survivors.

    Raises
    ------
    LockVerificationError
        If any pinned file fails verification (see :func:`verify_lock`).
    ValueError
        If the LOW profile/resolved-catalog cross-check fails or the
        taxonomy assigns a NIST family to more than one module (see
        :func:`build_control_catalog`).
    """
    input_root = Path(input_root)
    resolved = verify_lock(input_root, lock)

    nist_catalog = _load_json(resolved["nist_catalog"])
    low_profile = _load_json(resolved["nist_low_profile"])
    low_resolved = _load_json(resolved["nist_low_resolved"])
    nist_ctid_mapping = _load_json(resolved["nist_attack"])
    attack_stix = _load_json(resolved["attack_stix"])
    veris_mapping = _load_json(resolved["veris_attack"])
    vcdb_archive_path = resolved["vcdb_archive"]

    attack_version = spec["eligibility"]["attack_version"]

    controls, control_order, catalog_index = build_control_catalog(
        nist_catalog, low_profile, low_resolved, taxonomy
    )
    module_order = build_module_order(control_order, controls, taxonomy)
    related_edges, related_outside_scope = build_related_edges(
        control_order, catalog_index
    )

    attack_index, parent_of = build_attack_index(attack_stix)

    control_coverage, ctid_quarantine = build_control_coverage(
        control_order, nist_ctid_mapping, attack_index, parent_of, attack_version
    )
    module_coverage = build_module_coverage(control_coverage, controls, module_order)

    exclude_values = spec["mapping"]["exclude_enumerations"]
    veris_index, veris_quarantine = build_veris_action_variety_index(
        veris_mapping, exclude_values, attack_version
    )

    records, ledger, incident_quarantine = process_vcdb_records(
        vcdb_archive_path, spec, veris_index, attack_index, parent_of
    )

    audit_rows = [{k: v for k, v in row.items() if k != "_data"} for row in ledger]

    parsed_rows = [r for r in ledger if r["parse_ok"]]
    exclusion_counts = Counter(
        r["reason"] for r in parsed_rows if r.get("reason") not in (None, "eligible")
    )
    status_counts = Counter(r["status"] for r in ledger)

    audit: Dict[str, Any] = {
        "counts": {
            "source_files_total": len(ledger),
            "by_status": dict(status_counts),
            "parse_errors": len(ledger) - len(parsed_rows),
            "parsed_ok": len(parsed_rows),
            "eligible_records": len(records),
        },
        "exclusions": dict(exclusion_counts),
        "mapping_quarantine": {
            "nist_ctid_mitigates": ctid_quarantine,
            "veris_action_variety": veris_quarantine,
            "incident_paths": incident_quarantine,
        },
        "related_link_outside_scope": related_outside_scope,
        "low_selected_control_count": len(control_order),
        "modules_without_low_controls": sorted(
            set(module_order) - {row["module"] for row in controls.values()}
        ),
        "modules_without_mapped_technique_coverage": sorted(
            m for m in module_order if not module_coverage.get(m)
        ),
    }

    return {
        "controls": controls,
        "control_order": control_order,
        "module_order": module_order,
        "control_coverage": control_coverage,
        "module_coverage": module_coverage,
        "related_edges": related_edges,
        "records": records,
        "audit": audit,
        "audit_rows": audit_rows,
    }
