"""Regression checks added after independent experimental-validity review."""
import copy
import os
from pathlib import Path
import subprocess
import sys
import unittest
from research import metrics
from research.experiment import frequencies, run_experiments, static_order, summarize, coverage_of
from research.pipeline import canonical, graph_report
from research.tests import test_experiment as fixtures


class ReviewRegressionTests(unittest.TestCase):
    def test_held_out_weights_and_orders_cannot_be_swapped(self):
        data, spec = fixtures.ExperimentTests().fixture()
        result = run_experiments(data, spec)
        by_id = {r["incident_id"]: r for r in data["records"]}
        for p in result["profiles"]:
            suite = p["suites"]["held_out"]
            sampled = [by_id[i] for i, n in suite["bootstrap_id_counts"].items() for _ in range(n)]
            test = [by_id[i] for i in result["sector_summaries"][p["sector"]]["test_ids"]]
            self.assertEqual(suite["ranking_frequencies"], frequencies(sampled))
            self.assertEqual(suite["evaluation_frequencies"], frequencies(test))
            remaining = [m for m in data["module_order"] if m not in p["preimplemented_modules"]]
            self.assertEqual(suite["analytics_order"], static_order(remaining, data["module_coverage"], frequencies(sampled))[0])

    def fake_rows(self, a, b, spec):
        return [{"profile_id": "P1", "suite": suite, "milestone": milestone,
                 "scenario": scenario, "weighted_gap": a if scenario.endswith("analytics") else b,
                 "top25_unweighted_gap": 999}
                for suite in ("in_sample", "held_out") for milestone in spec["evaluation"]["milestones"]
                for scenario in ("module_analytics", "module_rule", "matched_control_analytics", "matched_control_nist")]

    def test_lower_gap_positive_effect_and_worse_negative_effect(self):
        _, spec = fixtures.ExperimentTests().fixture()
        for a, b, better in [(.1, .3, True), (.3, .1, False)]:
            for row in summarize(self.fake_rows(a, b, spec), spec):
                self.assertEqual(row["paired"]["improved"], int(better))
                self.assertEqual(row["paired"]["worse"], int(not better))
                self.assertEqual(row["conditional_signed_rank"]["status"], "computed")
                self.assertEqual(row["conditional_signed_rank"]["rank_biserial"], 1 if better else -1)

    def test_all_zero_and_tolerance_tie_have_no_pvalue(self):
        _, spec = fixtures.ExperimentTests().fixture()
        for a, b in [(.1, .1), (.1, .1 + 1e-14)]:
            for row in summarize(self.fake_rows(a, b, spec), spec):
                self.assertEqual(row["paired"]["tied"], 1)
                self.assertIsNone(row["paired"]["nonzero_median"])
                self.assertEqual(row["conditional_signed_rank"]["status"], "undefined_all_zero")
                self.assertIsNone(row["conditional_signed_rank"]["p_value_two_sided"])
                self.assertIsNone(row["conditional_signed_rank"]["w_plus"])

    def test_module_coverage_bonus_fails_closed(self):
        data, spec = fixtures.ExperimentTests().fixture()
        data["module_coverage"]["A"].add("UNSUPPORTED")
        with self.assertRaises(ValueError): run_experiments(data, spec)

    def test_initial_coverage_and_selected_budget_disjointness(self):
        data, spec = fixtures.ExperimentTests().fixture()
        result = run_experiments(data, spec)
        for row in result["trajectories"]:
            if row["budget_unit"] == "control":
                self.assertFalse(set(row["selected_units"]) & set(row["preimplemented_controls"]))
                self.assertEqual(len(row["selected_units"]), row["new_units"])
                self.assertEqual(coverage_of(row["preimplemented_controls"], data["control_coverage"]),
                                 coverage_of(row["preimplemented_modules"], data["module_coverage"]))

    def test_graph_reporting_separates_scc_from_chain(self):
        data, _ = fixtures.ExperimentTests().fixture()
        data["related_edges"] = {("a-1", "a-2"), ("a-2", "a-1"), ("a-1", "b-1"),
                                  ("a-2", "b-1"), ("c-1", "c-1")}
        report = graph_report(data)
        self.assertEqual(report["controls"]["max_scc_size"], 2)
        self.assertEqual(report["controls"]["longest_path_edges"], 1)
        self.assertEqual(report["controls"]["longest_path_components"], 2)
        self.assertEqual(report["self_links"], 1)
        self.assertEqual(report["module_projection"]["original_between_count"], 2)
        self.assertEqual(report["module_projection"]["unique_projected_between_count"], 1)
        self.assertEqual(report["module_projection"]["duplicates_collapsed_count"], 1)
        data["related_edges"] = list(reversed(sorted(data["related_edges"])))
        self.assertEqual(canonical(report), canonical(graph_report(data)))

    def test_hashseed_does_not_change_graph_serialization(self):
        snippet = ('from research.metrics import condensation_longest_path; from research.pipeline import canonical; '
                   'g={n:set(v) for n,v in [("c",["d"]),("b",["a","c"]),("a",["b"]),("d",[])]}; '
                   'print(canonical(condensation_longest_path(g)).decode())')
        outputs = [subprocess.check_output([sys.executable, "-c", snippet],
                                          cwd=Path(__file__).resolve().parents[2],
                                          env={**os.environ, "PYTHONHASHSEED": str(seed)})
                   for seed in (1, 42, 999)]
        self.assertEqual(len(set(outputs)), 1)

    def test_invalid_numeric_weights_are_rejected(self):
        for bad in (-1, float("nan"), float("inf")):
            with self.assertRaises(ValueError): metrics.standalone_ranking({"A": bad})
            with self.assertRaises(ValueError): metrics.marginal_gain_ranking({"A": {"T1"}}, weights={"T1": bad})
            with self.assertRaises(ValueError): frequencies([{"credits": {"T1": bad}}])
        with self.assertRaises(ValueError): metrics.weighted_coverage_gap(1, float("inf"))




class SourceTaxonomyRegressionTests(unittest.TestCase):
    """Full IG1 inventory derived from the official CIS v8 workbook, not M2SBF.

    Source: https://learn.cisecurity.org/l/799323/2021-05-18/47qgv
    SHA256: 461c258158a66dba5d9f45eaabf9100c69b3de37f70827811fb7a7fd538ee43d
    Controls V8: column B identifiers, column G IG1=x. Preserve .10 formatting.
    Only reference identifiers are reproduced; no proprietary standard text.
    """
    EXPECTED_IG1 = frozenset("""
        1.1 1.2 2.1 2.2 2.3 3.1 3.2 3.3 3.4 3.5 3.6 4.1 4.2 4.3 4.4 4.5 4.6 4.7 5.1 5.2 5.3 5.4 6.1 6.2 6.3 6.4 6.5 7.1 7.2 7.3 7.4 8.1 8.2 8.3 9.1 9.2 10.1 10.2 10.3 11.1 11.2 11.3 11.4 12.1 14.1 14.2 14.3 14.4 14.5 14.6 14.7 14.8 15.1 17.1 17.2 17.3
    """.split())

    def setUp(self):
        import json
        taxonomy = Path(__file__).parents[1] / "module_taxonomy.json"
        self.modules = json.loads(taxonomy.read_text())["modules"]

    def test_cis_assignments_equal_official_ig1_source_set(self):
        assigned = [s for m in self.modules for s in m["cis_safeguards"]]
        self.assertEqual(len(self.EXPECTED_IG1), 56)
        self.assertEqual(set(assigned), self.EXPECTED_IG1)

    def test_cis_ig1_has_exactly_one_assignment_per_identifier(self):
        assigned = [s for m in self.modules for s in m["cis_safeguards"]]
        self.assertEqual(len(assigned), len(set(assigned)))

    def test_source_correction_places_14_8_under_awareness(self):
        by_id = {m["id"]: m for m in self.modules}
        self.assertIn("14.8", by_id["M2SBF-AWR"]["cis_safeguards"])
        self.assertNotIn("16.1", by_id["M2SBF-CFG"]["cis_safeguards"])


if __name__ == "__main__": unittest.main()
