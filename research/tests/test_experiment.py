import copy
import json
from pathlib import Path
import unittest
from research.experiment import frequencies, gap, milestone_count, split_pool, run_experiments, static_order


class ExperimentTests(unittest.TestCase):
    def fixture(self):
        spec = json.loads(Path(__file__).parents[1].joinpath("spec.json").read_text())
        spec["profiles"]["preimplemented_module_counts"] = [0, 1, 2]
        controls = {"a-1": {"module": "A"}, "a-2": {"module": "A"},
                    "b-1": {"module": "B"}, "c-1": {"module": "C"}}
        data = {"controls": controls, "control_order": list(controls), "module_order": ["A", "B", "C"],
                "control_coverage": {"a-1": {"T1"}, "a-2": {"T1"}, "b-1": {"T2"}, "c-1": {"T3"}},
                "module_coverage": {"A": {"T1"}, "B": {"T2"}, "C": {"T3"}}, "records": []}
        for sector in spec["sectors"]:
            for i in range(10):
                data["records"].append({"incident_id": f"{sector}-{i}", "source_path": f"{sector}/{i}",
                                        "sector": sector, "credits": {f"T{1+i%3}": 1.0}})
        return data, spec

    def test_frequency_is_mean_not_renormalized_distribution(self):
        f = frequencies([{"credits": {"T1": 1, "T2": .5}}, {"credits": {"T1": .5}}])
        self.assertEqual(f, {"T1": .75, "T2": .25})

    def test_frequency_empty_fails(self):
        with self.assertRaises(ValueError): frequencies([])

    def test_ceil_remaining_budget(self):
        self.assertEqual(milestone_count(.25, 14), 4)
        self.assertEqual(milestone_count(.75, 10), 8)
        self.assertEqual(milestone_count(.25, 0), 0)
        with self.assertRaises(ValueError): milestone_count(1.1, 14)

    def test_full_weighted_universe_not_top25(self):
        weights = {f"T{i}": 1 for i in range(30)}
        self.assertAlmostEqual(gap(weights, {f"T{i}" for i in range(25)}), 5/30)

    def test_static_ties_are_id_sorted(self):
        order, _ = static_order(["B", "A"], {"B": {"T2"}, "A": {"T1"}}, {"T1": 1, "T2": 1})
        self.assertEqual(order, ["A", "B"])

    def test_split_is_disjoint_and_permutation_invariant(self):
        data, _ = self.fixture()
        p = data["records"][:10]
        train, test = split_pool(p, .7, 42)
        self.assertEqual(len(train), 7)
        self.assertEqual((train, test), split_pool(p[::-1], .7, 42))
        self.assertFalse({r["incident_id"] for r in train} & {r["incident_id"] for r in test})

    def test_full_design_and_matched_budget_invariants(self):
        data, spec = self.fixture()
        original = copy.deepcopy(data)
        result = run_experiments(data, spec)
        self.assertEqual(data, original)
        self.assertEqual(len(result["profiles"]), 36)
        self.assertEqual(len(result["trajectories"]), 1152)
        self.assertEqual(len(result["comparisons"]), 16)
        self.assertEqual(result, run_experiments(data, spec))
        lookup = {(r["profile_id"], r["suite"], r["milestone"], r["scenario"]): r for r in result["trajectories"]}
        for r in result["trajectories"]:
            self.assertTrue(0 <= r["weighted_gap"] <= 1)
            if r["scenario"] == "matched_control_analytics":
                other = lookup[(r["profile_id"], r["suite"], r["milestone"], "matched_control_nist")]
                self.assertEqual(r["new_units"], other["new_units"])
                self.assertEqual(r["preimplemented_controls"], other["preimplemented_controls"])
                self.assertEqual(r["implemented_control_count"], other["implemented_control_count"])
            if r["milestone"] == 1:
                self.assertAlmostEqual(r["weighted_gap"], 0)
        for profile in result["profiles"]:
            train = result["sector_summaries"][profile["sector"]]["train_ids"]
            test = result["sector_summaries"][profile["sector"]]["test_ids"]
            sampled = profile["suites"]["held_out"]["bootstrap_id_counts"]
            self.assertTrue(set(sampled) <= set(train))
            self.assertFalse(set(sampled) & set(test))
        for summary in result["comparisons"]:
            self.assertEqual(sum(summary["paired"][k] for k in ("improved", "tied", "worse")), 36)
            self.assertIn("not assessed", summary["hypothesis_status"])

    def test_sparse_sector_fails_instead_of_fabricating_profiles(self):
        data, spec = self.fixture()
        data["records"] = data["records"][1:2]
        with self.assertRaises(ValueError): run_experiments(data, spec)


if __name__ == "__main__": unittest.main()
