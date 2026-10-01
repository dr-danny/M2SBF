"""Stdlib unittest suite for research.metrics.

Covers: toy-graph SCC/condensation longest paths, control-to-module
projection accounting, invalid-weight rejection for the coverage gap,
a worked static-vs-marginal ranking example, paired descriptive
differences, and a brute-force validation of the exact signed-rank test
against every one of its 2**n sign assignments by hand.
"""

from __future__ import annotations

import itertools
import math
import unittest

from research import metrics


class ComputeSccsTests(unittest.TestCase):
    def test_two_cycles_joined_by_a_bridge(self) -> None:
        # Cycle A: 1 -> 2 -> 3 -> 1
        # Cycle B: 4 -> 5 -> 4
        # Bridge: 3 -> 4 (one-directional, does not merge the cycles)
        graph = {
            1: [2],
            2: [3],
            3: [1, 4],
            4: [5],
            5: [4],
        }
        sccs = metrics.compute_sccs(graph)
        sccs_as_sets = sorted((frozenset(c) for c in sccs), key=lambda s: sorted(s))
        expected = sorted(
            [frozenset({1, 2, 3}), frozenset({4, 5})], key=lambda s: sorted(s)
        )
        self.assertEqual(sccs_as_sets, expected)

    def test_all_singletons_on_a_dag(self) -> None:
        graph = {1: [2], 2: [3], 3: []}
        sccs = metrics.compute_sccs(graph)
        self.assertEqual(len(sccs), 3)
        for comp in sccs:
            self.assertEqual(len(comp), 1)

    def test_successor_only_node_included(self) -> None:
        # Node 2 never appears as a key, only as a successor of 1.
        graph = {1: [2]}
        sccs = metrics.compute_sccs(graph)
        all_nodes = {n for comp in sccs for n in comp}
        self.assertEqual(all_nodes, {1, 2})

    def test_deterministic_regardless_of_key_insertion_order(self) -> None:
        # Same graph, keys inserted in a different order, plus string node
        # ids (which are the type most exposed to PYTHONHASHSEED-driven set
        # ordering). Output must be identical either way.
        graph_a = {
            "alpha": ["beta"],
            "beta": ["gamma"],
            "gamma": ["alpha", "delta"],
            "delta": ["epsilon"],
            "epsilon": ["delta"],
        }
        graph_b = {
            "epsilon": ["delta"],
            "delta": ["epsilon"],
            "gamma": ["alpha", "delta"],
            "beta": ["gamma"],
            "alpha": ["beta"],
        }
        self.assertEqual(metrics.compute_sccs(graph_a), metrics.compute_sccs(graph_b))

    def test_deterministic_across_repeated_calls(self) -> None:
        # A stand-in for "deterministic across PYTHONHASHSEED": repeated
        # calls in the same process with distinctly-ordered dict literals
        # must always agree, since our traversal never relies on raw set
        # iteration order.
        graph = {"n3": ["n1"], "n1": ["n2"], "n2": ["n3", "n4"], "n4": []}
        first = metrics.compute_sccs(graph)
        second = metrics.compute_sccs(dict(reversed(list(graph.items()))))
        self.assertEqual(first, second)
        # Each component's node list is itself canonically sorted.
        for comp in first:
            self.assertEqual(comp, sorted(comp, key=metrics._canonical_sort_key))


class CondensationLongestPathTests(unittest.TestCase):
    def test_scc_size_reported_separately_from_path_length(self) -> None:
        # Big cycle {1,2,3,4} feeds into a lone node 5, which feeds into
        # a 2-cycle {6,7}. The biggest SCC (size 4) is NOT on the longest
        # path measured by node count if the chain of components is only
        # depth 2 vs some other structure -- here it happens to be on the
        # path, but the two metrics must still be reported as distinct
        # numbers rather than one being derived by assuming the other.
        graph = {
            1: [2],
            2: [3],
            3: [4],
            4: [1, 5],
            5: [6],
            6: [7],
            7: [6],
        }
        result = metrics.condensation_longest_path(graph)
        self.assertEqual(result["scc_count"], 3)
        self.assertEqual(result["max_scc_size"], 4)  # component {1,2,3,4}
        # Path: {1,2,3,4} -> {5} -> {6,7} => 3 components, 2 hops (edges).
        self.assertEqual(result["longest_path_components"], 3)
        self.assertEqual(result["longest_path_edges"], 2)
        self.assertEqual(
            result["longest_path_components"], len(result["longest_path_component_ids"])
        )
        # Descriptive node count along that path: 4 + 1 + 2 = 7. This is
        # NOT a claim of a realizable 7-node simple path (the 4-cycle and
        # the 2-cycle are SCCs, not walkable-through-once chains).
        self.assertEqual(result["nodes_in_path_components"], 7)
        self.assertNotIn("longest_path_nodes", result)
        self.assertEqual(len(result["sccs"]), 3)

    def test_disconnected_components_no_path(self) -> None:
        graph = {1: [2], 2: [1], 3: [4], 4: [3]}
        result = metrics.condensation_longest_path(graph)
        self.assertEqual(result["scc_count"], 2)
        self.assertEqual(result["max_scc_size"], 2)
        # No condensation edges at all -> longest path is a single
        # component, zero hops.
        self.assertEqual(result["longest_path_components"], 1)
        self.assertEqual(result["longest_path_edges"], 0)
        self.assertEqual(result["nodes_in_path_components"], 2)

    def test_single_node_no_edges(self) -> None:
        graph = {1: []}
        result = metrics.condensation_longest_path(graph)
        self.assertEqual(result["scc_count"], 1)
        self.assertEqual(result["max_scc_size"], 1)
        self.assertEqual(result["longest_path_components"], 1)
        self.assertEqual(result["longest_path_edges"], 0)
        self.assertEqual(result["nodes_in_path_components"], 1)

    def test_empty_graph(self) -> None:
        result = metrics.condensation_longest_path({})
        self.assertEqual(result["scc_count"], 0)
        self.assertEqual(result["max_scc_size"], 0)
        self.assertEqual(result["longest_path_component_ids"], [])
        self.assertEqual(result["longest_path_components"], 0)
        self.assertEqual(result["longest_path_edges"], 0)
        self.assertEqual(result["nodes_in_path_components"], 0)

    def test_max_scc_size_not_conflated_with_path_length(self) -> None:
        # A single giant SCC {1,2,3,4,5} with no other components at all:
        # max_scc_size is large (5), but there is nowhere else to go, so
        # the condensation-DAG path is trivially a single component with
        # zero hops. The two metrics must disagree sharply here.
        graph = {1: [2], 2: [3], 3: [4], 4: [5], 5: [1]}
        result = metrics.condensation_longest_path(graph)
        self.assertEqual(result["max_scc_size"], 5)
        self.assertEqual(result["longest_path_components"], 1)
        self.assertEqual(result["longest_path_edges"], 0)
        self.assertEqual(result["nodes_in_path_components"], 5)

    def test_deterministic_regardless_of_key_insertion_order(self) -> None:
        graph_a = {
            "a": ["b"],
            "b": ["c"],
            "c": ["a", "d"],
            "d": ["e"],
            "e": ["f"],
            "f": ["e"],
        }
        graph_b = {
            "f": ["e"],
            "e": ["f"],
            "d": ["e"],
            "c": ["a", "d"],
            "b": ["c"],
            "a": ["b"],
        }
        result_a = metrics.condensation_longest_path(graph_a)
        result_b = metrics.condensation_longest_path(graph_b)
        self.assertEqual(result_a["sccs"], result_b["sccs"])
        self.assertEqual(
            result_a["longest_path_component_ids"], result_b["longest_path_component_ids"]
        )
        self.assertEqual(
            result_a["longest_path_components"], result_b["longest_path_components"]
        )
        self.assertEqual(result_a["nodes_in_path_components"], result_b["nodes_in_path_components"])


class ProjectEdgesToModulesTests(unittest.TestCase):
    def setUp(self) -> None:
        # Controls A,B in module M1; C,D in module M2; E alone in M3.
        self.node_to_module = {
            "A": "M1",
            "B": "M1",
            "C": "M2",
            "D": "M2",
            "E": "M3",
        }

    def test_within_between_and_dedup_accounting(self) -> None:
        edges = [
            ("A", "B"),  # within M1
            ("A", "C"),  # between M1->M2
            ("B", "D"),  # between M1->M2 (duplicate DIRECTED module pair)
            ("C", "D"),  # within M2
            ("A", "E"),  # between M1->M3
            ("B", "E"),  # between M1->M3 (duplicate DIRECTED module pair)
            ("D", "E"),  # between M2->M3
        ]
        result = metrics.project_edges_to_modules(edges, self.node_to_module)

        self.assertEqual(result["original_within_count"], 2)  # (A,B) and (C,D)
        self.assertEqual(result["original_between_count"], 5)
        self.assertEqual(result["unique_projected_between_count"], 3)  # M1->M2, M1->M3, M2->M3
        self.assertEqual(result["duplicates_collapsed_count"], 2)  # 5 - 3
        self.assertEqual(
            result["unique_projected_between"],
            {("M1", "M2"), ("M1", "M3"), ("M2", "M3")},
        )
        self.assertEqual(len(result["within_edges"]), 2)
        self.assertEqual(len(result["between_edges"]), 5)
        self.assertEqual(result["unmapped_edges"], [])

    def test_opposite_directions_are_distinct_module_pairs(self) -> None:
        # (A -> C) is M1->M2; (D -> A) is M2->M1. These are OPPOSITE
        # directed module pairs and must both survive dedup as separate
        # entries, proving direction is preserved rather than collapsed
        # into an undirected {M1, M2} pair.
        edges = [
            ("A", "C"),  # M1 -> M2
            ("D", "A"),  # M2 -> M1 (reverse direction, same module pair)
            ("B", "C"),  # M1 -> M2 again (true duplicate, same direction)
        ]
        result = metrics.project_edges_to_modules(edges, self.node_to_module)

        self.assertEqual(result["original_between_count"], 3)
        # Only ('M1','M2') and ('M2','M1') survive as distinct directed
        # pairs; the third edge is a true duplicate of ('M1','M2').
        self.assertEqual(result["unique_projected_between_count"], 2)
        self.assertEqual(result["duplicates_collapsed_count"], 1)
        self.assertIn(("M1", "M2"), result["unique_projected_between"])
        self.assertIn(("M2", "M1"), result["unique_projected_between"])
        # It must NOT have collapsed ('M1','M2') and ('M2','M1') into a
        # single undirected entry.
        self.assertEqual(len(result["unique_projected_between"]), 2)

    def test_unmapped_edges_excluded_but_reported(self) -> None:
        edges = [("A", "B"), ("A", "Z")]  # Z is not in node_to_module
        result = metrics.project_edges_to_modules(edges, self.node_to_module)
        self.assertEqual(result["original_within_count"], 1)
        self.assertEqual(result["original_between_count"], 0)
        self.assertEqual(result["unmapped_edges"], [("A", "Z")])

    def test_no_edges(self) -> None:
        result = metrics.project_edges_to_modules([], self.node_to_module)
        self.assertEqual(result["original_within_count"], 0)
        self.assertEqual(result["original_between_count"], 0)
        self.assertEqual(result["unique_projected_between_count"], 0)
        self.assertEqual(result["duplicates_collapsed_count"], 0)


class WeightedCoverageGapTests(unittest.TestCase):
    def test_normal_case(self) -> None:
        gap = metrics.weighted_coverage_gap(covered_weight=30, total_weight=100)
        self.assertAlmostEqual(gap, 0.7)

    def test_full_coverage_is_zero_gap(self) -> None:
        gap = metrics.weighted_coverage_gap(covered_weight=50, total_weight=50)
        self.assertAlmostEqual(gap, 0.0)

    def test_rejects_zero_total(self) -> None:
        with self.assertRaises(ValueError):
            metrics.weighted_coverage_gap(covered_weight=0, total_weight=0)

    def test_rejects_negative_total(self) -> None:
        with self.assertRaises(ValueError):
            metrics.weighted_coverage_gap(covered_weight=1, total_weight=-5)

    def test_rejects_negative_covered(self) -> None:
        with self.assertRaises(ValueError):
            metrics.weighted_coverage_gap(covered_weight=-1, total_weight=5)

    def test_rejects_nan_covered(self) -> None:
        with self.assertRaises(ValueError):
            metrics.weighted_coverage_gap(covered_weight=math.nan, total_weight=5)

    def test_rejects_nan_total(self) -> None:
        with self.assertRaises(ValueError):
            metrics.weighted_coverage_gap(covered_weight=1, total_weight=math.nan)

    def test_rejects_covered_exceeding_total(self) -> None:
        with self.assertRaises(ValueError):
            metrics.weighted_coverage_gap(covered_weight=10, total_weight=5)


class RankingTests(unittest.TestCase):
    def test_standalone_ranking_deterministic_ties(self) -> None:
        scores = {"b": 5.0, "a": 5.0, "c": 9.0, "d": 1.0}
        ranking = metrics.standalone_ranking(scores)
        # c highest; a and b tie at 5.0, broken alphabetically -> a before b;
        # d last.
        self.assertEqual(ranking, ["c", "a", "b", "d"])

    def test_static_vs_marginal_gain_diverge_on_overlap(self) -> None:
        # Item "big" has the highest standalone score but its coverage is
        # a strict subset of the union of two smaller items. Once those
        # two are picked, "big" contributes nothing new.
        scores = {"big": 10.0, "x": 4.0, "y": 4.0}
        coverage_sets = {
            "big": {1, 2},
            "x": {1, 3},
            "y": {2, 4},
        }

        standalone = metrics.standalone_ranking(scores)
        self.assertEqual(standalone, ["big", "x", "y"])

        marginal = metrics.marginal_gain_ranking(coverage_sets)
        # Greedy: every item covers 2 new elements on the first pick;
        # tie-break picks "big" first (alphabetically first: "big" < "x" < "y").
        self.assertEqual(marginal[0], ("big", 2))
        # After "big" covers {1,2}, "x" only gains {3} (1 new) and "y" only
        # gains {4} (1 new) -- both drop from 2 to 1, showing the
        # divergence from a fixed standalone score that never recomputes.
        remaining_gains = {item_id: gain for item_id, gain in marginal[1:]}
        self.assertEqual(remaining_gains["x"], 1)
        self.assertEqual(remaining_gains["y"], 1)
        self.assertEqual(len(marginal), 3)

    def test_marginal_gain_respects_pre_covered(self) -> None:
        coverage_sets = {"a": {1, 2}, "b": {2, 3}}
        # Pre-covering {1, 2} should make "a" contribute nothing new.
        order = metrics.marginal_gain_ranking(coverage_sets, pre_covered={1, 2})
        gains = dict(order)
        self.assertEqual(gains["a"], 0)
        self.assertEqual(gains["b"], 1)  # only {3} is new

    def test_marginal_gain_tie_break_is_deterministic(self) -> None:
        coverage_sets = {"z": {1}, "y": {2}, "x": {3}}
        order = metrics.marginal_gain_ranking(coverage_sets)
        # All gains equal (1 each); tie-break must be ascending id.
        self.assertEqual([item_id for item_id, _ in order], ["x", "y", "z"])

    def test_weights_default_to_unweighted_behavior(self) -> None:
        coverage_sets = {"big": {1, 2}, "x": {1, 3}, "y": {2, 4}}
        unweighted = metrics.marginal_gain_ranking(coverage_sets)
        explicitly_unweighted = metrics.marginal_gain_ranking(
                coverage_sets, weights=None
            )
        self.assertEqual(unweighted, explicitly_unweighted)

    def test_nonuniform_weights_change_the_ranking(self) -> None:
        # "small" covers only element 9, but it is weighted so heavily
        # that it must be picked first even though "wide" covers two
        # elements. Unweighted, "wide" (gain 2) beats "small" (gain 1);
        # weighted, "small" (gain 100) beats "wide" (gain 2).
        coverage_sets = {"wide": {1, 2}, "small": {9}}
        weights = {1: 1.0, 2: 1.0, 9: 100.0}  # All observed weights are explicit.

        unweighted_order = metrics.marginal_gain_ranking(coverage_sets)
        self.assertEqual(unweighted_order[0][0], "wide")
        self.assertEqual(unweighted_order[0][1], 2)

        weighted_order = metrics.marginal_gain_ranking(coverage_sets, weights=weights)
        self.assertEqual(weighted_order[0][0], "small")
        self.assertEqual(weighted_order[0][1], 100.0)
        self.assertEqual(weighted_order[1][0], "wide")
        self.assertEqual(weighted_order[1][1], 2.0)

    def test_weighted_gain_respects_pre_covered_and_missing_weights(self) -> None:
        # Unobserved element 3 must not receive invented positive weight.
        coverage_sets = {"a": {1, 3}, "b": {2}}
        weights = {1: 5.0, 2: 5.0}
        order = metrics.marginal_gain_ranking(
            coverage_sets, pre_covered={1}, weights=weights
        )
        gains = dict(order)
        # "a" adds only an unweighted element; element 1 was pre-covered.
        self.assertEqual(gains["a"], 0.0)
        self.assertEqual(gains["b"], 5.0)


class PairedDescriptiveDiffTests(unittest.TestCase):
    def test_improved_tied_worse_and_medians(self) -> None:
        baseline = [10, 10, 10, 10, 10]
        comparison = [12, 10, 8, 10, 20]
        # diffs: +2, 0, -2, 0, +10
        result = metrics.paired_descriptive_diff(baseline, comparison)
        self.assertEqual(result["n"], 5)
        self.assertEqual(result["improved"], 2)
        self.assertEqual(result["tied"], 2)
        self.assertEqual(result["worse"], 1)
        # all diffs sorted: -2, 0, 0, 2, 10 -> median 0
        self.assertEqual(result["all_median"], 0)
        # nonzero diffs sorted: -2, 2, 10 -> median 2
        self.assertEqual(result["nonzero_median"], 2)

    def test_all_zero_differences(self) -> None:
        result = metrics.paired_descriptive_diff([5, 5, 5], [5, 5, 5])
        self.assertEqual(result["improved"], 0)
        self.assertEqual(result["worse"], 0)
        self.assertEqual(result["tied"], 3)
        self.assertEqual(result["all_median"], 0)
        self.assertIsNone(result["nonzero_median"])

    def test_mismatched_lengths_rejected(self) -> None:
        with self.assertRaises(ValueError):
            metrics.paired_descriptive_diff([1, 2], [1])

    def test_empty_input_rejected(self) -> None:
        with self.assertRaises(ValueError):
            metrics.paired_descriptive_diff([], [])


class ExactSignedRankTestTests(unittest.TestCase):
    def _brute_force_two_sided_p(self, nonzero_diffs):
        """Reference implementation: literally enumerate every sign
        assignment over the observed absolute values (using average ranks
        for ties), independent of the DP implementation under test."""
        abs_vals = [abs(d) for d in nonzero_diffs]
        ranks = metrics._average_ranks(abs_vals)
        n = len(nonzero_diffs)

        observed_signs = [1 if d > 0 else -1 for d in nonzero_diffs]
        observed_w_plus = sum(r for r, s in zip(ranks, observed_signs) if s > 0)
        total = sum(ranks)
        center = total / 2.0
        observed_dist = abs(observed_w_plus - center)

        extreme = 0
        for signs in itertools.product([1, -1], repeat=n):
            w_plus = sum(r for r, s in zip(ranks, signs) if s > 0)
            if abs(w_plus - center) >= observed_dist - 1e-9:
                extreme += 1
        return extreme / (2 ** n), observed_w_plus, total - observed_w_plus

    def test_matches_brute_force_on_small_example_with_ties(self) -> None:
        # Includes a tie (two differences of equal absolute value 3) and a
        # zero (excluded) to exercise both special cases at once.
        differences = [3, -3, 5, 0, 7]
        result = metrics.exact_signed_rank_test(differences)

        nonzero = [d for d in differences if d != 0]
        expected_p, expected_w_plus, expected_w_minus = self._brute_force_two_sided_p(
            nonzero
        )

        self.assertEqual(result["n_nonzero"], 4)
        self.assertEqual(result["n_zero_excluded"], 1)
        self.assertAlmostEqual(result["w_plus"], expected_w_plus)
        self.assertAlmostEqual(result["w_minus"], expected_w_minus)
        self.assertAlmostEqual(result["p_value_two_sided"], expected_p, places=9)

    def test_matches_brute_force_on_all_distinct_no_zeros(self) -> None:
        differences = [1, -2, 3, -4, 5, -6]
        result = metrics.exact_signed_rank_test(differences)
        expected_p, expected_w_plus, expected_w_minus = self._brute_force_two_sided_p(
            differences
        )
        self.assertEqual(result["n_zero_excluded"], 0)
        self.assertAlmostEqual(result["w_plus"], expected_w_plus)
        self.assertAlmostEqual(result["w_minus"], expected_w_minus)
        self.assertAlmostEqual(result["p_value_two_sided"], expected_p, places=9)

    def test_all_positive_gives_minimum_p_value_and_positive_direction(self) -> None:
        differences = [1, 2, 3, 4, 5]
        result = metrics.exact_signed_rank_test(differences)
        # Only one of 2^5 sign assignments (all positive) is this extreme;
        # by symmetry all-negative is equally extreme too.
        self.assertAlmostEqual(result["p_value_two_sided"], 2 / 32)
        self.assertEqual(result["direction"], "positive")
        self.assertAlmostEqual(result["rank_biserial"], 1.0)

    def test_all_zero_differences_raises(self) -> None:
        with self.assertRaises(ValueError):
            metrics.exact_signed_rank_test([0, 0, 0])

    def test_rank_biserial_sign_matches_direction_label(self) -> None:
        # More/larger negative differences -> negative rank-biserial.
        differences = [-10, -8, 1]
        result = metrics.exact_signed_rank_test(differences)
        self.assertLess(result["rank_biserial"], 0)
        self.assertEqual(result["direction"], "negative")

    def test_note_labels_statistic_as_conditional_not_independent(self) -> None:
        result = metrics.exact_signed_rank_test([1, -2, 3])
        note = result["note"].lower()
        self.assertIn("conditional", note)
        self.assertIn("not an independent", note)


if __name__ == "__main__":
    unittest.main()
