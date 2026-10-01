"""Standard-library-only research primitives for the M2SBF public-data pipeline.

This module intentionally has zero third-party dependencies and performs no
network access. It is a fresh, independent implementation written against a
new public-data pipeline; it never reads, fits, or reproduces any numbers
from the M2SBF manuscript. Every function below documents exactly what it
computes so results can be audited from first principles.

Contents
--------
1. Directed-graph strongly-connected-component (SCC) analysis and
   condensation-DAG longest-path metrics. SCC size (`max_scc_size`) is kept
   separate from condensation-path length (`longest_path_components` /
   `longest_path_edges`), which is in turn kept separate from
   `nodes_in_path_components`, an explicitly-labeled *descriptive node
   count* rather than a claim of a realizable simple-path length in the
   original graph. All traversal is canonically sorted so results are
   deterministic regardless of `PYTHONHASHSEED` or input key order.
2. Projection of an original control-level "related control" edge list onto
   a coarser module partition, with original within/between edge counts
   kept separate from the deduplicated (unique) projected *directed*
   between-module edge set and the count of duplicates collapsed by that
   projection. Direction is preserved: `(A, C)` and `(C, A)` project onto
   distinct directed module pairs and are never merged.
3. A weighted coverage-gap statistic that rejects negative, NaN, or
   zero-total inputs rather than silently producing a misleading number.
4. Two deterministic ranking procedures over the same input (a fixed
   "standalone score" ordering and a greedy recomputed, optionally
   *element-weighted*, "marginal gain" ordering that supports pre-covered
   items), both with stable tie-breaking on item id so results are
   reproducible.
5. Paired descriptive-difference summary statistics (baseline vs.
   comparison), separating improved/tied/worse counts and separating the
   median of *all* paired differences from the median of only the
   *non-zero* differences.
6. An optional exact two-sided Wilcoxon signed-rank test computed by full
   sign-randomization dynamic programming (average ranks for ties, zero
   differences excluded), reporting a signed rank-biserial effect size and
   explicitly labeled as a conditional, within-sample randomization
   statistic -- not an independent, organization-level inferential claim.
"""

from __future__ import annotations

import math
from collections import defaultdict, deque
from statistics import median
from typing import (
    Any,
    Dict,
    Hashable,
    Iterable,
    List,
    Mapping,
    Optional,
    Sequence,
    Set,
    Tuple,
)

Node = Hashable


def _canonical_sort_key(node: Node) -> Tuple[str, str]:
    """Hash-independent, insertion-order-independent sort key for a node.

    Iteration order over Python ``set`` objects depends on object hash
    values, which are randomized per-process for strings unless
    ``PYTHONHASHSEED`` is fixed. To keep every traversal, tie-break, and
    reported ordering in this module reproducible regardless of
    ``PYTHONHASHSEED`` and regardless of the order keys were inserted into
    the input mapping, all node/edge iteration in this module is explicitly
    sorted by this key: ``(type name, repr)``. ``repr`` gives a total,
    process-independent order for the built-in hashable types used as node
    ids (str, int, tuple, etc.); grouping by type name first avoids
    cross-type comparison errors (e.g. int vs. str) while still being fully
    deterministic.
    """
    return (type(node).__name__, repr(node))


# ---------------------------------------------------------------------------
# 1. Directed SCC / condensation longest path
# ---------------------------------------------------------------------------


def compute_sccs(graph: Mapping[Node, Iterable[Node]]) -> List[List[Node]]:
    """Compute strongly connected components of a directed graph.

    Uses an iterative (non-recursive) version of Tarjan's algorithm so it
    is safe on graphs deeper than the Python recursion limit.

    Parameters
    ----------
    graph:
        Mapping from node to an iterable of its direct successor nodes.
        Nodes that only ever appear as a successor value (and never as a
        key) are still included in the output as singleton components.

    Returns
    -------
    List of SCCs, each a list of nodes sorted by :func:`_canonical_sort_key`.
    The outer list order is the order in which Tarjan's algorithm closes
    each component (a reverse-topological order of the condensation DAG),
    which is itself deterministic because traversal order is deterministic;
    callers that need a specific topological order should use
    :func:`condensation_longest_path`, which computes one explicitly.

    Determinism
    ------------
    Traversal always visits unvisited start nodes, and each node's
    successors, in canonically sorted order (see
    :func:`_canonical_sort_key`). The result is therefore identical across
    runs regardless of ``PYTHONHASHSEED`` and regardless of the key
    insertion order of the input ``graph`` mapping -- only the graph's
    actual node/edge structure determines the output.
    """
    node_set: Set[Node] = set(graph.keys())
    for succs in graph.values():
        node_set.update(succs)
    all_nodes: List[Node] = sorted(node_set, key=_canonical_sort_key)
    full_graph: Dict[Node, List[Node]] = {
        n: sorted(graph.get(n, []), key=_canonical_sort_key) for n in all_nodes
    }

    index_counter = 0
    index: Dict[Node, int] = {}
    lowlink: Dict[Node, int] = {}
    on_stack: Dict[Node, bool] = {}
    tarjan_stack: List[Node] = []
    result: List[List[Node]] = []

    for start in all_nodes:
        if start in index:
            continue

        work_stack: List[Tuple[Node, Any]] = [(start, iter(full_graph[start]))]
        index[start] = index_counter
        lowlink[start] = index_counter
        index_counter += 1
        tarjan_stack.append(start)
        on_stack[start] = True

        while work_stack:
            v, successors_iter = work_stack[-1]
            pushed_child = False
            for w in successors_iter:
                if w not in index:
                    index[w] = index_counter
                    lowlink[w] = index_counter
                    index_counter += 1
                    tarjan_stack.append(w)
                    on_stack[w] = True
                    work_stack.append((w, iter(full_graph[w])))
                    pushed_child = True
                    break
                elif on_stack.get(w, False):
                    lowlink[v] = min(lowlink[v], index[w])
            if pushed_child:
                continue

            work_stack.pop()
            if work_stack:
                parent = work_stack[-1][0]
                lowlink[parent] = min(lowlink[parent], lowlink[v])

            if lowlink[v] == index[v]:
                component: List[Node] = []
                while True:
                    w = tarjan_stack.pop()
                    on_stack[w] = False
                    component.append(w)
                    if w == v:
                        break
                component.sort(key=_canonical_sort_key)
                result.append(component)

    return result


def condensation_longest_path(graph: Mapping[Node, Iterable[Node]]) -> Dict[str, Any]:
    """Compute the longest chain of components in the condensation DAG.

    The condensation DAG collapses every SCC into a single super-node and
    keeps an edge between two super-nodes whenever any original edge
    crosses between their components. This function reports three
    deliberately distinct metrics that must never be conflated:

    - ``max_scc_size``: the size of the single largest SCC (a property of
      one component, independent of any path).
    - ``longest_path_components`` / ``longest_path_edges``: the length of
      the longest chain through the *condensation DAG*, measured in
      component hops (``longest_path_edges == longest_path_components - 1``
      for a non-empty path).
    - ``nodes_in_path_components``: the sum of the sizes of the components
      that lie on that condensation-DAG path. This is a **descriptive
      count of nodes contained in those components**, not a claim that a
      simple path of that many original-graph nodes/edges is realizable.
      A component with more than one node is an SCC (a cycle), so a single
      simple path that walks through it and reaches every one of its nodes
      before continuing to the next component is not generally possible;
      this number only says how many original nodes live inside the
      components that the condensation-level path touches.

    Parameters
    ----------
    graph:
        Mapping from node to an iterable of its direct successor nodes.

    Returns
    -------
    Dict with keys:
        - ``scc_count``: number of strongly connected components.
        - ``max_scc_size``: size (node count) of the largest single SCC.
        - ``sccs``: the list of SCCs (each a list of nodes), as returned by
          :func:`compute_sccs`.
        - ``longest_path_component_ids``: indices into ``sccs`` describing
          the longest chain through the condensation DAG, in topological
          (start-to-end) order.
        - ``longest_path_components``: ``len(longest_path_component_ids)``,
          the number of components on that chain.
        - ``longest_path_edges``: number of condensation-DAG edges on that
          path (component-to-component hops); equals
          ``longest_path_components - 1`` when the path is non-empty, and
          ``0`` when the graph is empty.
        - ``nodes_in_path_components``: total number of *original* graph
          nodes contained in the components on that path (sum of their
          sizes) -- a descriptive node-count, **not** a realizable
          simple-path length in the original graph (see caveat above).

    Determinism
    ------------
    All node/component/successor iteration is taken in canonically sorted
    order (see :func:`_canonical_sort_key` and :func:`compute_sccs`), and
    equal-scoring predecessor paths retain the first predecessor in the
    deterministic Kahn traversal. Final endpoint ties prefer the lowest
    component id. This does not promise a lexicographically smallest full
    path. The result is identical
    regardless of ``PYTHONHASHSEED`` and regardless of the input mapping's
    key insertion order.
    """
    sccs = compute_sccs(graph)
    node_to_scc: Dict[Node, int] = {}
    for i, component in enumerate(sccs):
        for n in component:
            node_to_scc[n] = i

    all_nodes = sorted(node_to_scc.keys(), key=_canonical_sort_key)
    full_graph: Dict[Node, List[Node]] = {
        n: sorted(graph.get(n, []), key=_canonical_sort_key) for n in all_nodes
    }

    cond_edges: Dict[int, Set[int]] = defaultdict(set)
    for n in all_nodes:
        a = node_to_scc[n]
        for s in full_graph[n]:
            if s not in node_to_scc:
                continue
            b = node_to_scc[s]
            if a != b:
                cond_edges[a].add(b)

    num_components = len(sccs)

    indegree = {i: 0 for i in range(num_components)}
    for a in range(num_components):
        for b in sorted(cond_edges.get(a, ())):
            indegree[b] += 1

    queue: deque = deque(i for i in range(num_components) if indegree[i] == 0)
    topo: List[int] = []
    indegree_work = dict(indegree)
    while queue:
        u = queue.popleft()
        topo.append(u)
        for v in sorted(cond_edges.get(u, ())):
            indegree_work[v] -= 1
            if indegree_work[v] == 0:
                queue.append(v)
    # Condensation must be acyclic; fail explicitly if this invariant breaks.
    if len(topo) != num_components:
        raise ValueError("Condensation graph unexpectedly contains a cycle")
    # Component ids are assigned in
    # canonically sorted Tarjan-discovery order, and both queue seeding
    # (ascending range) and edge relaxation (sorted) are deterministic, so
    # `topo` itself is fully deterministic.

    best_edges = {i: 0 for i in range(num_components)}
    best_nodes = {i: len(sccs[i]) for i in range(num_components)}
    parent: Dict[int, Optional[int]] = {i: None for i in range(num_components)}

    for u in topo:
        for v in sorted(cond_edges.get(u, ())):
            cand_edges = best_edges[u] + 1
            cand_nodes = best_nodes[u] + len(sccs[v])
            if cand_edges > best_edges[v] or (
                cand_edges == best_edges[v] and cand_nodes > best_nodes[v]
            ):
                best_edges[v] = cand_edges
                best_nodes[v] = cand_nodes
                parent[v] = u

    if num_components == 0:
        end = None
    else:
        # Ties broken by lowest component id: ascending `range` iteration
        # order plus deterministic component-id assignment above makes
        # `max` return the same index every run.
        end = max(range(num_components), key=lambda i: (best_edges[i], best_nodes[i]))

    path: List[int] = []
    cur = end
    while cur is not None:
        path.append(cur)
        cur = parent[cur]
    path.reverse()

    return {
        "scc_count": num_components,
        "max_scc_size": max((len(c) for c in sccs), default=0),
        "sccs": sccs,
        "longest_path_component_ids": path,
        "longest_path_components": len(path),
        "longest_path_edges": best_edges[end] if end is not None else 0,
        "nodes_in_path_components": best_nodes[end] if end is not None else 0,
    }


# ---------------------------------------------------------------------------
# 2. Projecting original control edges onto modules
# ---------------------------------------------------------------------------


def project_edges_to_modules(
    edges: Iterable[Tuple[Node, Node]],
    node_to_module: Mapping[Node, Hashable],
) -> Dict[str, Any]:
    """Project original "related control" edges onto a module partition.

    Every original edge ``(u, v)`` is classified as:
        - *within*: ``node_to_module[u] == node_to_module[v]``.
        - *between*: the two endpoints map to different modules.
        - *unmapped*: either endpoint is missing from ``node_to_module``
          (excluded from all counts below, reported separately so it is
          never silently dropped).

    The set of *between* edges is then projected onto **directed** module
    pairs ``(node_to_module[u], node_to_module[v])``. Direction is
    preserved deliberately: an edge ``(A, C)`` and its reverse ``(C, A)``
    project onto the *distinct* directed pairs ``(M1, M2)`` and
    ``(M2, M1)`` and are **not** deduplicated against each other, because
    the underlying relationship is directed and collapsing direction would
    silently discard information about which module the edge originates
    from. Only genuinely duplicate directed module pairs (same source
    module *and* same target module) are deduplicated.

    Parameters
    ----------
    edges:
        Iterable of ``(source, target)`` control-id pairs. Direction is
        significant: ``(u, v)`` is treated as a different edge from
        ``(v, u)`` throughout this function.
    node_to_module:
        Mapping from control id to the module id that contains it.

    Returns
    -------
    Dict with keys:
        - ``original_within_count``: count of original edges within a
          single module.
        - ``original_between_count``: count of original edges spanning two
          different modules (before dedup).
        - ``unique_projected_between``: set of directed
          ``(mod_source, mod_target)`` tuples -- the deduplicated,
          direction-preserving module-to-module edge set. ``(M1, M2)`` and
          ``(M2, M1)`` are both retained as separate entries whenever both
          directions occur in the input.
        - ``unique_projected_between_count``: ``len(unique_projected_between)``.
        - ``duplicates_collapsed_count``: ``original_between_count -
          unique_projected_between_count``, i.e. how many original edges
          were redundant once projected onto the same *directed* module
          pair.
        - ``within_edges`` / ``between_edges`` / ``unmapped_edges``: the
          original edges classified into each bucket, for auditability.
    """
    within_edges: List[Tuple[Node, Node]] = []
    between_edges: List[Tuple[Node, Node]] = []
    unmapped_edges: List[Tuple[Node, Node]] = []
    unique_between_pairs: Set[Tuple[Hashable, Hashable]] = set()

    for edge in edges:
        u, v = edge
        if u not in node_to_module or v not in node_to_module:
            unmapped_edges.append(edge)
            continue
        mod_u = node_to_module[u]
        mod_v = node_to_module[v]
        if mod_u == mod_v:
            within_edges.append(edge)
        else:
            between_edges.append(edge)
            unique_between_pairs.add((mod_u, mod_v))

    original_between_count = len(between_edges)
    unique_projected_between_count = len(unique_between_pairs)

    return {
        "original_within_count": len(within_edges),
        "original_between_count": original_between_count,
        "unique_projected_between": unique_between_pairs,
        "unique_projected_between_count": unique_projected_between_count,
        "duplicates_collapsed_count": original_between_count
        - unique_projected_between_count,
        "within_edges": within_edges,
        "between_edges": between_edges,
        "unmapped_edges": unmapped_edges,
    }


# ---------------------------------------------------------------------------
# 3. Weighted coverage gap
# ---------------------------------------------------------------------------


def weighted_coverage_gap(covered_weight: float, total_weight: float) -> float:
    """Compute the fraction of total weight that is *not* covered.

    ``gap = (total_weight - covered_weight) / total_weight``

    Rejects inputs that would make this statistic meaningless or undefined:
    NaN in either input, a negative value in either input, a zero (or
    otherwise non-positive) ``total_weight``, or ``covered_weight`` that
    exceeds ``total_weight``.

    Parameters
    ----------
    covered_weight:
        Non-negative total weight of covered items.
    total_weight:
        Positive total weight of all items (covered + uncovered).

    Returns
    -------
    Coverage gap as a float in ``[0.0, 1.0]``.

    Raises
    ------
    ValueError
        If either input is NaN, either input is negative, ``total_weight``
        is not strictly positive, or ``covered_weight > total_weight``.
    """
    if not math.isfinite(covered_weight) or not math.isfinite(total_weight):
        raise ValueError("weighted_coverage_gap: inputs must be finite")
    if covered_weight < 0 or total_weight < 0:
        raise ValueError("weighted_coverage_gap: inputs must not be negative")
    if total_weight == 0:
        raise ValueError(
            "weighted_coverage_gap: total_weight must be positive (got zero)"
        )
    if covered_weight > total_weight:
        raise ValueError(
            "weighted_coverage_gap: covered_weight cannot exceed total_weight"
        )
    return (total_weight - covered_weight) / total_weight


# ---------------------------------------------------------------------------
# 4. Deterministic rankings: standalone score vs. genuine marginal gain
# ---------------------------------------------------------------------------


def standalone_ranking(scores: Mapping[Hashable, float]) -> List[Hashable]:
    """Rank items by a fixed, precomputed "standalone" score.

    This ordering never looks at overlap between items: it is exactly the
    scores given, sorted descending, with ties broken by ascending
    string-form id so the result is fully deterministic and reproducible
    across runs and platforms.

    Parameters
    ----------
    scores:
        Mapping from item id to its standalone score.

    Returns
    -------
    List of item ids, best (highest score) first.
    """
    if any(not math.isfinite(v) or v < 0 for v in scores.values()):
        raise ValueError("standalone_ranking: scores must be finite and nonnegative")
    return sorted(scores.keys(), key=lambda item_id: (-scores[item_id], str(item_id)))


def marginal_gain_ranking(
    coverage_sets: Mapping[Hashable, Set[Hashable]],
    pre_covered: Optional[Set[Hashable]] = None,
    weights: Optional[Mapping[Hashable, float]] = None,
) -> List[Tuple[Hashable, float]]:
    """Rank items by *genuine, recomputed* greedy weighted marginal gain.

    Unlike :func:`standalone_ranking`, this is a greedy maximum-coverage
    procedure: at each step it picks the item whose *remaining* new
    coverage (elements not already covered by previously picked items or
    by ``pre_covered``) contributes the largest total weight, then updates
    the covered set before evaluating the next step. This means an item
    with a high standalone score can still rank low here if everything it
    covers is already covered by earlier picks (or by ``pre_covered``) --
    that divergence is the point of computing both rankings separately.

    Weighting: each *covered element* (not each item) may carry an
    importance weight via ``weights``. An element missing from an explicit
    weight map receives zero credit. With ``weights=None``, every element
    receives weight 1.0, giving unweighted new-element-count gain. Non-uniform weights can and do change the greedy pick order
    relative to the unweighted case: an item covering fewer but
    higher-weight elements can legitimately outrank an item covering more
    lower-weight elements.

    Ties in marginal gain are broken by ascending string-form item id, so
    the ordering is fully deterministic.

    Parameters
    ----------
    coverage_sets:
        Mapping from item id to the set of elements it covers.
    pre_covered:
        Optional set of elements considered already covered before the
        greedy procedure starts (e.g. by controls/items outside this
        ranking exercise). Defaults to the empty set.
    weights:
        Optional mapping from covered-element id to a non-negative
        importance weight. Elements not present in this mapping default to
        weight ``0.0``. Defaults to ``None``, which is fully unweighted
        (every element weight ``1.0``, i.e. plain coverage-count gain).

    Returns
    -------
    List of ``(item_id, marginal_gain)`` pairs in greedy pick order, where
    ``marginal_gain`` is the total weight of *new* elements that item
    covered at the moment it was picked (an integer count when
    ``weights`` is ``None``, a weighted float sum otherwise).
    """
    if weights is not None and any(not math.isfinite(v) or v < 0 for v in weights.values()):
        raise ValueError("marginal_gain_ranking: weights must be finite and nonnegative")
    covered: Set[Hashable] = set(pre_covered) if pre_covered else set()
    remaining: Dict[Hashable, Set[Hashable]] = {
        item_id: set(elements) for item_id, elements in coverage_sets.items()
    }

    def _gain(elements: Set[Hashable]) -> float:
        new_elements = elements - covered
        if weights is None:
            return len(new_elements)
        return math.fsum(weights.get(e, 0.0) for e in sorted(new_elements, key=_canonical_sort_key))

    order: List[Tuple[Hashable, float]] = []

    while remaining:
        best_id: Optional[Hashable] = None
        best_gain: float = -1.0
        for item_id in sorted(remaining.keys(), key=str):
            gain = _gain(remaining[item_id])
            if gain > best_gain:
                best_gain = gain
                best_id = item_id
        assert best_id is not None
        order.append((best_id, best_gain))
        covered |= remaining[best_id]
        del remaining[best_id]

    return order


# ---------------------------------------------------------------------------
# 5. Paired descriptive differences
# ---------------------------------------------------------------------------


def paired_descriptive_diff(
    baseline: Sequence[float], comparison: Sequence[float]
) -> Dict[str, Any]:
    """Summarize paired differences between a baseline and a comparison.

    This is a purely descriptive analytics summary: it makes no inferential
    (population-level) claim on its own. See
    :func:`exact_signed_rank_test` for an explicitly-labeled conditional
    inferential statistic that can optionally be layered on top of the same
    differences.

    Parameters
    ----------
    baseline, comparison:
        Equal-length sequences of paired numeric observations. Difference
        for pair ``i`` is defined as ``comparison[i] - baseline[i]`` (so a
        positive difference means the comparison improved on the
        baseline).

    Returns
    -------
    Dict with keys:
        - ``n``: number of pairs.
        - ``improved``: count of pairs with ``difference > 0``.
        - ``tied``: count of pairs with ``difference == 0``.
        - ``worse``: count of pairs with ``difference < 0``.
        - ``all_median``: median over *all* differences, ties included.
        - ``nonzero_median``: median over only the non-zero differences,
          or ``None`` if every difference is zero (kept separate from
          ``all_median`` because ties can otherwise mask the typical size
          of a real change).
        - ``differences``: the raw list of per-pair differences.

    Raises
    ------
    ValueError
        If the two sequences have different lengths or are empty.
    """
    if len(baseline) != len(comparison):
        raise ValueError(
            "paired_descriptive_diff: baseline and comparison must be the same length"
        )
    if len(baseline) == 0:
        raise ValueError("paired_descriptive_diff: need at least one pair")

    diffs = [c - b for b, c in zip(baseline, comparison)]
    improved = sum(1 for d in diffs if d > 0)
    worse = sum(1 for d in diffs if d < 0)
    tied = sum(1 for d in diffs if d == 0)
    nonzero = [d for d in diffs if d != 0]

    return {
        "n": len(diffs),
        "improved": improved,
        "tied": tied,
        "worse": worse,
        "all_median": median(diffs),
        "nonzero_median": median(nonzero) if nonzero else None,
        "differences": diffs,
    }


# ---------------------------------------------------------------------------
# 6. Exact two-sided signed-rank test (sign-randomization DP)
# ---------------------------------------------------------------------------


def _average_ranks(values: Sequence[float]) -> List[float]:
    """Assign 1-indexed ranks to ``values``, averaging ranks within ties."""
    n = len(values)
    order = sorted(range(n), key=lambda i: values[i])
    ranks = [0.0] * n
    i = 0
    while i < n:
        j = i
        while j + 1 < n and values[order[j + 1]] == values[order[i]]:
            j += 1
        avg_rank = (i + 1 + j + 1) / 2.0
        for k in range(i, j + 1):
            ranks[order[k]] = avg_rank
        i = j + 1
    return ranks


def exact_signed_rank_test(differences: Sequence[float]) -> Dict[str, Any]:
    """Exact two-sided Wilcoxon signed-rank test via sign-randomization DP.

    This computes the *exact* null distribution of the signed-rank
    statistic by dynamic programming over all ``2**n`` possible sign flips
    of the observed non-zero absolute differences (``n`` = number of
    non-zero differences), rather than a normal approximation. Tied
    absolute differences receive the average of the ranks they span.
    Differences equal to zero are excluded from the ranking entirely, per
    the standard Wilcoxon signed-rank convention, and the count of excluded
    zeros is reported.

    IMPORTANT -- interpretation label: the resulting p-value is a
    *conditional randomization statistic*: it answers "assuming the
    observed multiset of absolute differences, how extreme is the observed
    split of signs relative to all equally-likely sign assignments?" It is
    a within-sample paired-comparison statistic. It is **not** an
    independent, organization-level (between-subjects) inferential claim,
    and must not be reported or read as one.

    Parameters
    ----------
    differences:
        Sequence of paired differences (e.g. ``comparison - baseline`` per
        pair). Zero differences are excluded automatically.

    Returns
    -------
    Dict with keys:
        - ``n_nonzero``: number of non-zero differences used.
        - ``n_zero_excluded``: number of zero differences excluded.
        - ``w_plus`` / ``w_minus``: sum of ranks assigned to positive /
          negative differences.
        - ``statistic``: ``min(w_plus, w_minus)``, the conventional
          two-sided Wilcoxon signed-rank statistic.
        - ``p_value_two_sided``: exact two-sided p-value from the full
          sign-randomization distribution.
        - ``rank_biserial``: signed matched-pairs rank-biserial effect
          size, ``(w_plus - w_minus) / (w_plus + w_minus)``, in
          ``[-1, 1]``. Positive means the positive differences carried
          more rank-weight (comparison exceeded baseline more/bigger);
          negative means the opposite.
        - ``direction``: ``"positive"``, ``"negative"``, or ``"none"``
          (zero rank-biserial), naming which side ``rank_biserial`` favors.
        - ``note``: the interpretation-label string described above.

    Raises
    ------
    ValueError
        If every difference is zero (statistic is undefined).
    """
    nonzero_diffs = [d for d in differences if d != 0]
    n = len(nonzero_diffs)
    if n == 0:
        raise ValueError(
            "exact_signed_rank_test: all differences are zero; statistic is undefined"
        )

    abs_vals = [abs(d) for d in nonzero_diffs]
    signs = [1 if d > 0 else -1 for d in nonzero_diffs]
    ranks = _average_ranks(abs_vals)

    w_plus = sum(r for r, s in zip(ranks, signs) if s > 0)
    total_rank = sum(ranks)
    w_minus = total_rank - w_plus

    # Ranks under tie-averaging are always multiples of 0.5; scale by 2 to
    # do exact integer DP and avoid floating-point accumulation error.
    scaled_ranks = [round(r * 2) for r in ranks]
    total_scaled = sum(scaled_ranks)
    center_scaled = total_scaled / 2.0

    dist: Dict[int, int] = defaultdict(int)
    dist[0] = 1
    for r in scaled_ranks:
        new_dist: Dict[int, int] = defaultdict(int)
        for s, cnt in dist.items():
            new_dist[s] += cnt
            new_dist[s + r] += cnt
        dist = new_dist

    total_assignments = 2 ** n
    observed_scaled = round(w_plus * 2)
    observed_dist_from_center = abs(observed_scaled - center_scaled)

    extreme_count = sum(
        cnt
        for s, cnt in dist.items()
        if abs(s - center_scaled) >= observed_dist_from_center - 1e-9
    )
    p_value = min(1.0, extreme_count / total_assignments)

    rank_biserial = (w_plus - w_minus) / total_rank if total_rank > 0 else 0.0
    if rank_biserial > 0:
        direction = "positive"
    elif rank_biserial < 0:
        direction = "negative"
    else:
        direction = "none"

    return {
        "n_nonzero": n,
        "n_zero_excluded": len(differences) - n,
        "w_plus": w_plus,
        "w_minus": w_minus,
        "statistic": min(w_plus, w_minus),
        "p_value_two_sided": p_value,
        "rank_biserial": rank_biserial,
        "direction": direction,
        "note": (
            "Exact conditional sign-randomization statistic over the observed "
            "|differences| multiset (2^n sign flips). This is a within-sample "
            "paired-comparison statistic, not an independent, "
            "organizational-level inferential claim."
        ),
    }
