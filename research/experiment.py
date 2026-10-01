"""Deterministic frequency-based experiments. No legacy weights or fitted targets."""
from collections import Counter
from math import ceil, floor, fsum, isfinite
from random import Random
from statistics import median
from . import metrics


def frequencies(records):
    """Mean fractional candidate-technique credit per mapped source record."""
    if not records:
        raise ValueError("Cannot estimate frequencies from an empty mapped pool")
    values = {}
    for row in records:
        for technique, credit in sorted(row["credits"].items()):
            if not isfinite(credit) or not 0 < credit <= 1:
                raise ValueError("Incident-technique credits must be finite and in (0,1]")
            values.setdefault(technique, []).append(credit)
    return {t: fsum(v) / len(records) for t, v in sorted(values.items())}


def coverage_of(units, coverage):
    return set().union(*(coverage[u] for u in units)) if units else set()


def gap(weights, covered):
    keys = sorted(weights)
    total = fsum(weights[t] for t in keys)
    hit = fsum(weights[t] for t in keys if t in covered)
    return metrics.weighted_coverage_gap(hit, total)


def static_order(units, coverage, weights):
    scores = {u: fsum(weights.get(t, 0.0) for t in sorted(coverage[u])) for u in units}
    return metrics.standalone_ranking(scores), scores


def milestone_count(fraction, remaining):
    if not 0 <= fraction <= 1 or remaining < 0:
        raise ValueError("Invalid milestone fraction or remaining-unit count")
    return min(remaining, ceil(fraction * remaining))


def split_pool(pool, fraction, seed):
    """Source IDs were collision-excluded by loader. Split before bootstrapping."""
    if len(pool) < 2 or not 0 < fraction < 1:
        raise ValueError("Held-out analysis requires >=2 mapped records and 0<fraction<1")
    shuffled = sorted(pool, key=lambda x: (x["incident_id"], x["source_path"]))
    Random(seed).shuffle(shuffled)
    cut = min(len(pool) - 1, max(1, floor(len(pool) * fraction)))
    train, test = shuffled[:cut], shuffled[cut:]
    assert {r["incident_id"] for r in train}.isdisjoint(r["incident_id"] for r in test)
    return train, test


def evaluate_paths(data, spec, profile_id, suite, weights, rank_weights, initial_modules, top25):
    """Report module-unit and matched atomic-control budgets as DISTINCT designs."""
    module_cov, control_cov = data["module_coverage"], data["control_coverage"]
    initial_modules = list(initial_modules)
    initial_controls = [c for c in data["control_order"] if data["controls"][c]["module"] in initial_modules]
    remaining_modules = [m for m in data["module_order"] if m not in initial_modules]
    analytics, scores = static_order(remaining_modules, module_cov, rank_weights)
    remaining_controls = [c for c in data["control_order"] if c not in initial_controls]
    flattened = [c for m in analytics for c in remaining_controls if data["controls"][c]["module"] == m]
    if set(flattened) != set(remaining_controls) or len(flattened) != len(remaining_controls):
        raise ValueError("Analytics flattening is not a partition of remaining Low controls")
    rows = []
    for milestone in spec["evaluation"]["milestones"]:
        km = milestone_count(milestone, len(remaining_modules))
        kc = milestone_count(milestone, len(remaining_controls))
        designs = [
            ("module_analytics", "module", analytics[:km]),
            ("module_rule", "module", remaining_modules[:km]),
            ("matched_control_analytics", "control", flattened[:kc]),
            ("matched_control_nist", "control", remaining_controls[:kc]),
        ]
        for scenario, unit, selected in designs:
            if unit == "module":
                modules = initial_modules + selected
                controls = [c for c in data["control_order"] if data["controls"][c]["module"] in modules]
                covered = coverage_of(modules, module_cov)
            else:
                controls = initial_controls + selected
                covered = coverage_of(controls, control_cov)
                modules = None  # A partial module is not represented as fully implemented.
            rows.append({
                "profile_id": profile_id, "suite": suite, "milestone": milestone,
                "scenario": scenario, "budget_unit": unit, "new_units": len(selected),
                "remaining_units": len(remaining_modules) if unit == "module" else len(remaining_controls),
                "selected_units": selected, "preimplemented_modules": initial_modules,
                "preimplemented_controls": initial_controls, "implemented_modules": modules,
                "implemented_control_count": len(controls), "implemented_controls": controls,
                "covered_parent_technique_count": len(covered), "weighted_gap": gap(weights, covered),
                "top25_unweighted_gap": len(set(top25) - covered) / len(top25),
            })
    return rows, {"analytics_order": analytics, "standalone_scores": scores,
                  "rule_order": remaining_modules, "matched_control_analytics_order": flattened}


def summarize(rows, spec):
    """Positive differences mean LOWER analytics gap: baseline minus analytics."""
    results = []
    for suite in ("in_sample", "held_out"):
        for milestone in spec["evaluation"]["milestones"]:
            for analytics, baseline, budget in [
                ("module_analytics", "module_rule", "remaining modules"),
                ("matched_control_analytics", "matched_control_nist", "remaining Low controls"),
            ]:
                lookup = {(r["profile_id"], r["scenario"]): r for r in rows
                          if r["suite"] == suite and r["milestone"] == milestone}
                ids = sorted({p for p, scenario in lookup if scenario == analytics})
                a = [lookup[(p, analytics)]["weighted_gap"] for p in ids]
                b = [lookup[(p, baseline)]["weighted_gap"] for p in ids]
                differences = [0.0 if abs(y - x) <= spec["statistics"]["zero_tolerance"] else y - x
                               for x, y in zip(a, b)]
                nonzero = [d for d in differences if d != 0]
                summary = {"n": len(ids), "improved": sum(d > 0 for d in differences),
                           "tied": sum(d == 0 for d in differences), "worse": sum(d < 0 for d in differences),
                           "all_median": median(differences),
                           "nonzero_median": median(nonzero) if nonzero else None, "differences": differences}
                conditional = ({"status": "computed", **metrics.exact_signed_rank_test(differences)} if nonzero else
                               {"status": "undefined_all_zero", "n_nonzero": 0,
                                "n_zero_excluded": len(differences), "p_value_two_sided": None,
                                "w_plus": None, "w_minus": None, "statistic": None,
                                "rank_biserial": None, "direction": "all_zero",
                                "note": "No nonzero ranks; no signed-rank test is reported."})
                results.append({"suite": suite, "milestone": milestone, "analytics": analytics,
                                "baseline": baseline, "budget_unit": budget,
                                "difference_definition": "baseline weighted_gap - analytics weighted_gap; positive favors analytics",
                                "analytics_gap_median": median(a), "baseline_gap_median": median(b),
                                "paired": summary, "conditional_signed_rank": conditional,
                                "hypothesis_status": "not assessed: these are simulated profiles, not independent observed organizations"})
    return results


def run_experiments(data, spec):
    for module, represented in data["module_coverage"].items():
        controls = [c for c in data["control_order"] if data["controls"][c]["module"] == module]
        if represented != coverage_of(controls, data["control_coverage"]):
            raise ValueError("Module coverage must be exactly its member controls' mapped coverage")
    if max(spec["profiles"]["preimplemented_module_counts"]) > len(data["module_order"]):
        raise ValueError("Preimplemented count exceeds module taxonomy size")
    by_sector = {s: [] for s in spec["sectors"]}
    for row in data["records"]:
        by_sector[row["sector"]].append(row)
    for s, pool in by_sector.items():
        by_sector[s] = sorted(pool, key=lambda x: (x["incident_id"], x["source_path"]))
        if len(pool) < 2:
            raise ValueError(f"Sector {s} lacks >=2 mapped eligible records")
    pooled = frequencies(data["records"])
    top = sorted(pooled, key=lambda t: (-pooled[t], t))[:25]
    top25 = [{"technique": t, "mean_fractional_credit": pooled[t],
              "max_normalized_weight": pooled[t] / max(pooled.values())} for t in top]
    sector_summaries, splits = {}, {}
    for sector_i, (sector, pool) in enumerate(by_sector.items()):
        f = frequencies(pool)
        ranking, scores = static_order(data["module_order"], data["module_coverage"], f)
        train, test = split_pool(pool, spec["evaluation"]["training_fraction"],
                                 spec["seed"] * 1000000 + sector_i)
        splits[sector] = (train, test)
        sector_summaries[sector] = {"mapped_records": len(pool), "frequencies": f,
                                    "standalone_order": ranking, "standalone_scores": scores,
                                    "train_ids": [r["incident_id"] for r in train],
                                    "test_ids": [r["incident_id"] for r in test],
                                    "split_seed": spec["seed"] * 1000000 + sector_i}
    profiles, rows = [], []
    for sector, pool in by_sector.items():
        for maturity_i, maturity in enumerate(spec["profiles"]["maturity"]):
            for resource in spec["profiles"]["resource"]:
                i = len(profiles)
                profile_id = f"SMB-{i + 1:03d}"
                seed = spec["seed"] * 1000 + i
                initial = data["module_order"][:spec["profiles"]["preimplemented_module_counts"][maturity_i]]
                profile = {"id": profile_id, "sector": sector, "maturity": maturity,
                           "resource": resource, "resource_role": "metadata only", "seed": seed,
                           "preimplemented_modules": initial, "suites": {}}
                train, test = splits[sector]
                for suite, training, evaluation in [("in_sample", pool, None), ("held_out", train, test)]:
                    sampled = Random(seed).choices(training, k=len(training))
                    rank_weights = frequencies(sampled)
                    weights = rank_weights if evaluation is None else frequencies(evaluation)
                    path_rows, ordering = evaluate_paths(data, spec, profile_id, suite, weights,
                                                         rank_weights, initial, top)
                    rows.extend(path_rows)
                    profile["suites"][suite] = {"bootstrap_draws": len(sampled),
                                               "bootstrap_id_counts": dict(sorted(Counter(r["incident_id"] for r in sampled).items())),
                                               "ranking_frequencies": rank_weights, "evaluation_frequencies": weights,
                                               **ordering}
                profiles.append(profile)
    return {"technique_universe": sorted(pooled), "top25": top25,
            "sector_summaries": sector_summaries, "profiles": profiles, "trajectories": rows,
            "comparisons": summarize(rows, spec),
            "interpretation": "Candidate crosswalk coverage of public-disclosure records; not effectiveness, breach probability, labor, or organizational adoption."}
