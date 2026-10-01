# Architecture and maintenance notes

This document describes how the `research/` package fits together. It complements `research/README.md` (methodology and interpretation) and explains the code structure, the determinism rules and the known maintenance caveats. Function names are given instead of line numbers so the guide stays accurate as files change.

## Data flow

```
input-lock.json  ->  fetch_inputs  ->  research-data/   (hash-verified public sources)
                                           |
spec.json, module_taxonomy.json  ->  inputs.load_inputs  ->  data bundle
                                           |
                     pipeline.graph_report (metrics: SCCs, longest path, projection)
                     experiment.run_experiments (frequencies, rankings, profiles, trajectories)
                                           |
                     pipeline.run  ->  manifest.json + result files in a NEW output directory
```

## Modules

| File | Responsibility | Main entry points |
|---|---|---|
| `fetch_inputs.py` | Downloads only the locked public HTTPS URLs and verifies byte length and SHA-256 before publishing each file | `fetch_locked`, `safe_path` |
| `inputs.py` | Verifies the lock, parses the pinned sources and joins them into one data bundle (about 1,100 lines) | `verify_lock`, `load_inputs` |
| `metrics.py` | Pure, dependency-free research primitives: graph and ranking math and the exact statistics | `compute_sccs`, `condensation_longest_path`, `project_edges_to_modules`, `weighted_coverage_gap`, `standalone_ranking`, `marginal_gain_ranking`, `paired_descriptive_diff`, `exact_signed_rank_test` |
| `experiment.py` | The deterministic experiment: per-sector technique frequencies, standalone rankings, train and held-out splits, bootstrap profiles, matched budgets, summaries | `run_experiments`, `evaluate_paths`, `summarize` |
| `pipeline.py` | Command-line runner: loads, computes, writes the manifest and result files, records checksums | `run`, `graph_report`, `main` |

### What `inputs.load_inputs` builds

1. `verify_lock` checks every pinned file (presence, byte length, SHA-256, path safety) and raises `LockVerificationError` on any mismatch.
2. `build_control_catalog` selects the NIST SP 800-53 Rev. 5 Low controls (base and enhancements) from the official OSCAL artifacts and assigns each to a module via `family_to_module_map`.
3. `build_related_edges` projects OSCAL `related` links onto the selected controls (cross-references, not prerequisites).
4. `build_attack_index` and `normalize_and_rollup` index ATT&CK Enterprise techniques and normalize raw identifiers to active parent techniques, quarantining the rest.
5. `build_control_coverage` and `build_module_coverage` compute CTID coverage for exact control IDs (no implicit enhancement inheritance), then union it per module.
6. `build_veris_action_variety_index`, `process_vcdb_records` and `compute_incident_credits` apply the eligibility policy to VCDB records (excluding repeated IDs, missing IDs, nonaccepted statuses and incompatible schema versions) and compute fractional technique credits per incident.

## Determinism rules

These are what make two runs byte-identical. Preserve them when changing code.

- All randomness comes from explicitly seeded `random.Random` instances. Seeds derive from `spec.json`: sector split seed = `seed * 1000000 + sector_index`; profile seed = `seed * 1000 + profile_index`.
- Iteration is over sorted keys or explicitly ordered lists, never over raw set or dict order. A regression test runs under different `PYTHONHASHSEED` values.
- Floating-point sums use `math.fsum`. Non-finite, negative and zero-weight inputs raise errors instead of propagating.
- Output JSON is canonical (sorted keys, no NaN). `run_id` hashes the lock, specification, taxonomy and every `.py` source file; `semantic_output_sha256` hashes the computed evidence. An existing output directory is never overwritten.
- Invariants checked at run time: each module's coverage equals the union of its member controls' coverage; module counts account for every selected control; graph projection accounts for every source edge.

## Tests

`research/tests/` holds unit tests (including brute-force checks of the exact signed-rank statistic, path-escape and checksum failures, malformed archives and ranking regressions) and integration tests that run the loader against the real locked inputs. Integration tests skip when `research-data` is absent. Continuous integration downloads the inputs, fails if any test is skipped, runs the pipeline twice comparing `semantic_output_sha256` and `run_id`, and checks both against the values cited by the praxis.

## Known maintenance caveats

These are recorded openly. None affects the verified results; they affect how safely the code can be changed.

- **Large functions.** `metrics.condensation_longest_path` (about 146 lines, highest branching), `inputs.load_inputs`, `inputs.process_vcdb_records`, `metrics.exact_signed_rank_test`, `inputs.verify_lock` and `metrics.compute_sccs` exceed 90 lines. Refactoring them is worthwhile but changes source hashes and therefore the run ID, so it needs a fresh verification run and should be done on a branch, not on the verified release.
- **Two large modules.** `inputs.py` (about 1,100 lines) could be split into lock verification, catalog and coverage building, and VCDB processing.
- **Sparse docs in two files.** `experiment.py` and `pipeline.py` have few docstrings; the module map above is the reference for them.
- **`assert` in `experiment.split_pool`.** The train and test disjointness check uses `assert`, which Python removes under `-O`. The loader already guarantees unique incident IDs, but an explicit exception would be more robust.
- **No linter or type checker is configured.** Type annotations are present on most functions in `inputs.py` and `metrics.py`. Adding checkers would surface findings in files that are pinned by the verified release, so introduce them on a branch and baseline the findings first.
- **Expected-hash check.** CI asserts that a run reproduces the run ID and semantic output hash cited by the praxis. If a change to `research/` intentionally alters results, update the expected values in `.github/workflows/tests.yml` and `CHANGELOG.md` in the same pull request and explain why.
