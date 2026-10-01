# Public-data research pipeline

This package is a **new implementation and new research run**, not recovered July output or a claim that the earlier demo reproduced the manuscript. It follows the procedural core of manuscript v16 Sections 3.3-3.7 and explicitly resolves omissions in `spec.json`. No old result is an implementation acceptance target.

The existing backend, frontend and frozen exports remain the legacy embedded-input simulator. They are not connected to this package. This change does not deploy an app, replace the manuscript, or automatically accept a hypothesis.

## Run

Python 3.10+ and its standard library only. Tested with Python 3.13.12. No SciPy installation, API keys, remote services or downloaded-script execution is required.

From the repository root:

```sh
python3 -m research.fetch_inputs --dest research-data
python3 -m unittest discover -s research/tests -v
python3 -m research.pipeline --inputs research-data --out research-results/run-001
```

The downloader accepts only the locked public HTTPS URLs and verifies every byte length and SHA256 before publishing a local file. The offline pipeline verifies the locks again before parsing. Existing output directories and mismatching existing inputs are never silently overwritten. To repeat a run, use a new output directory. Compare `semantic_output_sha256` and `run_id` in the two manifests. A source-code change intentionally changes the run ID even if numerical results remain unchanged.

Large raw datasets and generated outputs are not committed. `input-lock.json` records the exact URLs, source commits, versions and hashes needed to retrieve them. Download size is approximately 111 MB (106 MiB). Preserve the upstream notices in `licenses/`.

## What is computed

- Actual NIST Low controls and enhancements from the official selected/resolved OSCAL artifacts, with set-equality and family-partition checks.
- Directed related-control graph, SCCs, condensation paths and audited module-edge projection. SCC size is never called a linear implementation chain. These are cross-references, not validated prerequisites.
- CTID NIST-to-ATT&CK coverage on exact selected control IDs. No implicit enhancement inheritance and no hand-added native mitigation bonus.
- Primary target-industry VCDB file records selected under the frozen eligibility policy. Their candidate technique credits use action variety only, exclude Unknown/Other, normalize active parent techniques before fractional attribution, and take the maximum credit per technique across an incident's paths.
- Full-universe frequency-based standalone module rankings, plus a separately named weighted marginal-gain companion. No KEV/IC3 weights, boosts, effort multipliers or score jitter.
- Thirty-six deterministic bootstrap profiles with structural maturity starting conditions. Resources are metadata only; invented employee observations are not generated.
- Distinct same-module-count and matched-remaining-control-count comparisons, with identical preimplemented controls in the latter. A module count is not a measure of implementation effort.
- In-sample runs and a separate training/held-out companion. Each sector's split uses `seed * 1000000 + sector_index`; each profile uses `seed * 1000 + profile_index`. Splits precede bootstrap. Held-out weighted gaps do not enter ranking.
- Paired descriptive summaries and explicitly conditional signed-rank sign-randomization statistics. All-zero comparisons have no reported signed-rank p-value. Effect direction is baseline gap minus analytics gap: positive favors analytics. Absolute differences tied at binary-float precision use average ranks; near-zero differences within the declared tolerance are excluded.

## Changes from the under-specified manuscript

1. Pins NIST content 5.2.0, ATT&CK 16.1, matching VERIS 1.4.0 mappings and a newly retrieved VCDB snapshot. These are not asserted to be the original July snapshots.
2. Excludes all records in repeated-ID groups rather than arbitrarily retaining one, plus records without IDs, nonaccepted source statuses and incompatible VERIS versions. No reliable SME-only employee threshold can be inferred from these categorical records. The full selection ledger includes exclusions and malformed input.
3. Applies rollup and tactic exclusions **before** the 1/k credit allocation. The manuscript's worked example and its written rule disagree on this ordering.
4. Uses ceiling milestone rounding over remaining units and consistent preimplementation across control comparisons.
5. Disables the unspecified, asymmetric native mitigation supplement. This means several modules have no represented CTID technique coverage, not that they have no real security value.
6. Retains the legacy author-defined module/family taxonomy but corrects its omitted SOC2 identifier CC9.1 in this research-only taxonomy. CIS/SOC2 labels do not establish semantic equivalence or compliance.
7. Adds matched-control and held-out diagnostics. These are new analyses, not claims that the manuscript already performed them.
8. Uses an explicit exact conditional sign-randomization calculation with ties, rather than silently depending on SciPy's version-specific method selection. The bootstrap profiles and repeated held-out pools are not independent observed organizations. No confirmatory population-level test or automatic H1/H2/H3 acceptance is claimed.

These choices were fixed before the new outcome computation, but are not historical preregistration: the earlier hypotheses and reported findings were already known. See `spec.json` for all operational decisions.

## Outputs and interpretation

The run writes input and source-code fingerprints, effective specification, control/module catalogs, normalized record credits, a per-file eligibility ledger, graph results, profiles, trajectory JSON/CSV, comparison summaries and output checksums. Normalized records and credits are adapted data, not a newly observed incident dataset.

A low weighted gap means greater **represented candidate-technique coverage under these crosswalks**, not lower estimated breach probability, demonstrated prevention, labor savings, adoption or organizational effectiveness. VCDB is a disclosure-biased convenience corpus. CTID relationships are broad many-to-many analyst mappings, not validated incident technique observations or effectiveness probabilities. Source schemas and scope were inspected, but this package is not a full OSCAL or historical VERIS schema validator. NIST/CTID control IDs align; semantic revision equivalence is not independently established.

Top25 is pooled across the full eligible corpus and used only as a descriptive companion, including on held-out rows. It is not a strictly out-of-sample metric; the held-out weighted-gap measure is the appropriate held-out diagnostic.

No comparable CIS/SOC2 graph composite, eight-weight cross-framework sensitivity result or independently scored governance rubric is invented here. Those manuscript claims remain evidence-gated. The existing manuscript is not automatically rewritten by this code.

## Tests

The suite covers checksum/path failures, malformed tar records, ID collisions, control joins, active/parent technique normalization, fractional maximum attribution, directed SCC/projection distinctions, brute-force small signed-rank comparisons, deterministic rankings, budget equality, all-zero cases and training/test separation. Integration checks use the locked public bundle when available; absence skips those specific checks rather than claiming they ran. See the current test-run log for the executed count.
