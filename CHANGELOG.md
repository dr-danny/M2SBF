# Changelog

Notable changes to this repository, newest first.

## v1.0.0 - 2026-10-01

First public release: a clean snapshot of the research package that supports the praxis, with its documentation, tests and continuous integration.

- `research/` is byte-identical to the revision that produced the verified run cited by the praxis (Git tree hash `bf88a47b5a65b91b04a8003c7c526ee72cc3a24e`, provenance commit `67b657a187848ebd5263177a18c87808e49a523b`).
- A fresh run reproduces `run_id` `eb2060dd7639f478a2a1ab479c3774c545094b4235d5af987ee9c2e6f9e3b0be` and `semantic_output_sha256` `50e6af0f863a640255b1122fd9da9af53bf2cd60580b9497f82a80f05f1a57bc`; continuous integration asserts both.
- Archived on Zenodo with a DOI: [10.5281/zenodo.23076620](https://doi.org/10.5281/zenodo.23076620).
- Apache License 2.0 with a `NOTICE` defining its scope; `SECURITY.md`, `CITATION.cff`, `CONTRIBUTING.md` and `docs/ARCHITECTURE.md`.
- Test workflow on Python 3.10 and 3.13 (full suite, no skipped tests, two-run determinism check, praxis-cited hash assertion), Trivy security scan, and Dependabot updates for GitHub Actions.

## Development history before this release

The package was developed in a private provenance repository, available to examiners on request. Its relevant revisions, by date:

- 2026-09-28 `1b9bf3b`: added a test showing that a standalone ranking can lose to a union. Not included here: the run ID hashes the test files, so adding it would change the run ID cited by the praxis.
- 2026-09-26 `67b657a`: added regression tests requiring exact equality with the independently extracted full 56-item CIS IG1 list. This is the producing revision and is included.
- 2026-09-26 `5f30ef3`: corrected the CIS Controls v8 IG1 scope in the research taxonomy (removed out-of-scope safeguard 16.1 from Configuration Management, added missing IG1 safeguard 14.8 to Security Awareness and Training) and recorded the official source URL, edition, workbook SHA-256 and cell references. Included.
- 2026-09-09 `2094d0a`: initial reproducible public-data research package (loader, graph metrics, experiment, pipeline and tests). Included, as modified by the two later revisions.
