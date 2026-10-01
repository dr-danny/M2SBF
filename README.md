# M2SBF

Reproducible, version-pinned public-data research implementation that supports the doctoral praxis "Modern Modular Secure Business Framework (M2SBF): An Analytics-Assisted Governance Architecture for Small and Mid-Sized Businesses" by Daniel Mehditash.

The package loads hash-locked public sources (NIST SP 800-53 OSCAL, CTID mappings, MITRE ATT&CK, VCDB), builds a control and technique-coverage model, and runs a deterministic module-prioritization experiment. Its outputs are new computed evidence, not reconstructed historical results. Python standard library only; no third-party dependencies.

## Quick start

Requires Python 3.10 or newer (CI runs 3.10 and 3.13). From the repository root:

```sh
python3 -m research.fetch_inputs --dest research-data      # about 111 MB, every file hash-verified
python3 -m unittest discover -s research/tests -v          # full suite, uses the downloaded inputs
python3 -m research.pipeline --inputs research-data --out research-results/run-001
```

A run writes a manifest with a `run_id` and a `semantic_output_sha256`. Repeat the run into a new directory and compare them to confirm determinism. Existing output directories are never overwritten.

The verified run cited by the praxis has:

- `run_id` `eb2060dd7639f478a2a1ab479c3774c545094b4235d5af987ee9c2e6f9e3b0be`
- `semantic_output_sha256` `50e6af0f863a640255b1122fd9da9af53bf2cd60580b9497f82a80f05f1a57bc`

Continuous integration checks that a fresh run reproduces both values.

## Repository layout

| Path | Contents |
|---|---|
| `research/` | The research package, its tests, the locked input list (`input-lock.json`), the specification (`spec.json`), the module taxonomy and upstream license texts |
| `docs/ARCHITECTURE.md` | Module map, data flow, determinism rules and maintenance notes |
| `.github/workflows/` | `tests.yml` (tests, reproducibility check) and `trivy-security.yml` (security scan) |
| `CITATION.cff`, `LICENSE`, `NOTICE`, `SECURITY.md`, `CONTRIBUTING.md`, `CHANGELOG.md` | Project metadata and policies |

See [`research/README.md`](research/README.md) for the methodology decisions and what each output does and does not mean.

## Provenance

This repository is a clean public snapshot of the research package that supports the praxis. The complete development history, including earlier revisions of the package and an earlier demonstration prototype that is not part of this repository, is retained in a private provenance repository and is available to examiners on request.

The `research/` directory here is byte-identical to the revision that produced the verified run cited by the praxis. Its Git tree hash is `bf88a47b5a65b91b04a8003c7c526ee72cc3a24e`, the same as `research/` at provenance commit `67b657a187848ebd5263177a18c87808e49a523b`. The release tag `v1.0.0` marks this snapshot. See [`CHANGELOG.md`](CHANGELOG.md) for how the provenance revisions map to this release.

## Tests and continuous integration

Every push and pull request to `main` runs the full suite on Python 3.10 and 3.13 against the downloaded, hash-verified inputs, fails if any test is skipped, runs the pipeline twice to confirm identical output, and checks that the run reproduces the run ID and output hash cited by the praxis. The same checks run weekly to confirm the upstream files are unchanged. A separate workflow scans dependencies and configuration with Trivy.

## License

Apache License 2.0, copyright 2026 Daniel Mehditash. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE) for scope. Third-party data keeps its upstream license (see [`research/NOTICE.md`](research/NOTICE.md)).

## Citing and security

Citation metadata is in [`CITATION.cff`](CITATION.cff). To report a vulnerability, see [`SECURITY.md`](SECURITY.md).
