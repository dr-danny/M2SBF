# Contributing

This repository is a research artifact supporting a doctoral praxis. Issues and pull requests are welcome and reviewed on a best-effort basis.

## Ground rules

- **The verified release is fixed.** The praxis cites the `v1.0.0` release, the Git tree hash of `research/`, and a run ID and output hash. Do not move or delete the `v1.0.0` tag or rewrite the history of `main`.
- **Changing any `.py` file under `research/` changes the run ID** (source hashes are part of it). Propose such changes on a new branch with a clear explanation of the effect on results, re-run the verification before relying on them, and update the expected run ID and output hash in `.github/workflows/tests.yml` only if the change is intentional.
- **No secrets, no third-party standard text.** Do not commit credentials, or text from copyrighted standards (for example CIS Controls or the AICPA Trust Services Criteria). Identifiers are fine.
- **Security issues** go through the private channel described in [`SECURITY.md`](SECURITY.md), not public issues.

## Running the checks locally

Python 3.10 or newer; standard library only.

```sh
python3 -m compileall -q research
python3 -m research.fetch_inputs --dest research-data
python3 -m unittest discover -s research/tests -v
```

The integration tests use `research-data` (or the directory named by the `M2SBF_INPUT_ROOT` environment variable). Without it they are skipped; CI fails if any test is skipped, so run them with the data present before opening a pull request.

## Pull requests

- Keep changes focused, and explain what changed and why.
- Continuous integration must pass: tests on Python 3.10 and 3.13, the two-run determinism check and the Trivy scan.
- By contributing you agree that your contribution is licensed under the Apache License 2.0 (see [`LICENSE`](LICENSE)).
