# Security policy

## What is maintained
This repository is a research artifact that supports a doctoral praxis. The maintained code is the
`research/` package: a version-pinned public-data pipeline, its tests and its verification notes. It uses
only the Python standard library and has no third-party runtime dependencies.

## Reporting a vulnerability
Please report security issues privately through GitHub (Security tab, "Report a vulnerability") rather
than opening a public issue. If that option is not available, contact the maintainer through the
GitHub profile. Reports are reviewed on a best-effort basis.

Please include the affected file or commit, steps to reproduce, and the impact you observed.

## Automated scanning
- Trivy scans pushes and pull requests to `main`, weekly, and on demand, through the shared
  MARFI-Systems reusable workflow pinned to a commit SHA. If it finds a Critical or High issue it opens
  an issue titled "Trivy Security Findings", and closes it when a later scan is clean.
- GitHub secret scanning with push protection and CodeQL code scanning are enabled.
- The test workflow runs on Python 3.10 and 3.13, and checks that a run reproduces the run ID and output
  hash cited by the praxis.
- Dependabot keeps the SHA-pinned GitHub Actions current.
