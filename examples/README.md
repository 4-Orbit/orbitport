# Orbitport examples

Runnable examples for the Orbitport APIs, one folder per feature.

| Folder | Feature |
| --- | --- |
| [kms](kms/) | Key management: encryption, signing, data keys, key-store and rotation, grouped by role |
| [github-issues](github-issues/) | Local operator console, Cedar-gated issue workflow, server-side GitHub App adapter, and credential/policy/audit integration seams |

The KMS examples read the same configuration. Copy `.env.example` to `.env` (gitignored) and set `ORBITPORT_PAT` to a token from the [dashboard](https://accounts.spacecomputer.io). The GitHub issue demo runs independently with Node and uses mock credentials by default; see its README.

> **Disclaimer:** keeping a token in a `.env` file is not a best practice. It is used here only to make the examples easy to try, and it is meant for testing and non-production code only. In production, inject the token from a secret manager or your CI's secret store, and never commit it.
