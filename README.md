# Code Exposure Scanner

A defensive pipeline for authorized code-secret discovery, sanitized findings and responsible disclosure workflows.

![review](https://img.shields.io/badge/review-private-374151) ![primary](https://img.shields.io/badge/primary-Python-2563EB) [![LinkedIn](https://img.shields.io/badge/LinkedIn-Douglas%20Silva-0A66C2?logo=linkedin&logoColor=white)](https://www.linkedin.com/in/douglas-silva-data-analyst/)

[Overview](#overview) · [Architecture](#architecture) · [Setup](#setup) · [Validation](#validation) · [Roadmap](#roadmap) · [Review notes](docs/REVIEW.md)

## Overview

- Scoped repository discovery and immutable blob retrieval reduce scan ambiguity.
- Pattern and structural detectors produce sanitized findings.
- Queue, recovery and disclosure modules separate detection from notification.

**Technology:** Python · PostgreSQL · Redis Streams · SQLite paths · HTTP API · Docker

**Persistence and data:** PostgreSQL tracks jobs and findings; Redis transports events and may hold sensitive raw evidence in configured modes. Local storage paths are also present.

## Architecture

```text
Authorized repository scope → immutable source/history scan → local detection → sanitized storage → private review/disclosure
```

| Location | Review focus |
| --- | --- |
| [`secret_hunter/scan_policy.py`](secret_hunter/scan_policy.py) | Source/configuration inspected for scope and structure |
| [`secret_hunter/pipeline.py`](secret_hunter/pipeline.py) | Source/configuration inspected for scope and structure |
| [`secret_hunter/disclosure.py`](secret_hunter/disclosure.py) | Source/configuration inspected for scope and structure |
| [`secret_hunter/history_scan.py`](secret_hunter/history_scan.py) | Source/configuration inspected for scope and structure |
| [`compose.yaml`](compose.yaml) | Source/configuration inspected for scope and structure |

Internal package and module names are retained where changing them would affect imports or compatibility. This descriptive repository name does not imply a completed package/API migration.

## Setup

Use pyproject.toml for package installation and config.example.yaml for configuration structure. Do not enable live discovery or notifications to reproduce a unit test.

Start from an isolated environment. Use `.env.example` when present and inspect the configuration loader: an example file is not necessarily loaded automatically. Runtime databases, real account sessions and private credentials are not bundled. Live integration prerequisites are separate from local tests.

## Validation

Static parsing checked 40 Python files and 1 strict JSON files. Python syntax errors: 0; JSON errors: 0. No functional test/build result is claimed for this preparation.

Available test scripts are inventoried in [the review notes](docs/REVIEW.md). Choose offline checks before operating any integration.

These results apply to the selected checks on the preparation copy. They do not establish deployment readiness, full coverage, live provider availability or measured performance. CI definitions, when present under `docs/ci-templates/`, are inactive review templates; no remote CI badge is claimed.

## Limits and current status

Raw secret material is not included in this copy. Detection fixtures intentionally contain obviously invalid key markers. No live repository scan, credential validation or disclosure was executed.

This private snapshot is for code and portfolio review. Generated runtime material and unreviewed binary assets may be excluded. [Review notes](docs/REVIEW.md) record preparation scope, findings and outstanding validation.

## Roadmap

- [ ] Run isolated detector/regression suites.
- [ ] Review queue permissions and raw-evidence retention.
- [ ] Verify disclosure remains private and requires an authorized scope.

## History and attribution

9 existing commits were retained after path/content filtering. Original authors and author/committer dates were retained; commit hashes may change. Upstream commits are not presented as new work by the maintainer.

No open-source license is granted by this preparation. A license and attribution review is required before public redistribution.

## Maintainer and feedback

Douglas de Oliveira Silva · [GitHub](https://github.com/qquante) · [LinkedIn](https://www.linkedin.com/in/douglas-silva-data-analyst/)

For this private review, report reproducible issues with a minimal fixture and the exact check output. Keep account data, credentials and generated sensitive reports out of issues and commits. Existing contribution guidelines apply where present.

**Topics:** `python`, `secret-scanning`, `defensive-security`, `postgresql`, `redis`, `static-analysis`
