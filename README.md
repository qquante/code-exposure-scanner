# Code Exposure Scanner

A defensive pipeline for authorized code-secret discovery, sanitized findings and responsible disclosure workflows.

## Features

- Scoped repository discovery and immutable blob retrieval reduce scan ambiguity.
- Pattern and structural detectors produce sanitized findings.
- Queue, recovery and disclosure modules separate detection from notification.

## Stack

Python · PostgreSQL · Redis Streams · SQLite paths · HTTP API · Docker

PostgreSQL tracks jobs and findings; Redis transports events and may hold sensitive raw evidence in configured modes. Local storage paths are also present.

## Getting started

Use pyproject.toml for package installation and config.example.yaml for configuration structure. Do not enable live discovery or notifications to reproduce a unit test.

## How it works

```text
Authorized repository scope → immutable source/history scan → local detection → sanitized storage → private review/disclosure
```

## Current limitations

Raw secret material is not included in this copy. Detection fixtures intentionally contain obviously invalid key markers. No live repository scan, credential validation or disclosure was executed.

## License

No open-source license has been granted. Redistribution terms remain to be defined.
