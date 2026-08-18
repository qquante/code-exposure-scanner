from __future__ import annotations

from datetime import datetime, timezone

from secret_hunter import pipeline
from secret_hunter.config import Config
from secret_hunter.discovery import RepositoryMetadata
from secret_hunter.extract import Finding


class _SearchStore:
    def __init__(self) -> None:
        self.jobs: list[dict] = []

    def reserve_rate_slot(self, *_args, **_kwargs) -> float:
        return 0

    def enqueue_job(self, kind, natural_key, payload, **kwargs) -> bool:
        self.jobs.append(
            {"kind": kind, "natural_key": natural_key, "payload": payload, **kwargs}
        )
        return True


class _SearchClient:
    def __init__(self, _cfg, **_kwargs) -> None:
        pass

    def search_code(self, _query: str) -> list[dict]:
        return [
            {
                "repository": {"full_name": "acme/demo"},
                "path": "node_modules/dotenv/README.md",
                "sha": "a" * 40,
            },
            {
                "repository": {"full_name": "acme/demo"},
                "path": "src/wallet.ts",
                "sha": "b" * 40,
            },
        ]

    def close(self) -> None:
        pass


class _MetadataClient:
    def __init__(self, _cfg) -> None:
        pass

    def get_repository(self, repo: str) -> RepositoryMetadata:
        return RepositoryMetadata(
            github_repository_id=123,
            full_name=repo,
            is_public=True,
            language="TypeScript",
            size_kb=20,
            is_fork=False,
            is_archived=False,
            is_disabled=False,
            default_branch="main",
            created_at=datetime.now(timezone.utc).isoformat(),
        )

    def close(self) -> None:
        pass


def test_code_search_skips_dependencies_before_metadata_and_keeps_branch(
    monkeypatch,
) -> None:
    monkeypatch.setattr(pipeline, "GitHubClient", _SearchClient)
    monkeypatch.setattr(pipeline, "GitHubPublicEventsClient", _MetadataClient)
    store = _SearchStore()

    pipeline.handle_job(
        store,  # type: ignore[arg-type]
        Config(),
        {
            "id": 7,
            "kind": "github_search",
            "payload": {"query": "fixture", "type_id": "evm_private_key_env"},
        },
    )

    assert len(store.jobs) == 1
    assert store.jobs[0]["payload"]["path"] == "src/wallet.ts"
    assert store.jobs[0]["payload"]["branch"] == "main"


def test_dependency_blob_is_rejected_before_github_client(monkeypatch) -> None:
    class _ForbiddenClient:
        def __init__(self, *_args, **_kwargs) -> None:
            raise AssertionError("dependency path must not fetch a blob")

    monkeypatch.setattr(pipeline, "GitHubClient", _ForbiddenClient)

    pipeline.handle_job(
        object(),  # type: ignore[arg-type]
        Config(),
        {
            "kind": "fetch_blob",
            "payload": {
                "repo": "acme/demo",
                "path": "backend/node_modules/pkg/README.md",
                "blob_sha": "a" * 40,
            },
        },
    )


def test_persistence_boundary_keeps_only_wallet_allowlist_and_clears_raw() -> None:
    class _Store:
        def __init__(self) -> None:
            self.types: list[str] = []

        def upsert_finding(self, finding, *, run_id=None):
            self.types.append(finding.type_id)
            return len(self.types), True

    def finding(type_id: str, path: str = ".env") -> Finding:
        return Finding(
            type_id=type_id,
            provider="fixture",
            category="crypto",
            risk="critical",
            secret_redacted="fixture",
            secret_raw="sensitive-fixture",
            repo="acme/demo",
            path=path,
        )

    findings = [
        finding("evm_private_key"),
        finding("bitcoin_wif"),
        finding("private_key_pem"),
        finding("solana_seed_hex", "node_modules/pkg/example.js"),
    ]
    store = _Store()

    created = pipeline._persist_findings(  # type: ignore[arg-type]
        store, Config(), findings, run_id=None
    )

    assert created == 1
    assert store.types == ["evm_private_key"]
    assert all(item.secret_raw == "" for item in findings)
