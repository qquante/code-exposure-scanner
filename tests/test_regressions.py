from __future__ import annotations

import base64
import json
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import secret_hunter.history_scan as history_scan


from secret_hunter import pipeline
from secret_hunter.config import Config
from secret_hunter.discovery import RepositoryMetadata
from secret_hunter.disclosure import GitHubDisclosureClient
from secret_hunter.extract import Finding, dedupe, extract_from_text
from secret_hunter.history_scan import NativeGitScanner, _trufflehog_to_finding
from secret_hunter.github_search import GitHubClient
from secret_hunter.pipeline import schedule_search
from secret_hunter.report import build_issue_body
from secret_hunter.validate import (
    _btc_address_from_wif,
    _solana_pubkey_from_keypair,
    b58encode,
    validate_evm,
)


def test_search_and_notification_tokens_are_loaded_and_used_separately(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    search_file = tmp_path / "search-token"
    notify_file = tmp_path / "notify-token"
    search_file.write_text("search-only-fixture", encoding="utf-8")
    notify_file.write_text("notify-only-fixture", encoding="utf-8")
    monkeypatch.setenv("GITHUB_SEARCH_TOKEN_FILE", str(search_file))
    monkeypatch.setenv("GITHUB_NOTIFY_TOKEN_FILE", str(notify_file))

    cfg = Config.from_env(tmp_path / "missing-config.yaml")
    search_client = GitHubClient(cfg)
    notify_client = GitHubDisclosureClient(cfg)
    try:
        assert cfg.github_token == "search-only-fixture"
        assert cfg.github_notify_token == "notify-only-fixture"
        assert search_client.session.headers["Authorization"] == "Bearer search-only-fixture"
        assert notify_client.session.headers["Authorization"] == "Bearer notify-only-fixture"
    finally:
        search_client.close()
        notify_client.close()



def test_discovery_auto_queue_flag_is_loaded_from_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SH_DISCOVERY_AUTO_QUEUE_SCANS", "true")
    monkeypatch.setenv("SH_DISCOVERY_REPOSITORIES_PER_POLL", "12")
    monkeypatch.setenv("SH_DISCOVERY_WINDOWS_PER_POLL", "6")
    monkeypatch.setenv("SH_DISCOVERY_SEARCH_REQUESTS_PER_MINUTE", "20")
    monkeypatch.setenv("SH_DISCOVERY_HEAD_SCAN_SAMPLE_PERCENT", "100")
    monkeypatch.setenv("SH_DISCOVERY_LIVE_MAX_AGE_MINUTES", "17")
    monkeypatch.setenv("SH_EVENT_BUS_ENABLED", "true")
    monkeypatch.setenv("SH_EVENT_BUS_PREFIX", "test-pipeline")
    monkeypatch.setenv("SH_EVENT_BUS_DISPATCH_BATCH", "321")
    monkeypatch.setenv("SH_EVENT_BUS_DISPATCH_INTERVAL_MS", "125")

    cfg = Config.from_env(tmp_path / "missing-config.yaml")

    assert cfg.discovery_auto_queue_scans is True
    assert cfg.discovery_repositories_per_poll == 12
    assert cfg.discovery_windows_per_poll == 6
    assert cfg.discovery_search_requests_per_minute == 20
    assert cfg.discovery_head_scan_sample_percent == 100
    assert cfg.discovery_live_max_age_minutes == 17
    assert cfg.event_bus_enabled is True
    assert cfg.event_bus_prefix == "test-pipeline"
    assert cfg.event_bus_dispatch_batch == 321
    assert cfg.event_bus_dispatch_interval_ms == 125


def test_detector_toggles_are_loaded_from_yaml(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("SH_AI_DETECTION_ENABLED", raising=False)
    monkeypatch.delenv("SH_PRIVATE_KEY_DETECTION_ENABLED", raising=False)
    monkeypatch.delenv("SH_SCAN_HISTORY", raising=False)
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "ai_detection_enabled: false\n"
        "private_key_detection_enabled: true\n"
        "scan_history: true\n",
        encoding="utf-8",
    )

    cfg = Config.from_env(config_path)

    assert cfg.ai_detection_enabled is False
    assert cfg.private_key_detection_enabled is True
    assert cfg.scan_history is True


def _commit(repo: Path, message: str) -> None:
    subprocess.run(["git", "add", "."], cwd=repo, check=True, capture_output=True)
    subprocess.run(
        ["git", "commit", "-qm", message], cwd=repo, check=True, capture_output=True
    )


def test_native_history_finds_a_secret_removed_later(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(
        ["git", "config", "user.email", "fixture@example.invalid"],
        cwd=repo,
        check=True,
    )
    subprocess.run(["git", "config", "user.name", "Fixture"], cwd=repo, check=True)

    target = repo / "config.py"
    target.write_text('TOKEN="sk_live_' + "A" * 24 + '"\n', encoding="utf-8")
    _commit(repo, "add synthetic credential")
    target.write_text("# removed\n", encoding="utf-8")
    _commit(repo, "remove synthetic credential")

    cfg = Config(
        output_dir=tmp_path / "out",
        db_path=tmp_path / "out" / "findings.db",
        salt_path=tmp_path / "out" / ".salt",
    )
    findings = NativeGitScanner(cfg).scan_local(repo, repo="acme/demo")

    assert any(item.type_id == "stripe_live" for item in findings)
    assert all(item.commit for item in findings)


def test_native_history_skips_dependency_paths(tmp_path: Path) -> None:
    repo = tmp_path / "repo-dependency"
    target = repo / "backend" / "node_modules" / "wallet" / "README.md"
    target.parent.mkdir(parents=True)
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(
        ["git", "config", "user.email", "fixture@example.invalid"],
        cwd=repo,
        check=True,
    )
    subprocess.run(["git", "config", "user.name", "Fixture"], cwd=repo, check=True)
    target.write_text(
        'PRIVATE_KEY="0x' + "1234567890abcdef" * 4 + '"\n', encoding="utf-8"
    )
    _commit(repo, "vendored dependency fixture")

    findings = NativeGitScanner(Config()).scan_local(repo, repo="acme/demo")

    assert not any(item.path.startswith("backend/node_modules/") for item in findings)

def test_dedupe_does_not_merge_redaction_collisions() -> None:
    findings = [
        Finding(
            "synthetic",
            "Fixture",
            "generic",
            "high",
            "ABCD…WXYZ",
            secret_raw="ABCD111111WXYZ",
        ),
        Finding(
            "synthetic",
            "Fixture",
            "generic",
            "high",
            "ABCD…WXYZ",
            secret_raw="ABCD222222WXYZ",
        ),
    ]

    assert len(dedupe(findings)) == 2


def test_trufflehog_git_metadata_contract() -> None:
    finding = _trufflehog_to_finding(
        {
            "DetectorName": "AWS",
            "Raw": "AKIA" + "A" * 16,
            "Verified": False,
            "SourceMetadata": {
                "Data": {
                    "Git": {
                        "repository": "https://github.com/acme/demo",
                        "file": "old.env",
                        "commit": "abc123",
                        "line": 7,
                    }
                }
            },
        }
    )

    assert finding.repo == "acme/demo"
    assert finding.path == "old.env"
    assert finding.commit == "abc123"
    assert finding.line == 7


def test_trufflehog_persists_only_accepted_raw_record_as_redis_evidence(
    monkeypatch,
) -> None:
    class _Evidence:
        def __init__(self) -> None:
            self.items: list[tuple[str, bytes, dict]] = []
            self.closed = False

        def append_bytes(self, source, payload, *, metadata=None):
            self.items.append((source, payload, dict(metadata or {})))
            return "1-0"

        def close(self):
            self.closed = True

    evidence = _Evidence()
    private_key = "0x" + "1234567890abcdef" * 4
    accepted = json.dumps(
        {
            "DetectorName": "evm_private_key",
            "Raw": f"PRIVATE_KEY={private_key}",
            "Verified": False,
            "SourceMetadata": {
                "Data": {
                    "Git": {
                        "repository": "https://github.com/acme/demo",
                        "file": ".env",
                        "commit": "abc123",
                        "line": 1,
                    }
                }
            },
        },
        separators=(",", ":"),
    )
    rejected = json.dumps(
        {
            "DetectorName": "evm_private_key",
            "Raw": f"PRIVATE_KEY={private_key}",
            "SourceMetadata": {
                "Data": {"Git": {"file": "node_modules/pkg/test.js"}}
            },
        }
    )
    monkeypatch.setattr(history_scan, "maybe_evidence_store", lambda _cfg: evidence)
    monkeypatch.setattr(
        history_scan.subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess(
            args=[], returncode=0, stdout=f"{accepted}\n{rejected}\n", stderr=""
        ),
    )

    findings = history_scan.trufflehog_scan(
        "https://github.com/acme/demo",
        Config(evidence_enabled=True, private_key_detection_enabled=True),
    )
    assert len(findings) == 1
    assert evidence.items[0][0] == "github.history.trufflehog"
    assert evidence.items[0][1] == accepted.encode()
    assert evidence.items[0][2]["repository"] == "acme/demo"
    assert evidence.items[0][2]["path"] == ".env"
    assert evidence.closed is True



def test_pem_fingerprint_material_includes_the_block() -> None:
    first = "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----"
    second = "-----BEGIN PRIVATE KEY-----\nBBBB\n-----END PRIVATE KEY-----"

    first_match = next(
        item for item in extract_from_text(first) if item.type_id == "private_key_pem"
    )
    second_match = next(
        item for item in extract_from_text(second) if item.type_id == "private_key_pem"
    )

    assert first_match.secret_raw == first
    assert second_match.secret_raw == second
    assert first_match.secret_raw != second_match.secret_raw


@pytest.mark.parametrize(
    "label",
    (
        "PRIVATE_KEY",
        "ETH_PK",
        "BASE_PK",
        "BSC_PK",
        "ROBINHOOD_PK",
        "DEPLOYER_PK",
        "RELAYER_KEY",
    ),
)
def test_evm_private_key_is_chain_agnostic_but_requires_context(label: str) -> None:
    value = "0x" + "1234567890abcdef" * 4

    transaction = extract_from_text(f"tx_hash = '{value}'")
    credential = extract_from_text(f"{label} = '{value}'")

    assert not any(item.type_id == "evm_private_key" for item in transaction)
    assert any(item.type_id == "evm_private_key" for item in credential)


def test_evm_private_key_covers_common_wallet_constructors() -> None:
    value = "0x" + "1234567890abcdef" * 4

    assert any(
        item.type_id == "evm_private_key"
        for item in extract_from_text(f"const wallet = new ethers.Wallet('{value}')")
    )
    assert any(
        item.type_id == "evm_private_key"
        for item in extract_from_text(f"Account.from_key('{value[2:]}')")
    )


def test_evm_short_pk_alias_requires_real_env_path() -> None:
    value = "0x" + "1234567890abcdef" * 4

    assert any(
        item.type_id == "evm_private_key"
        for item in extract_from_text(f"PK={value}", path=".env")
    )
    assert not any(
        item.type_id == "evm_private_key"
        for item in extract_from_text(f"PK={value}", path=".env.example")
    )
    assert not any(
        item.type_id == "evm_private_key"
        for item in extract_from_text(f"PK={value}", path="README.md")
    )

def test_evm_validation_never_calls_rpc(monkeypatch: pytest.MonkeyPatch) -> None:
    value = "0x" + "1234567890abcdef" * 4
    finding = next(
        item for item in extract_from_text(f"PRIVATE_KEY='{value}'")
        if item.type_id == "evm_private_key"
    )

    def forbidden(*_args, **_kwargs):
        raise AssertionError("validação EVM não pode consultar rede")

    monkeypatch.setattr("requests.post", forbidden)
    validate_evm(finding, Config(validate_crypto=True))

    assert finding.validate_status == "format_valid"
    assert "localmente" in finding.validate_detail or "biblioteca local" in finding.validate_detail


def test_dedupe_prefers_specific_detector_but_keeps_distinct_locations() -> None:
    secret = "sk_live_" + "Q" * 24
    findings = extract_from_text(f'TOKEN="{secret}"\nTOKEN="{secret}"')

    unique = dedupe(findings)

    assert [item.type_id for item in unique] == ["stripe_live", "stripe_live"]
    assert [item.line for item in unique] == [1, 2]


def test_mnemonic_requires_context_wordlist_and_checksum() -> None:
    valid = " ".join(["abandon"] * 11 + ["about"])
    invalid = "alpha bravo charlie delta echo foxtrot golf hotel india juliet kilo lima"

    assert not any(item.type_id == "bip39_mnemonic" for item in extract_from_text(valid))
    assert not any(
        item.type_id == "bip39_mnemonic"
        for item in extract_from_text(f'MNEMONIC="{invalid}"')
    )
    assert any(
        item.type_id == "bip39_mnemonic"
        for item in extract_from_text(f'MNEMONIC="{valid}"')
    )


def test_database_uri_requires_embedded_password() -> None:
    public = extract_from_text("postgresql://database.example.invalid/app")
    credential = extract_from_text(
        "postgresql://app:strong-password@database.example.invalid/app"
    )

    assert not any(item.type_id == "postgres_uri" for item in public)
    assert any(item.type_id == "postgres_uri" for item in credential)


_SOLANA_KEYPAIR = bytes([1] * 32) + bytes.fromhex(
    "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c"
)
_SOLANA_KEYPAIR_BASE58 = b58encode(_SOLANA_KEYPAIR)


def test_solana_array_requires_context_or_sensitive_filename() -> None:
    array = json.dumps(list(_SOLANA_KEYPAIR))

    assert not any(item.type_id == "solana_keypair_json" for item in extract_from_text(array))
    assert any(
        item.type_id == "solana_keypair_json"
        for item in extract_from_text(array, path="id.json")
    )
    assert any(
        item.type_id == "solana_keypair_json"
        for item in extract_from_text(f"Keypair.fromSecretKey(Uint8Array.from({array}))")
    )


@pytest.mark.parametrize(
    ("type_id", "value"),
    (
        ("solana_keypair_base58", _SOLANA_KEYPAIR_BASE58),
        ("solana_keypair_base64", base64.b64encode(_SOLANA_KEYPAIR).decode("ascii")),
        ("solana_keypair_hex", _SOLANA_KEYPAIR.hex()),
    ),
)
def test_solana_keypair_encoded_formats(type_id: str, value: str) -> None:
    findings = extract_from_text(f'SOLANA_PRIVATE_KEY="{value}"')

    assert any(item.type_id == type_id for item in findings)


def test_solana_seed_formats_require_explicit_seed_context() -> None:
    seed = bytes(range(1, 33))
    variants = (
        ("solana_seed_array", json.dumps(list(seed))),
        ("solana_seed_base58", b58encode(seed)),
        ("solana_seed_base64", base64.b64encode(seed).decode("ascii")),
        ("solana_seed_hex", seed.hex()),
    )

    for type_id, value in variants:
        findings = extract_from_text(f'Keypair.fromSeed("{value}")')
        if type_id == "solana_seed_array":
            findings = extract_from_text(f"Keypair.fromSeed(Uint8Array.from({value}))")
        assert any(item.type_id == type_id for item in findings)
        if type_id == "solana_seed_hex":
            assert not any(item.type_id == "evm_private_key" for item in findings)

    public_key = b58encode(seed)
    assert not any(
        item.type_id.startswith("solana_seed")
        for item in extract_from_text(f'PUBLIC_KEY="{public_key}"')
    )


def test_cargo_lock_solana_package_checksums_are_not_seeds() -> None:
    cargo_lock = '''
[[package]]
name = "solana-seed-derivable"
version = "3.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "ff7bdb72758e3bec33ed0e2658a920f1f35dfb9ed576b951d20d63cb61ecd95c"
dependencies = [
 "solana-derivation-path",
]

[[package]]
name = "solana-seed-phrase"
version = "3.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "dc905b200a95f2ea9146e43f2a7181e3aeb55de6bc12afb36462d00a3c7310de"
'''

    assert extract_from_text(cargo_lock, path="Cargo.lock") == []
    assert extract_from_text(cargo_lock, path="crates/wallet/CARGO.LOCK") == []


def test_evm_keystore_v3_is_separate_from_plaintext_private_key() -> None:
    payload = json.dumps(
        {
            "version": 3,
            "address": "00" * 20,
            "crypto": {
                "cipher": "aes-128-ctr",
                "ciphertext": "ab" * 32,
                "kdf": "scrypt",
                "mac": "cd" * 32,
            },
        }
    )

    findings = extract_from_text(payload, path="keystore/wallet.json")

    assert any(item.type_id == "evm_keystore_v3" for item in findings)
    assert not any(item.type_id == "evm_private_key" for item in findings)


def test_public_issue_contains_no_secret_locator() -> None:
    finding = {
        "repo": "acme/demo",
        "provider": "Stripe",
        "type_id": "stripe_live",
        "risk": "critical",
        "category": "payment",
        "path": ".env",
        "commit_sha": "abcdef123456",
        "secret_hint": "sk_live_…",
        "validation_status": "not_checked",
    }

    body = build_issue_body([finding], visibility="public")

    assert ".env" not in body
    assert "abcdef1234" not in body
    assert "sk_live_" not in body
    assert "canal privado" in body.lower()


def test_search_requires_a_strict_repository_org_or_user_scope() -> None:
    class NoopStore:
        def create_run(self, *_args):
            raise AssertionError("escopo inválido não pode criar run")

    for scope in ("", "language:python", "org:acme language:python", "repo:broken"):
        cfg = Config(search_scope=scope, allow_global_search=False)
        try:
            schedule_search(NoopStore(), cfg)  # type: ignore[arg-type]
        except ValueError:
            pass
        else:
            raise AssertionError(f"escopo deveria ser rejeitado: {scope!r}")


def test_search_scheduler_filters_configured_crypto_types() -> None:
    class Store:
        def __init__(self):
            self.jobs: list[dict] = []

        def create_run(self, *_args):
            return 7

        def enqueue_job(self, _kind, _key, payload, **_kwargs):
            self.jobs.append(payload)
            return True

        def complete_empty_run(self, _run_id):
            raise AssertionError("a rodada deve criar jobs")

    store = Store()
    cfg = Config(
        allow_global_search=True,
        private_key_detection_enabled=True,
        search_types=("evm_private_key_to_account", "solana_from_secret_key"),
    )

    run_id, created = schedule_search(store, cfg)  # type: ignore[arg-type]

    assert run_id == 7
    assert created == 2
    assert [job["type_id"] for job in store.jobs] == [
        "evm_private_key_to_account",
        "solana_from_secret_key",
    ]
    assert all("pushed:" not in job["query"] for job in store.jobs)


def test_code_search_downloads_only_repositories_created_within_limit(monkeypatch) -> None:
    recent = datetime.now(timezone.utc) - timedelta(hours=2)
    old = datetime.now(timezone.utc) - timedelta(hours=49)

    class SearchClient:
        def __init__(self, _cfg, **_kwargs):
            pass

        def search_code(self, _query):
            return [
                {
                    "repository": {"full_name": "acme/recent"},
                    "path": "wallet.ts",
                    "sha": "1" * 40,
                },
                {
                    "repository": {"full_name": "acme/old"},
                    "path": "wallet.ts",
                    "sha": "2" * 40,
                },
            ]

        def close(self):
            pass

    class MetadataClient:
        def __init__(self, _cfg):
            pass

        def get_repository(self, repository):
            created_at = recent if repository == "acme/recent" else old
            repository_id = 100 if repository == "acme/recent" else 200
            return RepositoryMetadata(
                github_repository_id=repository_id,
                full_name=repository,
                is_public=True,
                language="TypeScript",
                size_kb=10,
                is_fork=False,
                is_archived=False,
                is_disabled=False,
                default_branch="main",
                created_at=created_at.isoformat(),
            )

        def close(self):
            pass

    class Store:
        def __init__(self):
            self.buckets: list[str] = []
            self.jobs: list[dict] = []

        def reserve_rate_slot(self, bucket, *_args):
            self.buckets.append(bucket)
            return 0

        def enqueue_job(self, kind, _key, payload, **_kwargs):
            self.jobs.append({"kind": kind, **payload})
            return True

    monkeypatch.setattr(pipeline, "GitHubClient", SearchClient)
    monkeypatch.setattr(pipeline, "GitHubPublicEventsClient", MetadataClient)
    store = Store()

    pipeline.handle_job(
        store,  # type: ignore[arg-type]
        Config(discovery_max_event_age_hours=48),
        {
            "kind": "github_search",
            "run_id": 7,
            "payload": {"type_id": "openai_proj", "query": "fixture"},
        },
    )

    assert [job["repo"] for job in store.jobs] == ["acme/recent"]
    assert store.jobs[0]["kind"] == "fetch_blob"
    assert store.jobs[0]["repository_created_at"] == recent.isoformat()
    assert store.buckets.count("github-core-code-search-metadata") == 2


def test_disabled_private_key_search_job_is_ignored(monkeypatch) -> None:
    class SearchClient:
        def __init__(self, *_args, **_kwargs):
            raise AssertionError("GitHub não deve ser chamado para detector desligado")

    monkeypatch.setattr(pipeline, "GitHubClient", SearchClient)

    pipeline.handle_job(
        object(),  # type: ignore[arg-type]
        Config(private_key_detection_enabled=False),
        {
            "kind": "github_search",
            "payload": {"type_id": "evm_private_key_env", "query": "fixture"},
        },
    )


def test_bitcoin_compressed_wif_serializes_the_public_key_correctly() -> None:
    pytest.importorskip("ecdsa")
    address = _btc_address_from_wif(
        "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"
    )
    assert address == "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"


def test_solana_public_key_is_base58_and_keypair_is_consistent() -> None:
    signing = pytest.importorskip("nacl.signing").SigningKey(bytes(32))
    public = signing.verify_key.encode()
    keypair = bytes(32) + public

    encoded = _solana_pubkey_from_keypair(keypair)

    assert encoded == b58encode(public)
    assert encoded is not None and all(char in "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz" for char in encoded)
    assert _solana_pubkey_from_keypair(keypair[:-1] + b"\x00") is None


def test_distributed_rate_hook_runs_for_every_search_page() -> None:
    class Response:
        status_code = 200
        text = ""
        headers: dict[str, str] = {}

        def __init__(self, page: int):
            self.page = page

        def json(self):
            return {"total_count": 31, "items": [{"page": self.page}]}

    class Session:
        headers: dict[str, str] = {}

        def __init__(self):
            self.urls: list[str] = []

        def request(self, _method, url, **_kwargs):
            self.urls.append(url)
            page = 2 if "page=2" in url else 1
            return Response(page)

        def close(self):
            pass

    reservations: list[int] = []
    client = GitHubClient(Config(search_max_pages=2), before_search_request=lambda: reservations.append(1))
    client.session = Session()  # type: ignore[assignment]

    items = client.search_code('"fixture"', per_page=30)

    assert [item["page"] for item in items] == [1, 2]
    assert len(reservations) == 2
    assert all("sort=indexed&order=desc" in url for url in client.session.urls)
