from __future__ import annotations

import hashlib

from secret_hunter import pipeline
import secret_hunter.head_scan as head_scan
from secret_hunter.config import Config
from secret_hunter.extract import Finding
from secret_hunter.head_scan import HeadGitScanner, HeadScanResult


def _finding(category: str = "crypto") -> Finding:
    return Finding(
        type_id="evm_private_key" if category == "crypto" else "aws_access_key",
        provider="EVM" if category == "crypto" else "AWS",
        category=category,
        risk="critical",
        secret_redacted="0x1111…1111",
        secret_raw="0x" + "1" * 64,
        repo="acme/demo",
        path=".env",
        source="head",
    )


def test_head_tree_scan_prioritizes_sensitive_files_and_respects_limits(tmp_path) -> None:
    (tmp_path / "ordinary.txt").write_text("nothing", encoding="utf-8")
    evm_fixture = hashlib.sha256(b"secret-hunter-tcc-evm-fixture-v1").hexdigest()
    (tmp_path / ".env").write_text(
        'EVM_PRIVATE_KEY="0x' + evm_fixture + '"', encoding="utf-8"
    )
    cfg = Config(
        discovery_head_scan_max_files=1,
        discovery_head_scan_max_total_bytes=1024,
    )

    result = HeadGitScanner(cfg).scan_tree(
        tmp_path, repo="acme/demo", commit="abc123"
    )

    assert result.files_scanned == 1
    assert result.truncated is True
    assert any(item.category == "crypto" for item in result.findings)
    assert all(item.commit == "abc123" for item in result.findings)



def test_head_tree_scan_skips_vendored_dependencies(tmp_path) -> None:
    dependency = tmp_path / "backend" / "node_modules" / "dotenv"
    dependency.mkdir(parents=True)
    evm_fixture = hashlib.sha256(b"dependency-fixture-must-not-be-scanned").hexdigest()
    (dependency / "README.md").write_text(
        f"PRIVATE_KEY=0x{evm_fixture}", encoding="utf-8"
    )
    (tmp_path / "app.py").write_text('print("ok")', encoding="utf-8")

    result = HeadGitScanner(Config()).scan_tree(tmp_path, repo="acme/demo")

    assert result.files_scanned == 1
    assert result.findings == ()


def test_head_scan_persists_only_matching_raw_file_as_redis_evidence(
    monkeypatch, tmp_path
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
    monkeypatch.setattr(head_scan, "maybe_evidence_store", lambda _cfg: evidence)
    evm_fixture = hashlib.sha256(b"head-evidence-fixture").hexdigest()
    raw = f"PRIVATE_KEY=0x{evm_fixture}".encode()
    (tmp_path / ".env").write_bytes(raw)
    (tmp_path / "README.md").write_text("clean", encoding="utf-8")

    result = HeadGitScanner(Config(evidence_enabled=True)).scan_tree(
        tmp_path, repo="acme/demo", commit="abc123"
    )

    assert len(result.findings) == 1
    assert evidence.items == [
        (
            "github.head.file",
            raw,
            {
                "repository": "acme/demo",
                "path": ".env",
                "commit": "abc123",
                "finding_types": ["evm_private_key"],
            },
        )
    ]
    assert evidence.closed is True

class _Store:
    def __init__(self) -> None:
        self.enqueued: list[dict] = []

    def enqueue_job(self, kind, natural_key, payload, **kwargs):
        self.enqueued.append(
            {
                "kind": kind,
                "natural_key": natural_key,
                "payload": payload,
                **kwargs,
            }
        )
        return True


class _HeadScanner:
    findings: tuple[Finding, ...] = ()

    def __init__(self, _cfg: Config):
        pass

    def scan_repo(self, _url: str) -> HeadScanResult:
        return HeadScanResult(self.findings, 1, 10, False, "abc")


def _run_head_job(
    monkeypatch, findings: tuple[Finding, ...], *, cfg: Config | None = None
) -> _Store:
    _HeadScanner.findings = findings
    monkeypatch.setattr(pipeline, "HeadGitScanner", _HeadScanner)
    monkeypatch.setattr(pipeline, "_persist_findings", lambda *_args, **_kwargs: 0)
    store = _Store()
    pipeline.handle_job(
        store,  # type: ignore[arg-type]
        cfg or Config(),
        {
            "kind": "scan_history",
            "run_id": 7,
            "payload": {
                "repo": "acme/demo",
                "mode": "head",
                "trufflehog": True,
                "candidate_id": 9,
                "history_natural_key": "candidate-history:v1:event-9",
            },
        },
    )
    return store


def test_head_scan_log_hides_repository_name(monkeypatch, capsys) -> None:
    _run_head_job(monkeypatch, ())

    output = capsys.readouterr().out
    assert "acme/demo" not in output
    assert "repository_ref=" in output


def test_head_scan_queues_history_only_for_crypto_signal(monkeypatch) -> None:
    store = _run_head_job(monkeypatch, (_finding("crypto"),))

    assert len(store.enqueued) == 1
    assert store.enqueued[0]["kind"] == "scan_history"
    assert store.enqueued[0]["payload"]["mode"] == "history"
    assert store.enqueued[0]["priority"] == 5


def test_head_scan_queues_history_even_without_head_signal_when_enabled(
    monkeypatch,
) -> None:
    store = _run_head_job(monkeypatch, ())

    assert len(store.enqueued) == 1
    assert store.enqueued[0]["payload"]["trigger"] == "automatic_eligible"


def test_head_scan_does_not_expand_history_when_disabled(monkeypatch) -> None:
    assert _run_head_job(
        monkeypatch, (), cfg=Config(scan_history=False)
    ).enqueued == []
