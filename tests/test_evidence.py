from __future__ import annotations

import hashlib
import json

from secret_hunter.config import Config
from secret_hunter.evidence import REDACTED, RedisEvidenceStore


class FakeRedis:
    def __init__(self):
        self.calls: list[tuple[str, dict]] = []
        self.closed = False

    def xadd(self, stream: str, fields: dict) -> bytes:
        self.calls.append((stream, fields))
        return b"1-0"

    def close(self) -> None:
        self.closed = True


class FakeResponse:
    status_code = 200
    content = b'{"items":[{"sample":"raw"}]}'
    headers = {"Content-Type": "application/json", "Set-Cookie": "private"}


def test_append_preserves_raw_payload_without_trimming() -> None:
    client = FakeRedis()
    store = RedisEvidenceStore(client, "secret-hunter:raw-evidence")
    payload = b"raw\x00payload"

    entry_id = store.append_bytes("fixture", payload, metadata={"page": 1})

    assert entry_id == "1-0"
    stream, fields = client.calls[0]
    assert stream == "secret-hunter:raw-evidence"
    assert fields["payload"] == payload
    assert fields["payload_sha256"] == hashlib.sha256(payload).hexdigest()
    assert fields["payload_size"] == str(len(payload))
    assert json.loads(fields["metadata"]) == {"page": 1}


def test_http_capture_redacts_credentials_but_keeps_response_body() -> None:
    client = FakeRedis()
    store = RedisEvidenceStore(client, "evidence")

    store.capture_http_response(
        source="github.discovery",
        method="GET",
        url="https://api.github.com/events?access_token=unsafe&per_page=100",
        response=FakeResponse(),
        request_params={"page": 1, "token": "unsafe"},
        request_headers={"Authorization": "Bearer unsafe"},
    )

    fields = client.calls[0][1]
    metadata = json.loads(fields["metadata"])
    assert fields["payload"] == FakeResponse.content
    assert "unsafe" not in fields["metadata"]
    assert "%5Bredacted%5D" in metadata["request"]["url"]
    assert metadata["request"]["headers"]["Authorization"] == REDACTED
    assert metadata["request"]["params"]["token"] == REDACTED
    assert metadata["response"]["headers"]["Set-Cookie"] == REDACTED


def test_config_reads_evidence_password_file(monkeypatch, tmp_path) -> None:
    password_file = tmp_path / "redis-password.txt"
    password_file.write_text("a" * 64, encoding="utf-8")
    monkeypatch.setenv("SH_EVIDENCE_ENABLED", "true")
    monkeypatch.setenv("SH_EVIDENCE_REDIS_PASSWORD_FILE", str(password_file))
    monkeypatch.setenv("SH_EVIDENCE_REDIS_PORT", "6380")

    cfg = Config.from_env(tmp_path / "missing.yaml")

    assert cfg.evidence_enabled is True
    assert cfg.evidence_redis_password == "a" * 64
    assert cfg.evidence_redis_port == 6380
