from __future__ import annotations

import hashlib
import json
from uuid import uuid4

import pytest

from secret_hunter.config import Config
from secret_hunter.evidence import REDACTED, RedisEvidenceStore


class FakeRedis:
    def __init__(self):
        self.calls: list[tuple[str, dict]] = []
        self.closed = False

    def xadd(self, stream: str, fields: dict) -> bytes:
        self.calls.append((stream, fields))
        return b"1-0"

    def xrange(self, stream: str, min: str, max: str, count: int = 1):
        del min, max
        return [(b"1-0", fields) for key, fields in self.calls if key == stream][:count]

    def xrevrange(self, stream: str, max: str, min: str, count: int = 1):
        del min, max
        return [(b"1-0", fields) for key, fields in reversed(self.calls) if key == stream][:count]

    def close(self) -> None:
        self.closed = True


class FakeResponse:
    status_code = 200
    content = b'{"items":[{"sample":"raw"}]}'
    headers = {"Content-Type": "application/json", "Set-Cookie": "private"}


def test_append_stores_payload_with_hash_and_redis_auth_marker() -> None:
    client = FakeRedis()
    store = RedisEvidenceStore(client, "secret-hunter:raw-evidence")
    payload = b"raw\x00payload"

    entry_id = store.append_bytes("fixture", payload, metadata={"page": 1})

    assert entry_id == "1-0"
    stream, fields = client.calls[0]
    assert stream == "secret-hunter:raw-evidence"
    assert fields["schema_version"] == "3"
    assert fields["protection"] == "redis-auth"
    assert fields["payload"] == payload
    assert fields["payload_sha256"] == hashlib.sha256(payload).hexdigest()
    assert fields["payload_size"] == str(len(payload))
    assert json.loads(fields["metadata"]) == {"page": 1}
    proof = store.proof(entry_id="1-0")[0]
    assert proof["status"] == "verified"
    assert proof["plaintext_exposed"] is False
    assert "payload" not in proof


def test_http_capture_redacts_credentials_and_stores_response_body() -> None:
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


def test_real_redis_receives_password_protected_payload() -> None:
    cfg = Config.from_env()
    if not cfg.evidence_redis_password:
        pytest.skip("Redis de teste não configurado")
    cfg.evidence_enabled = True
    cfg.evidence_stream_key = f"secret-hunter-test:evidence:{uuid4().hex}"
    raw = b"synthetic-controlled-material-for-redis-test"
    store = RedisEvidenceStore.from_config(cfg)
    try:
        entry_id = store.append_bytes("fixture.redis", raw, metadata={"case": "redis-auth"})
        records = store.client.xrange(cfg.evidence_stream_key, min=entry_id, max=entry_id)
        assert len(records) == 1
        fields = {
            key.decode("utf-8"): value
            for key, value in records[0][1].items()
        }
        fields["metadata"] = fields["metadata"].decode("utf-8")
        assert fields["payload"] == raw
        assert store.proof(entry_id=entry_id)[0]["status"] == "verified"
    finally:
        store.client.delete(cfg.evidence_stream_key)
        store.close()

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
    cfg.fingerprint_key = "f" * 64
    cfg.database_password = "fixture"
    cfg.require_distributed_secrets()
