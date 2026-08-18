from __future__ import annotations

import base64
import hashlib
import json
from uuid import uuid4

import pytest

from Crypto.Cipher import AES

from secret_hunter.config import Config
from secret_hunter.evidence import REDACTED, RedisEvidenceStore


EVIDENCE_KEY = bytes(range(32))


def decrypt_payload(fields: dict, key: bytes = EVIDENCE_KEY) -> bytes:
    cipher = AES.new(
        key,
        AES.MODE_GCM,
        nonce=base64.b64decode(fields["nonce"]),
        mac_len=16,
    )
    cipher.update(fields["metadata"].encode("utf-8"))
    return cipher.decrypt_and_verify(
        fields["payload"], base64.b64decode(fields["auth_tag"])
    )


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


def test_append_encrypts_payload_without_trimming() -> None:
    client = FakeRedis()
    store = RedisEvidenceStore(client, "secret-hunter:raw-evidence", EVIDENCE_KEY)
    payload = b"raw\x00payload"

    entry_id = store.append_bytes("fixture", payload, metadata={"page": 1})

    assert entry_id == "1-0"
    stream, fields = client.calls[0]
    assert stream == "secret-hunter:raw-evidence"
    assert fields["schema_version"] == "2"
    assert fields["encryption"] == "AES-256-GCM"
    assert fields["encryption_key_id"] == hashlib.sha256(EVIDENCE_KEY).hexdigest()[:16]
    assert fields["payload"] != payload
    assert payload not in fields["payload"]
    assert decrypt_payload(fields) == payload
    assert fields["payload_sha256"] == hashlib.sha256(payload).hexdigest()
    assert fields["payload_ciphertext_sha256"] == hashlib.sha256(fields["payload"]).hexdigest()
    assert fields["payload_size"] == str(len(payload))
    assert json.loads(fields["metadata"]) == {"page": 1}


def test_http_capture_redacts_credentials_and_encrypts_response_body() -> None:
    client = FakeRedis()
    store = RedisEvidenceStore(client, "evidence", EVIDENCE_KEY)

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
    assert fields["payload"] != FakeResponse.content
    assert decrypt_payload(fields) == FakeResponse.content
    assert "unsafe" not in fields["metadata"]
    assert "%5Bredacted%5D" in metadata["request"]["url"]
    assert metadata["request"]["headers"]["Authorization"] == REDACTED
    assert metadata["request"]["params"]["token"] == REDACTED
    assert metadata["response"]["headers"]["Set-Cookie"] == REDACTED


def test_real_redis_receives_only_ciphertext() -> None:
    cfg = Config.from_env()
    if not cfg.evidence_redis_password or not cfg.evidence_encryption_key:
        pytest.skip("Redis de teste não configurado")
    cfg.evidence_enabled = True
    cfg.evidence_stream_key = f"secret-hunter-test:evidence:{uuid4().hex}"
    raw = b'synthetic-private-material-for-encryption-test'
    store = RedisEvidenceStore.from_config(cfg)
    try:
        entry_id = store.append_bytes("fixture.redis", raw, metadata={"case": "aes-gcm"})
        records = store.client.xrange(cfg.evidence_stream_key, min=entry_id, max=entry_id)
        assert len(records) == 1
        fields = {
            key.decode("utf-8"): value
            for key, value in records[0][1].items()
        }
        fields["metadata"] = fields["metadata"].decode("utf-8")
        fields["nonce"] = fields["nonce"].decode("ascii")
        fields["auth_tag"] = fields["auth_tag"].decode("ascii")
        assert fields["payload"] != raw
        assert raw not in fields["payload"]
        assert decrypt_payload(fields, bytes.fromhex(cfg.evidence_encryption_key)) == raw
    finally:
        store.client.delete(cfg.evidence_stream_key)
        store.close()

def test_config_reads_evidence_password_file(monkeypatch, tmp_path) -> None:
    password_file = tmp_path / "redis-password.txt"
    key_file = tmp_path / "evidence-key.txt"
    password_file.write_text("a" * 64, encoding="utf-8")
    key_file.write_text("b" * 64, encoding="utf-8")
    monkeypatch.setenv("SH_EVIDENCE_ENABLED", "true")
    monkeypatch.setenv("SH_EVIDENCE_REDIS_PASSWORD_FILE", str(password_file))
    monkeypatch.setenv("SH_EVIDENCE_ENCRYPTION_KEY_FILE", str(key_file))
    monkeypatch.setenv("SH_EVIDENCE_REDIS_PORT", "6380")

    cfg = Config.from_env(tmp_path / "missing.yaml")

    assert cfg.evidence_enabled is True
    assert cfg.evidence_redis_password == "a" * 64
    assert cfg.evidence_encryption_key == "b" * 64
    assert cfg.evidence_redis_port == 6380
    cfg.fingerprint_key = "f" * 64
    cfg.database_password = "fixture"
    cfg.require_distributed_secrets()
