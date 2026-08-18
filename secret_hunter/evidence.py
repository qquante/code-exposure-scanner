"""Armazenamento simples de respostas brutas do GitHub em Redis Streams."""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Mapping
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from .config import Config


REDACTED = "[redacted]"
_SENSITIVE_PARTS = (
    "authorization",
    "cookie",
    "password",
    "secret",
    "token",
    "private_key",
)


def _is_sensitive(name: object) -> bool:
    normalized = str(name).strip().lower().replace("-", "_")
    return any(part in normalized for part in _SENSITIVE_PARTS)


def _sanitize(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {
            str(key): REDACTED if _is_sensitive(key) else _sanitize(item)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_sanitize(item) for item in value]
    if isinstance(value, bytes):
        return f"<bytes:{len(value)}>"
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


def _sanitize_url(url: str) -> str:
    parts = urlsplit(url)
    query = [
        (key, REDACTED if _is_sensitive(key) else value)
        for key, value in parse_qsl(parts.query, keep_blank_values=True)
    ]
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), ""))


class RedisEvidenceStore:
    """Append-only lógico: um item por resposta HTTP, sem TTL nem trimming."""

    def __init__(self, client: Any, stream_key: str, encryption_key: bytes):
        key = bytes(encryption_key)
        if len(key) != 32:
            raise ValueError("a chave de evidência deve ter exatamente 32 bytes")
        self.client = client
        self.stream_key = stream_key
        self._encryption_key = key
        self.encryption_key_id = hashlib.sha256(key).hexdigest()[:16]

    @classmethod
    def from_config(cls, cfg: Config) -> "RedisEvidenceStore":
        if not cfg.evidence_redis_password:
            raise ValueError("senha do Redis de evidências ausente")
        try:
            import redis
        except ImportError as exc:  # pragma: no cover - falha de empacotamento
            raise RuntimeError("dependência redis não instalada") from exc

        client = redis.Redis(
            host=cfg.evidence_redis_host,
            port=cfg.evidence_redis_port,
            db=cfg.evidence_redis_db,
            password=cfg.evidence_redis_password,
            socket_connect_timeout=cfg.request_timeout,
            socket_timeout=cfg.request_timeout,
            decode_responses=False,
        )
        client.ping()
        try:
            encryption_key = bytes.fromhex(cfg.evidence_encryption_key)
        except ValueError as exc:
            client.close()
            raise ValueError("chave de criptografia da evidência inválida") from exc
        if len(encryption_key) != 32:
            client.close()
            raise ValueError("chave de criptografia da evidência deve ter 32 bytes")
        return cls(client, cfg.evidence_stream_key, encryption_key)

    def append_bytes(
        self,
        source: str,
        payload: bytes,
        *,
        metadata: Mapping[str, Any] | None = None,
    ) -> str:
        try:
            from Crypto.Cipher import AES
            from Crypto.Random import get_random_bytes
        except ImportError as exc:  # pragma: no cover - falha de empacotamento
            raise RuntimeError("dependência pycryptodome não instalada") from exc

        raw = bytes(payload)
        captured_at = datetime.now(timezone.utc).isoformat()
        metadata_json = json.dumps(
            _sanitize(dict(metadata or {})),
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        metadata_bytes = metadata_json.encode("utf-8")
        nonce = get_random_bytes(12)
        cipher = AES.new(self._encryption_key, AES.MODE_GCM, nonce=nonce, mac_len=16)
        cipher.update(metadata_bytes)
        ciphertext, auth_tag = cipher.encrypt_and_digest(raw)
        fields = {
            "schema_version": "2",
            "source": source,
            "captured_at": captured_at,
            "encryption": "AES-256-GCM",
            "encryption_key_id": self.encryption_key_id,
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "auth_tag": base64.b64encode(auth_tag).decode("ascii"),
            "payload": ciphertext,
            "payload_sha256": hashlib.sha256(raw).hexdigest(),
            "payload_ciphertext_sha256": hashlib.sha256(ciphertext).hexdigest(),
            "payload_size": str(len(raw)),
            "metadata": metadata_json,
            "metadata_sha256": hashlib.sha256(metadata_bytes).hexdigest(),
        }
        entry_id = self.client.xadd(self.stream_key, fields)
        return entry_id.decode("ascii") if isinstance(entry_id, bytes) else str(entry_id)

    def capture_http_response(
        self,
        *,
        source: str,
        method: str,
        url: str,
        response: Any,
        request_params: Mapping[str, Any] | None = None,
        request_headers: Mapping[str, Any] | None = None,
    ) -> str:
        content = getattr(response, "content", None)
        if content is None:
            content = str(getattr(response, "text", "")).encode("utf-8")
        return self.append_bytes(
            source,
            bytes(content),
            metadata={
                "request": {
                    "method": method.upper(),
                    "url": _sanitize_url(url),
                    "params": dict(request_params or {}),
                    "headers": dict(request_headers or {}),
                },
                "response": {
                    "status_code": int(response.status_code),
                    "headers": dict(getattr(response, "headers", {}) or {}),
                },
            },
        )

    def close(self) -> None:
        close = getattr(self.client, "close", None)
        if callable(close):
            close()


def maybe_evidence_store(cfg: Config) -> RedisEvidenceStore | None:
    if not cfg.evidence_enabled:
        return None
    return RedisEvidenceStore.from_config(cfg)
