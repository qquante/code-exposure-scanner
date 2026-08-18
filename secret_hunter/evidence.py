"""Armazenamento simples de respostas brutas do GitHub em Redis Streams."""

from __future__ import annotations

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

    def __init__(self, client: Any, stream_key: str):
        self.client = client
        self.stream_key = stream_key

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
        return cls(client, cfg.evidence_stream_key)

    def append_bytes(
        self,
        source: str,
        payload: bytes,
        *,
        metadata: Mapping[str, Any] | None = None,
    ) -> str:
        raw = bytes(payload)
        captured_at = datetime.now(timezone.utc).isoformat()
        metadata_json = json.dumps(
            _sanitize(dict(metadata or {})),
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        metadata_bytes = metadata_json.encode("utf-8")
        fields = {
            "schema_version": "3",
            "source": source,
            "captured_at": captured_at,
            "protection": "redis-auth",
            "payload": raw,
            "payload_sha256": hashlib.sha256(raw).hexdigest(),
            "payload_size": str(len(raw)),
            "metadata": metadata_json,
            "metadata_sha256": hashlib.sha256(metadata_bytes).hexdigest(),
        }
        entry_id = self.client.xadd(self.stream_key, fields)
        return entry_id.decode("ascii") if isinstance(entry_id, bytes) else str(entry_id)

    def proof(self, *, entry_id: str | None = None, limit: int = 3) -> list[dict[str, Any]]:
        """Verifica hashes sem devolver nem imprimir o corpo bruto armazenado."""
        records = (
            self.client.xrange(self.stream_key, min=entry_id, max=entry_id, count=1)
            if entry_id
            else self.client.xrevrange(
                self.stream_key, max="+", min="-", count=max(1, min(limit, 100))
            )
        )
        return [self._proof_record(item_id, fields) for item_id, fields in records]

    @staticmethod
    def _proof_record(item_id: Any, fields: Mapping[Any, Any]) -> dict[str, Any]:
        def raw(name: str) -> bytes:
            value = fields.get(name, fields.get(name.encode("utf-8")))
            if value is None:
                raise ValueError(f"campo de evidencia ausente: {name}")
            return value if isinstance(value, bytes) else str(value).encode("utf-8")

        def text(name: str) -> str:
            return raw(name).decode("utf-8")

        record_id = item_id.decode("ascii") if isinstance(item_id, bytes) else str(item_id)
        schema_version = text("schema_version")
        metadata = raw("metadata")
        metadata_ok = hashlib.sha256(metadata).hexdigest() == text("metadata_sha256")
        result: dict[str, Any] = {
            "entry_id": record_id,
            "schema_version": schema_version,
            "source": text("source"),
            "captured_at": text("captured_at"),
            "payload_size": int(text("payload_size")),
            "metadata_sha256_ok": metadata_ok,
            "plaintext_exposed": False,
        }
        if schema_version == "3":
            payload = raw("payload")
            result["protection"] = text("protection")
            result["payload_sha256"] = text("payload_sha256")
            result["payload_sha256_ok"] = (
                hashlib.sha256(payload).hexdigest() == result["payload_sha256"]
            )
            result["payload_size_ok"] = len(payload) == result["payload_size"]
            result["status"] = (
                "verified"
                if metadata_ok and result["payload_sha256_ok"] and result["payload_size_ok"]
                else "integrity_failed"
            )
        else:
            ciphertext = raw("payload")
            result["protection"] = text("encryption")
            result["ciphertext_sha256_ok"] = (
                hashlib.sha256(ciphertext).hexdigest()
                == text("payload_ciphertext_sha256")
            )
            result["status"] = (
                "legacy_encrypted"
                if metadata_ok and result["ciphertext_sha256_ok"]
                else "integrity_failed"
            )
        return result

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
