"""Redis Streams transport for independent, idempotent pipeline workers.

PostgreSQL remains the source of truth. Stream messages carry only job IDs and
sanitized metadata; raw secret material is never published on the event bus.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any

from .config import Config
from .queue_policy import STAGES, job_payload, stage_for_job


_SENSITIVE_KEY = re.compile(
    r"(?:authorization|cookie|mnemonic|password|private[_-]?key|secret|seed|token)",
    re.IGNORECASE,
)


def sanitize_event_payload(value: Any) -> Any:
    """Recursively redact sensitive fields before writing durable Redis events."""
    if isinstance(value, dict):
        return {
            str(key): "[redacted]" if _SENSITIVE_KEY.search(str(key)) else sanitize_event_payload(item)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [sanitize_event_payload(item) for item in value]
    if isinstance(value, str):
        stripped = value.strip()
        if stripped.startswith(("{", "[")):
            try:
                decoded = json.loads(stripped)
            except json.JSONDecodeError:
                pass
            else:
                if isinstance(decoded, (dict, list)):
                    return json.dumps(
                        sanitize_event_payload(decoded),
                        ensure_ascii=False,
                        sort_keys=True,
                    )
        return value
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return str(value)


class RedisStreamBus:
    """Small Redis Streams facade shared by dispatchers and stage workers."""

    def __init__(
        self,
        client: Any,
        *,
        prefix: str,
        block_ms: int = 5_000,
        claim_idle_ms: int = 180_000,
    ) -> None:
        self.client = client
        self.prefix = prefix.strip(":") or "secret-hunter"
        self.block_ms = max(int(block_ms), 1)
        self.claim_idle_ms = max(int(claim_idle_ms), 1_000)

    @classmethod
    def from_config(cls, cfg: Config) -> "RedisStreamBus":
        if not cfg.event_bus_enabled:
            raise RuntimeError("Redis event bus desabilitado")
        if not cfg.evidence_redis_password:
            raise RuntimeError("senha do Redis ausente")
        try:
            import redis
        except ImportError as exc:  # pragma: no cover - dependency is required in Docker
            raise RuntimeError("dependência redis não instalada") from exc
        client = redis.Redis(
            host=cfg.evidence_redis_host,
            port=cfg.evidence_redis_port,
            db=cfg.evidence_redis_db,
            password=cfg.evidence_redis_password,
            decode_responses=True,
            socket_connect_timeout=max(cfg.request_timeout, 1),
            socket_timeout=max(cfg.request_timeout, 1),
            health_check_interval=30,
        )
        client.ping()
        return cls(
            client,
            prefix=cfg.event_bus_prefix,
            block_ms=cfg.event_bus_block_ms,
            claim_idle_ms=cfg.event_bus_claim_idle_ms,
        )

    @property
    def events_stream(self) -> str:
        return f"{self.prefix}:events"

    @property
    def dead_letter_stream(self) -> str:
        return f"{self.prefix}:dead-letter"

    @property
    def event_index_group(self) -> str:
        return f"{self.prefix}:indexer"

    @property
    def dispatcher_cursor_key(self) -> str:
        return f"{self.prefix}:dispatcher:last-job-id"

    def job_stream(self, stage: str) -> str:
        if stage not in STAGES:
            raise ValueError(f"stage Redis inválido: {stage}")
        return f"{self.prefix}:jobs:{stage}"

    def worker_group(self, stage: str) -> str:
        if stage not in STAGES:
            raise ValueError(f"stage Redis inválido: {stage}")
        return f"{self.prefix}:workers:{stage}"

    def ensure_group(self, stream: str, group: str) -> None:
        try:
            self.client.xgroup_create(stream, group, id="0-0", mkstream=True)
        except Exception as exc:
            if "BUSYGROUP" not in str(exc):
                raise

    def publish_job(self, job: dict[str, Any]) -> tuple[str, bool]:
        """Publish a job once using its monotonic PostgreSQL ID as stream ID."""
        job_id = int(job["id"])
        stage = stage_for_job(job)
        stream = self.job_stream(stage)
        entry_id = f"{job_id}-0"
        fields = {
            "schema_version": "1",
            "event_type": "job.available",
            "event_key": f"job:{job_id}",
            "stage": stage,
            "job_id": str(job_id),
            "kind": str(job.get("kind") or ""),
            "natural_key": str(job.get("natural_key") or ""),
            "priority": str(job.get("priority") or 0),
            "status": str(job.get("status") or "pending"),
            "created_at": str(job.get("created_at") or ""),
            "payload": json.dumps(
                sanitize_event_payload(job_payload(job)), ensure_ascii=False, sort_keys=True
            ),
        }
        try:
            result = self.client.xadd(stream, fields, id=entry_id)
            return str(result), True
        except Exception as exc:
            if "equal or smaller" not in str(exc).lower():
                raise
            existing = self.client.xrange(stream, min=entry_id, max=entry_id, count=1)
            if existing and str(existing[0][1].get("job_id")) == str(job_id):
                return entry_id, False
            raise RuntimeError(
                f"stream {stream} avançou sem conter job {job_id}"
            ) from exc

    def publish_event(
        self,
        event_type: str,
        *,
        event_key: str,
        stage: str,
        payload: dict[str, Any],
        job_id: int | None = None,
        kind: str = "",
    ) -> str:
        fields = {
            "schema_version": "1",
            "event_type": event_type,
            "event_key": event_key,
            "stage": stage,
            "job_id": str(job_id or ""),
            "kind": kind,
            "occurred_at": datetime.now(timezone.utc).isoformat(),
            "payload": json.dumps(
                sanitize_event_payload(payload), ensure_ascii=False, sort_keys=True
            ),
        }
        return str(self.client.xadd(self.events_stream, fields))

    def publish_dead_letter(
        self,
        *,
        stage: str,
        message_id: str,
        fields: dict[str, Any],
        error: str,
    ) -> str:
        return str(
            self.client.xadd(
                self.dead_letter_stream,
                {
                    "schema_version": "1",
                    "event_type": "message.dead_letter",
                    "stage": stage,
                    "source_message_id": message_id,
                    "error": error[:1000],
                    "payload": json.dumps(
                        sanitize_event_payload(fields), ensure_ascii=False, sort_keys=True
                    ),
                    "occurred_at": datetime.now(timezone.utc).isoformat(),
                },
            )
        )

    def read_new(self, stage: str, consumer: str, *, count: int = 1) -> list[tuple[str, dict[str, str]]]:
        stream = self.job_stream(stage)
        group = self.worker_group(stage)
        self.ensure_group(stream, group)
        response = self.client.xreadgroup(
            group,
            consumer,
            {stream: ">"},
            count=max(count, 1),
            block=self.block_ms,
        )
        if not response:
            return []
        return [(str(entry_id), dict(fields)) for entry_id, fields in response[0][1]]

    def reclaim_idle(
        self, stage: str, consumer: str, *, count: int = 1
    ) -> list[tuple[str, dict[str, str]]]:
        stream = self.job_stream(stage)
        group = self.worker_group(stage)
        self.ensure_group(stream, group)
        result = self.client.xautoclaim(
            stream,
            group,
            consumer,
            self.claim_idle_ms,
            "0-0",
            count=max(count, 1),
        )
        entries = result[1] if result and len(result) > 1 else []
        return [(str(entry_id), dict(fields)) for entry_id, fields in entries]

    def ack_job(self, stage: str, message_id: str) -> int:
        return int(
            self.client.xack(
                self.job_stream(stage), self.worker_group(stage), message_id
            )
        )

    def read_events(
        self, consumer: str, *, count: int = 10
    ) -> list[tuple[str, dict[str, str]]]:
        self.ensure_group(self.events_stream, self.event_index_group)
        response = self.client.xreadgroup(
            self.event_index_group,
            consumer,
            {self.events_stream: ">"},
            count=max(count, 1),
            block=self.block_ms,
        )
        if not response:
            return []
        return [(str(entry_id), dict(fields)) for entry_id, fields in response[0][1]]

    def reclaim_events(
        self, consumer: str, *, count: int = 10
    ) -> list[tuple[str, dict[str, str]]]:
        self.ensure_group(self.events_stream, self.event_index_group)
        result = self.client.xautoclaim(
            self.events_stream,
            self.event_index_group,
            consumer,
            self.claim_idle_ms,
            "0-0",
            count=max(count, 1),
        )
        entries = result[1] if result and len(result) > 1 else []
        return [(str(entry_id), dict(fields)) for entry_id, fields in entries]

    def ack_event(self, message_id: str) -> int:
        return int(self.client.xack(self.events_stream, self.event_index_group, message_id))

    def dispatcher_cursor(self) -> int:
        raw = self.client.get(self.dispatcher_cursor_key)
        return max(int(raw or 0), 0)

    def advance_dispatcher_cursor(self, job_id: int) -> None:
        self.client.set(self.dispatcher_cursor_key, str(max(int(job_id), 0)))

    def stream_stats(self) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for stage in STAGES:
            stream = self.job_stream(stage)
            group = self.worker_group(stage)
            self.ensure_group(stream, group)
            groups = self.client.xinfo_groups(stream)
            selected = next((item for item in groups if item.get("name") == group), {})
            rows.append(
                {
                    "stage": stage,
                    "stream": stream,
                    "length": int(self.client.xlen(stream)),
                    "pending": int(selected.get("pending") or 0),
                    "consumers": int(selected.get("consumers") or 0),
                    "lag": selected.get("lag"),
                    "last_delivered_id": str(selected.get("last-delivered-id") or "0-0"),
                }
            )
        self.ensure_group(self.events_stream, self.event_index_group)
        event_groups = self.client.xinfo_groups(self.events_stream)
        event_selected = next(
            (item for item in event_groups if item.get("name") == self.event_index_group),
            {},
        )
        rows.append(
            {
                "stage": "events",
                "stream": self.events_stream,
                "length": int(self.client.xlen(self.events_stream)),
                "pending": int(event_selected.get("pending") or 0),
                "consumers": int(event_selected.get("consumers") or 0),
                "lag": event_selected.get("lag"),
                "last_delivered_id": str(
                    event_selected.get("last-delivered-id") or "0-0"
                ),
            }
        )
        return rows

    def close(self) -> None:
        self.client.close()
