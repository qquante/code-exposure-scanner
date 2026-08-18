from __future__ import annotations

from dataclasses import replace
from uuid import uuid4

import pytest

from secret_hunter.config import Config
from secret_hunter.event_bus import RedisStreamBus, sanitize_event_payload, stage_for_job


class _FakeRedis:
    def __init__(self) -> None:
        self.streams: dict[str, list[tuple[str, dict[str, str]]]] = {}
        self.values: dict[str, str] = {}
        self.groups: set[tuple[str, str]] = set()
        self.acked: list[tuple[str, str, str]] = []

    def xadd(self, stream, fields, id="*"):
        entries = self.streams.setdefault(stream, [])
        entry_id = str(id if id != "*" else f"{len(entries) + 1}-0")
        if any(existing_id == entry_id for existing_id, _ in entries):
            raise RuntimeError("ID specified in XADD is equal or smaller")
        entries.append((entry_id, dict(fields)))
        return entry_id

    def xrange(self, stream, min, max, count=1):
        return [item for item in self.streams.get(stream, []) if min <= item[0] <= max][:count]

    def xgroup_create(self, stream, group, id="0-0", mkstream=False):
        key = (stream, group)
        if key in self.groups:
            raise RuntimeError("BUSYGROUP Consumer Group name already exists")
        self.groups.add(key)
        if mkstream:
            self.streams.setdefault(stream, [])
        return True

    def xack(self, stream, group, message_id):
        self.acked.append((stream, group, message_id))
        return 1

    def get(self, key):
        return self.values.get(key)

    def set(self, key, value):
        self.values[key] = str(value)
        return True

    def xlen(self, stream):
        return len(self.streams.get(stream, []))

    def xinfo_groups(self, stream):
        return [
            {
                "name": group,
                "pending": 0,
                "consumers": 0,
                "lag": len(self.streams.get(stream, [])),
                "last-delivered-id": "0-0",
            }
            for candidate, group in self.groups
            if candidate == stream
        ]

    def close(self):
        return None


def _job(job_id: int, kind: str, payload: dict) -> dict:
    return {
        "id": job_id,
        "kind": kind,
        "natural_key": f"job-{job_id}",
        "payload": payload,
        "priority": 5,
        "status": "pending",
        "created_at": "2026-08-17T00:00:00+00:00",
    }


@pytest.mark.parametrize(
    ("kind", "payload", "stage"),
    [
        ("enrich_repository_candidate", {}, "metadata"),
        ("enrich_repository_candidate", {"queue_lane": "live"}, "metadata-live"),
        ("enrich_repository_candidate", {"queue_lane": "backfill"}, "metadata-backfill"),
        ("github_search", {}, "search"),
        ("fetch_blob", {}, "blob"),
        ("scan_history", {"mode": "head"}, "head"),
        ("scan_history", {"mode": "head", "queue_lane": "live"}, "head-live"),
        ("scan_history", {"mode": "head", "queue_lane": "backfill"}, "head-backfill"),
        ("scan_history", {"mode": "history"}, "history"),
        ("scan_ingested_file", {}, "ingest"),
    ],
)
def test_job_routes_to_one_independent_stage(kind, payload, stage) -> None:
    assert stage_for_job(_job(1, kind, payload)) == stage


def test_event_payload_redacts_sensitive_fields_recursively() -> None:
    value = sanitize_event_payload(
        {
            "repository": "acme/demo",
            "token": "ghp_raw",
            "nested": {"private_key": "raw", "risk": "critical"},
            "payload": '{"mnemonic": "raw words", "repo": "acme/demo"}',
        }
    )
    assert value == {
        "repository": "acme/demo",
        "token": "[redacted]",
        "nested": {"private_key": "[redacted]", "risk": "critical"},
        "payload": '{"mnemonic": "[redacted]", "repo": "acme/demo"}',
    }


def test_publish_job_is_idempotent_and_contains_sanitized_data() -> None:
    client = _FakeRedis()
    bus = RedisStreamBus(client, prefix="test")
    job = _job(
        42,
        "scan_history",
        {
            "mode": "head",
            "queue_lane": "live",
            "repo": "acme/demo",
            "token": "raw",
        },
    )

    assert bus.publish_job(job) == ("42-0", True)
    assert bus.publish_job(job) == ("42-0", False)

    entries = client.streams["test:jobs:head-live"]
    assert len(entries) == 1
    assert entries[0][1]["job_id"] == "42"
    assert '"token": "[redacted]"' in entries[0][1]["payload"]


def test_dispatcher_cursor_is_monotonic() -> None:
    bus = RedisStreamBus(_FakeRedis(), prefix="test")
    assert bus.dispatcher_cursor() == 0
    bus.advance_dispatcher_cursor(12)
    assert bus.dispatcher_cursor() == 12


def test_real_redis_consumer_group_round_trip_when_configured() -> None:
    cfg = Config.from_env()
    if not cfg.event_bus_enabled or not cfg.evidence_redis_password:
        pytest.skip("Redis de teste não configurado")
    prefix = f"secret-hunter-test:{uuid4().hex}"
    bus = RedisStreamBus.from_config(replace(cfg, event_bus_prefix=prefix, event_bus_block_ms=10))
    try:
        entry_id, created = bus.publish_job(
            _job(77, "scan_history", {"mode": "head", "repo": "acme/demo"})
        )
        assert created is True
        messages = bus.read_new("head", "test-consumer")
        assert messages == [(entry_id, messages[0][1])]
        assert messages[0][1]["job_id"] == "77"
        assert bus.ack_job("head", entry_id) == 1
    finally:
        for key in bus.client.scan_iter(match=f"{prefix}:*"):
            bus.client.delete(key)
        bus.close()
