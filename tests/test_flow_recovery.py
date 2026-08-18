from __future__ import annotations

import os
from dataclasses import replace
from datetime import datetime, timezone
from uuid import uuid4

import pytest

from secret_hunter.config import Config
from secret_hunter.discovery import RepositoryMetadata
from secret_hunter.event_bus import RedisStreamBus
from secret_hunter.pipeline import dispatch_jobs_once, handle_job
from secret_hunter.postgres import PostgresStore


pytestmark = pytest.mark.skipif(
    not os.environ.get("SH_DATABASE_HOST") and not os.environ.get("SH_DATABASE_URL"),
    reason="PostgreSQL de integração não configurado",
)


@pytest.fixture()
def store() -> PostgresStore:
    database = PostgresStore(Config.from_env(), init_schema=True)
    with database.pool.connection() as conn:
        conn.execute(
            """
            TRUNCATE pipeline_events, audit_events, discovery_candidates,
                     discovery_windows, discovery_checkpoints,
                     notification_findings, notification_outbox,
                     finding_locations, findings, scan_jobs, scan_runs,
                     repositories, rate_limit_buckets
            RESTART IDENTITY CASCADE
            """
        )
    try:
        yield database
    finally:
        with database.pool.connection() as conn:
            conn.execute(
                """
                TRUNCATE pipeline_events, audit_events, discovery_candidates,
                         discovery_windows, discovery_checkpoints,
                         notification_findings, notification_outbox,
                         finding_locations, findings, scan_jobs, scan_runs,
                         repositories, rate_limit_buckets
                RESTART IDENTITY CASCADE
                """
            )
        database.close()


def test_redis_dispatcher_recovers_undispatched_job_below_cursor(
    store: PostgresStore,
) -> None:
    cfg = Config.from_env()
    if not cfg.event_bus_enabled or not cfg.evidence_redis_password:
        pytest.skip("Redis de integração não configurado")

    prefix = f"secret-hunter-reconcile:{uuid4().hex}"
    bus = RedisStreamBus.from_config(
        replace(cfg, event_bus_prefix=prefix, event_bus_block_ms=10)
    )
    try:
        stream = bus.job_stream("blob")
        group = bus.worker_group("blob")
        bus.client.xadd(stream, {"job_id": "priming"}, id="999999-0")
        bus.ensure_group(stream, group)
        priming = bus.read_new("blob", "priming-worker")
        assert len(priming) == 1
        assert bus.ack_job("blob", priming[0][0]) == 1
        bus.advance_dispatcher_cursor(999999)

        assert store.enqueue_job(
            "fetch_blob",
            "redis-orphan-below-cursor",
            {"repo": "acme/recovered", "path": ".env", "blob_sha": "a" * 40},
        ) is True
        job = next(
            item
            for item in store.list_jobs_after(0)
            if item["natural_key"] == "redis-orphan-below-cursor"
        )
        assert int(job["id"]) < bus.dispatcher_cursor()

        scanned, published = dispatch_jobs_once(store, bus, batch=10)

        assert scanned == 1
        assert published == 1
        with store.pool.connection() as conn:
            dispatched = conn.execute(
                "SELECT redis_dispatched_at, redis_entry_id FROM scan_jobs WHERE id = %s",
                (job["id"],),
            ).fetchone()
        assert dispatched["redis_dispatched_at"] is not None
        assert dispatched["redis_entry_id"]
        messages = bus.read_new("blob", "recovery-worker")
        assert len(messages) == 1
        assert messages[0][1]["job_id"] == str(job["id"])
    finally:
        for key in bus.client.scan_iter(match=f"{prefix}:*"):
            bus.client.delete(key)
        bus.close()


def test_stats_separate_stale_pending_jobs(store: PostgresStore) -> None:
    assert store.enqueue_job(
        "fetch_blob",
        "stale-dashboard-job",
        {"repo": "acme/stale", "path": ".env", "blob_sha": "b" * 40},
    ) is True
    with store.pool.connection() as conn:
        conn.execute(
            """
            UPDATE scan_jobs
            SET created_at = now() - interval '10 minutes',
                updated_at = now() - interval '10 minutes'
            WHERE natural_key = 'stale-dashboard-job'
            """
        )

    stats = store.stats()

    assert stats["pending_jobs"] == 1
    assert stats["stale_pending_jobs"] == 1
    assert stats["live_pending_jobs"] == 0


def test_pushed_repository_reactivates_candidate_initially_created_empty(
    store: PostgresStore,
) -> None:
    created_at = datetime.now(timezone.utc).isoformat()
    repository_id = 424242
    event_id = f"repository-search:{repository_id}"
    empty_metadata = RepositoryMetadata(
        github_repository_id=repository_id,
        full_name="acme/initially-empty",
        is_public=True,
        language=None,
        size_kb=0,
        is_fork=False,
        is_archived=False,
        is_disabled=False,
        default_branch="main",
        created_at=created_at,
    )
    collector = "created-recheck-test"
    owner = "created-owner"
    assert store.claim_discovery_checkpoint(collector, owner, lease_seconds=120)
    created = store.persist_discovery_poll(
        collector,
        owner,
        [
            {
                "event_id": event_id,
                "github_repository_id": repository_id,
                "repository": "acme/initially-empty",
                "event_created_at": created_at,
                "metadata": empty_metadata.payload(),
            }
        ],
        etag="",
        newest_event_id=str(repository_id),
        poll_interval=15,
        gap_detected=False,
    )
    assert created == 1
    first_job = store.claim_job(
        "metadata-empty", kinds=("enrich_repository_candidate",)
    )
    assert first_job is not None
    handle_job(store, store.cfg, first_job)
    assert store.complete_job(first_job["id"], "metadata-empty")
    candidate = store.list_discovery_candidates()[0]
    assert candidate["status"] == "filtered"
    assert candidate["filter_reason"] == "size_below_min"

    pushed_metadata = RepositoryMetadata(
        github_repository_id=repository_id,
        full_name="acme/initially-empty",
        is_public=True,
        language="Python",
        size_kb=12,
        is_fork=False,
        is_archived=False,
        is_disabled=False,
        default_branch="main",
        created_at=created_at,
    )
    pushed_collector = "pushed-recheck-test"
    pushed_owner = "pushed-owner"
    assert store.claim_discovery_checkpoint(
        pushed_collector, pushed_owner, lease_seconds=120
    )
    reactivated = store.persist_discovery_poll(
        pushed_collector,
        pushed_owner,
        [
            {
                "event_id": event_id,
                "github_repository_id": repository_id,
                "repository": "acme/initially-empty",
                "event_created_at": created_at,
                "metadata": pushed_metadata.payload(),
                "recheck_token": f"{repository_id}:12:main",
            }
        ],
        etag="",
        newest_event_id=str(repository_id),
        poll_interval=15,
        gap_detected=False,
        reactivate_size_filtered=True,
    )

    assert reactivated == 1
    detail = store.get_discovery_candidate(candidate["id"])
    assert detail is not None
    assert detail["status"] == "pending_metadata"
    with store.pool.connection() as conn:
        jobs = conn.execute(
            """
            SELECT natural_key, payload
            FROM scan_jobs
            WHERE kind = 'enrich_repository_candidate'
            ORDER BY id
            """
        ).fetchall()
    assert len(jobs) == 2
    assert jobs[-1]["natural_key"].startswith("discovery-recheck:")
    assert jobs[-1]["payload"]["metadata"]["size_kb"] == 12
