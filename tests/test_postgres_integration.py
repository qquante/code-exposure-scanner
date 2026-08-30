from __future__ import annotations

import os
from dataclasses import replace
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from secret_hunter.config import Config
from secret_hunter.event_bus import RedisStreamBus
from secret_hunter.extract import Finding
from secret_hunter.postgres import PostgresStore
from secret_hunter.discovery import (
    PublicRepositoriesPoll,
    RepositoryCreatedEvent,
    RepositoryMetadata,
)
from secret_hunter.patterns import PATTERN_SET_ID
from secret_hunter.pipeline import (
    dispatch_jobs_once,
    handle_job,
    poll_public_repositories_once,
    schedule_ingest,
    schedule_repository,
)


def _event(
    event_id: str,
    *,
    repository_id: int = 123,
    repository: str = "acme/demo",
    created_at: str | None = None,
) -> dict:
    return {
        "id": event_id,
        "type": "CreateEvent",
        "public": True,
        "created_at": created_at or datetime.now(timezone.utc).isoformat(),
        "repo": {"id": repository_id, "name": repository},
        "payload": {"ref_type": "repository"},
    }


class FakePollClient:
    def __init__(self, events: tuple[dict, ...]):
        self.events = events

    def search_repository_window(
        self, *, window_start: datetime, window_end: datetime
    ) -> PublicRepositoriesPoll:
        repositories = tuple(
            RepositoryCreatedEvent(
                event_id=str(item["id"]),
                github_repository_id=int(item["repo"]["id"]),
                repository=str(item["repo"]["name"]),
                event_created_at=str(item["created_at"]),
            )
            for item in self.events
        )
        return PublicRepositoriesPoll(
            repositories=repositories,
            newest_repository_id=(
                str(max(item.github_repository_id for item in repositories))
                if repositories
                else ""
            ),
            poll_interval=60,
            source_items_seen=len(self.events),
            bootstrapped=False,
            request_count=1,
            window_start=window_start.isoformat(),
            window_end=window_end.isoformat(),
        )


pytestmark = pytest.mark.skipif(
    not os.environ.get("SH_DATABASE_HOST") and not os.environ.get("SH_DATABASE_URL"),
    reason="PostgreSQL de integração não configurado",
)


@pytest.fixture()
def store() -> PostgresStore:
    cfg = Config.from_env()
    db = PostgresStore(cfg, init_schema=True)
    with db.pool.connection() as conn:
        conn.execute(
            """
            TRUNCATE pipeline_events, audit_events, discovery_candidates, discovery_checkpoints,
                     notification_findings, notification_outbox,
                     finding_locations, findings,
                     scan_jobs, scan_runs, repositories, rate_limit_buckets
            RESTART IDENTITY CASCADE
            """
        )
    try:
        yield db
    finally:
        with db.pool.connection() as conn:
            conn.execute(
                """
                TRUNCATE pipeline_events, audit_events, discovery_candidates, discovery_checkpoints,
                         notification_findings, notification_outbox,
                         finding_locations, findings,
                         scan_jobs, scan_runs, repositories, rate_limit_buckets
                RESTART IDENTITY CASCADE
                """
            )
        db.close()


def test_schema_has_no_raw_secret_column(store: PostgresStore) -> None:
    with store.pool.connection() as conn:
        columns = conn.execute(
            """
            SELECT table_name, column_name
            FROM information_schema.columns
            WHERE table_schema = 'public'
            """
        ).fetchall()
    names = {(row["table_name"], row["column_name"]) for row in columns}
    assert not any(name in {"secret_raw", "raw_secret", "secret_value"} for _, name in names)


def test_concurrent_enqueue_is_idempotent(store: PostgresStore) -> None:
    def enqueue(_: int) -> bool:
        return store.enqueue_job(
            "fetch_blob",
            "same-natural-key",
            {"repo": "acme/demo", "path": "x", "blob_sha": "a" * 40},
        )

    with ThreadPoolExecutor(max_workers=16) as executor:
        results = list(executor.map(enqueue, range(64)))

    assert sum(results) == 1
    with store.pool.connection() as conn:
        assert conn.execute("SELECT count(*) AS n FROM scan_jobs").fetchone()["n"] == 1


def test_automatic_jobs_outside_recent_window_expire_before_claim(
    store: PostgresStore,
) -> None:
    old_event = datetime.now(timezone.utc) - timedelta(hours=5)
    assert store.enqueue_job(
        "scan_history",
        "expired-recent-window",
        {
            "repo": "acme/demo",
            "mode": "head",
            "event_created_at": old_event.isoformat(),
        },
    )

    assert store.claim_job_by_id(1, "expiry-test") is None
    state = store.get_job_state(1)

    assert state is not None
    assert state["status"] == "expired"
    assert state["completed_at"] is not None


def test_recent_head_job_remains_claimable_for_full_repository_window(
    store: PostgresStore,
) -> None:
    created_at = datetime.now(timezone.utc) - timedelta(minutes=10)
    assert store.enqueue_job(
        "scan_history",
        "recent-head-window",
        {
            "repo": "acme/recent",
            "mode": "head",
            "event_created_at": created_at.isoformat(),
            "repository_created_at": created_at.isoformat(),
        },
    )

    job = store.claim_job_by_id(1, "recent-window-test")

    assert job is not None
    assert job["status"] == "running"


def test_recent_findings_use_github_repository_creation_time(
    store: PostgresStore,
) -> None:
    now = datetime.now(timezone.utc)
    old = Finding(
        "google_api_key", "Google Gemini", "ai", "high", "oculto",
        repo="acme/old-repository", path=".env", secret_raw="AIza" + "A" * 35,
    )
    recent = Finding(
        "google_api_key", "Google Gemini", "ai", "high", "oculto",
        repo="acme/recent-repository", path=".env", secret_raw="AIza" + "B" * 35,
    )

    store.upsert_finding(
        old,
        repository_created_at=now - timedelta(days=365 * 9),
    )
    store.upsert_finding(
        recent,
        repository_created_at=now - timedelta(hours=2),
    )

    assert [item["repository"] for item in store.list_findings(view="recent")] == [
        "acme/recent-repository"
    ]
    assert [item["repository"] for item in store.list_findings(view="archive")] == [
        "acme/old-repository"
    ]
def test_history_jobs_expire_when_history_toggle_is_off(store: PostgresStore) -> None:
    assert store.cfg.scan_history is False
    assert store.enqueue_job(
        "scan_history",
        "history-disabled",
        {
            "repo": "acme/demo",
            "mode": "history",
            "event_created_at": datetime.now(timezone.utc).isoformat(),
        },
    )

    assert store.claim_job_by_id(1, "history-toggle-test") is None
    state = store.get_job_state(1)
    assert state is not None and state["status"] == "expired"


def test_concurrent_file_ingest_is_idempotent_and_persists_no_raw_secret(
    store: PostgresStore, tmp_path
) -> None:
    target = tmp_path / "acme" / "demo" / ".env"
    target.parent.mkdir(parents=True)
    raw = "0x" + "1234567890abcdef" * 4
    target.write_text(f'PRIVATE_KEY="{raw}"\n', encoding="utf-8")
    store.cfg.ingest_root = tmp_path
    store.cfg.private_key_detection_enabled = True

    with ThreadPoolExecutor(max_workers=8) as executor:
        scheduled = list(
            executor.map(lambda _: schedule_ingest(store, store.cfg), range(16))
        )

    assert sum(item[2] for item in scheduled) == 1
    with store.pool.connection() as conn:
        assert conn.execute(
            "SELECT count(*) AS n FROM scan_runs WHERE mode = 'ingest'"
        ).fetchone()["n"] == 1
    job = store.claim_job("ingest-test", kinds=("scan_ingested_file",))
    assert job is not None and job["kind"] == "scan_ingested_file"
    handle_job(store, store.cfg, job)
    assert store.complete_job(job["id"], "ingest-test")

    finding = store.list_findings()[0]
    detail = store.get_finding(finding["id"])
    serialized = repr((job, finding, detail))
    assert detail is not None
    assert detail["locations"][0]["source_kind"] == "ingest"
    assert detail["locations"][0]["path"] == ".env"
    assert finding["latest_path"] == ".env"
    assert finding["latest_commit_sha"] == ""
    assert raw not in serialized


def test_worker_kind_filter_does_not_claim_other_queues(store: PostgresStore) -> None:
    store.enqueue_job("fetch_blob", "blob-job", {"repo": "acme/demo"})
    store.enqueue_job("scan_ingested_file", "ingest-job", {"repository": "acme/demo"})

    claimed = store.claim_job("ingest-only", kinds=("scan_ingested_file",))

    assert claimed is not None
    assert claimed["natural_key"] == "ingest-job"


def test_discovery_checkpoint_lease_is_exclusive(store: PostgresStore) -> None:
    def claim(index: int):
        return store.claim_discovery_checkpoint(
            "github-public-events", f"collector-{index}", lease_seconds=120
        )

    with ThreadPoolExecutor(max_workers=16) as executor:
        claimed = [item for item in executor.map(claim, range(32)) if item]

    assert len(claimed) == 1


def test_discovery_poll_persists_candidate_and_enrichment_job_once(
    store: PostgresStore,
) -> None:
    event = _event("event-1")
    client = FakePollClient((event,))

    first = poll_public_repositories_once(
        store, store.cfg, client=client, owner="collector-1"  # type: ignore[arg-type]
    )
    # Libera a janela artificialmente para provar dedupe em um segundo poll.
    with store.pool.connection() as conn:
        conn.execute(
            "UPDATE discovery_checkpoints SET next_poll_at = now(), etag = '', last_event_id = ''"
        )
    second = poll_public_repositories_once(
        store, store.cfg, client=client, owner="collector-2"  # type: ignore[arg-type]
    )

    assert first["candidates_created"] == 1
    assert second["candidates_created"] == 0
    candidates = store.list_discovery_candidates()
    assert len(candidates) == 1
    assert candidates[0]["status"] == "pending_metadata"
    with store.pool.connection() as conn:
        jobs = conn.execute(
            "SELECT kind, payload FROM scan_jobs WHERE kind = 'enrich_repository_candidate'"
        ).fetchall()
    assert len(jobs) == 1
    assert jobs[0]["payload"]["repository"] == "acme/demo"

def test_discovery_claims_newest_repository_metadata_first(
    store: PostgresStore,
) -> None:
    now = datetime.now(timezone.utc)
    newest = _event(
        "event-newest",
        repository_id=1002,
        repository="acme/newest",
        created_at=(now - timedelta(minutes=1)).isoformat(),
    )
    older = _event(
        "event-older",
        repository_id=1001,
        repository="acme/older",
        created_at=(now - timedelta(hours=12)).isoformat(),
    )

    result = poll_public_repositories_once(
        store,
        store.cfg,
        client=FakePollClient((newest, older)),  # type: ignore[arg-type]
        owner="collector-recency-priority",
    )

    assert result["candidates_created"] == 2
    claimed = store.claim_job(
        "recency-worker", kinds=("enrich_repository_candidate",)
    )
    assert claimed is not None
    assert claimed["payload"]["repository"] == "acme/newest"
    with store.pool.connection() as conn:
        priorities = conn.execute(
            "SELECT priority FROM scan_jobs ORDER BY priority DESC"
        ).fetchall()
    assert priorities[0]["priority"] > priorities[1]["priority"]



def test_candidate_authorization_is_atomic_and_requires_eligible_review(
    store: PostgresStore,
) -> None:
    event = _event("event-authorize")
    poll_public_repositories_once(
        store,
        store.cfg,
        client=FakePollClient((event,)),  # type: ignore[arg-type]
        owner="collector-authorize",
    )
    candidate = store.list_discovery_candidates()[0]
    assert store.authorize_candidate_scan(
        candidate["id"],
        "reviewer-before-metadata",
        "ticket AUTH-BLOCKED",
        trufflehog=True,
        pattern_set_id=PATTERN_SET_ID,
    ) is None
    metadata = RepositoryMetadata(
        github_repository_id=123,
        full_name="acme/demo",
        is_public=True,
        language="Python",
        size_kb=10,
        is_fork=False,
        is_archived=False,
        is_disabled=False,
        default_branch="main",
        created_at=datetime.now(timezone.utc).isoformat(),
    )
    assert store.complete_candidate_metadata(
        candidate["id"], metadata.payload(), eligible=True, filter_reason=""
    )

    def authorize(index: int):
        return store.authorize_candidate_scan(
            candidate["id"],
            f"reviewer-{index}",
            f"ticket AUTH-{index:04d}",
            trufflehog=True,
            pattern_set_id=PATTERN_SET_ID,
        )

    with ThreadPoolExecutor(max_workers=16) as executor:
        results = [item for item in executor.map(authorize, range(32)) if item]

    assert len(results) == 1
    detail = store.get_discovery_candidate(candidate["id"])
    assert detail is not None and detail["status"] == "scan_queued"
    with store.pool.connection() as conn:
        counts = conn.execute(
            """
            SELECT
                (SELECT count(*) FROM scan_jobs WHERE kind = 'scan_history') AS jobs,
                (SELECT count(*) FROM scan_runs WHERE mode = 'history') AS runs,
                (SELECT count(*) FROM audit_events
                 WHERE action = 'candidate.scan_authorized') AS audits
            """
        ).fetchone()
    assert dict(counts) == {"jobs": 1, "runs": 1, "audits": 1}

def test_candidate_auto_queue_is_atomic_without_human_authorization(
    store: PostgresStore,
) -> None:
    event = _event("event-auto-queue")
    poll_public_repositories_once(
        store,
        store.cfg,
        client=FakePollClient((event,)),  # type: ignore[arg-type]
        owner="collector-auto-queue",
    )
    candidate = store.list_discovery_candidates()[0]
    metadata = RepositoryMetadata(
        github_repository_id=123,
        full_name="acme/demo",
        is_public=True,
        language="Python",
        size_kb=10,
        is_fork=False,
        is_archived=False,
        is_disabled=False,
        default_branch="main",
        created_at=datetime.now(timezone.utc).isoformat(),
    )
    assert store.complete_candidate_metadata(
        candidate["id"], metadata.payload(), eligible=True, filter_reason=""
    )

    def queue(_: int):
        return store.queue_candidate_scan_automatically(
            candidate["id"],
            trufflehog=True,
            pattern_set_id=PATTERN_SET_ID,
        )

    with ThreadPoolExecutor(max_workers=16) as executor:
        results = [item for item in executor.map(queue, range(32)) if item]

    assert len(results) == 1
    detail = store.get_discovery_candidate(candidate["id"])
    assert detail is not None and detail["status"] == "scan_queued"
    assert not detail["authorization_reference"]
    assert not detail["authorized_by"]
    assert detail["authorized_at"] is None
    with store.pool.connection() as conn:
        queued_job = conn.execute(
            """
            SELECT natural_key, payload
            FROM scan_jobs
            WHERE kind = 'scan_history'
            """
        ).fetchone()
        counts = conn.execute(
            """
            SELECT
                (SELECT count(*) FROM scan_jobs WHERE kind = 'scan_history') AS jobs,
                (SELECT count(*) FROM scan_runs WHERE mode = 'history') AS runs,
                (SELECT count(*) FROM audit_events
                 WHERE action = 'candidate.scan_auto_queued') AS audits
            """
        ).fetchone()
    assert queued_job["natural_key"].startswith("candidate-head:")
    assert queued_job["payload"]["mode"] == "head"
    assert queued_job["payload"]["queue_lane"] == "live"
    assert queued_job["payload"]["event_created_at"]
    assert queued_job["payload"]["repository_created_at"]
    assert queued_job["payload"]["history_natural_key"].startswith(
        "candidate-history:"
    )
    assert dict(counts) == {"jobs": 1, "runs": 1, "audits": 1}


def test_terminal_metadata_failure_and_retention_do_not_leave_stuck_candidates(
    store: PostgresStore,
) -> None:
    poll_public_repositories_once(
        store,
        store.cfg,
        client=FakePollClient((_event("event-failed-metadata"),)),  # type: ignore[arg-type]
        owner="collector-failed-metadata",
    )
    with store.pool.connection() as conn:
        conn.execute(
            """
            UPDATE scan_jobs SET max_attempts = 1
            WHERE kind = 'enrich_repository_candidate'
            """
        )
    job = store.claim_job("metadata-failure", kinds=("enrich_repository_candidate",))
    assert job is not None

    store.fail_job(job, "metadata-failure", "synthetic terminal failure")

    candidate = store.list_discovery_candidates()[0]
    assert candidate["status"] == "unavailable"
    assert candidate["filter_reason"] == "metadata_job_failed"
    with store.pool.connection() as conn:
        conn.execute(
            "UPDATE discovery_candidates SET updated_at = now() - interval '31 days'"
        )
        conn.execute(
            """
            UPDATE scan_jobs SET updated_at = now() - interval '31 days'
            WHERE kind = 'enrich_repository_candidate'
            """
        )
        conn.execute(
            "UPDATE repositories SET last_seen = now() - interval '31 days'"
        )

    pruned = store.prune_discovery(retention_days=30)

    assert pruned == {"candidates": 1, "jobs": 1, "repositories": 1}


def test_skip_locked_never_claims_a_job_twice(store: PostgresStore) -> None:
    for index in range(32):
        store.enqueue_job(
            "fetch_blob",
            f"job-{index}",
            {"repo": "acme/demo", "path": str(index), "blob_sha": f"{index:040d}"},
        )

    def claim(index: int):
        return store.claim_job(f"worker-{index}")

    with ThreadPoolExecutor(max_workers=16) as executor:
        claimed = [job for job in executor.map(claim, range(32)) if job]

    ids = [job["id"] for job in claimed]
    assert len(ids) == 32
    assert len(ids) == len(set(ids))


def test_concurrent_finding_upsert_keeps_one_finding_and_location(
    store: PostgresStore,
) -> None:
    raw = "sk_live_" + "A" * 24

    def upsert(_: int) -> bool:
        finding = Finding(
            type_id="stripe_live",
            provider="Stripe",
            category="payment",
            risk="critical",
            secret_redacted="sk_l…AAAA",
            repo="acme/demo",
            path=".env",
            blob_sha="b" * 40,
            line=3,
            secret_raw=raw,
        )
        return store.upsert_finding(finding)[1]

    with ThreadPoolExecutor(max_workers=16) as executor:
        inserted = list(executor.map(upsert, range(64)))

    assert sum(inserted) == 1
    with store.pool.connection() as conn:
        counts = conn.execute(
            """
            SELECT
                (SELECT count(*) FROM findings) AS findings,
                (SELECT count(*) FROM finding_locations) AS locations,
                (SELECT count(*) FROM notification_outbox) AS notifications
            """
        ).fetchone()
        dumped = conn.execute(
            """
            SELECT concat_ws(' ', f.secret_hint, n.private_body, n.public_body) AS text
            FROM findings f JOIN notification_outbox n ON n.finding_id = f.id
            """
        ).fetchone()["text"]
    assert dict(counts) == {"findings": 1, "locations": 1, "notifications": 1}
    assert raw not in dumped


def test_notification_approval_and_claim_are_atomic(store: PostgresStore) -> None:
    finding = Finding(
        type_id="stripe_live",
        provider="Stripe",
        category="payment",
        risk="critical",
        secret_redacted="sk_l…AAAA",
        repo="acme/demo",
        path=".env",
        secret_raw="sk_live_" + "A" * 24,
    )
    store.upsert_finding(finding)
    notification_id = store.list_notifications()[0]["id"]

    with ThreadPoolExecutor(max_workers=8) as executor:
        approvals = list(
            executor.map(
                lambda index: store.approve_notification(notification_id, f"actor-{index}"),
                range(8),
            )
        )
    assert sum(approvals) == 1

    with ThreadPoolExecutor(max_workers=8) as executor:
        claims = [item for item in executor.map(lambda _: store.claim_notification(), range(8)) if item]
    assert len(claims) == 1
    assert claims[0]["id"] == notification_id


def test_admin_detail_exposes_all_safe_fields_but_never_raw_secret(
    store: PostgresStore,
) -> None:
    raw = "sk_live_" + "Z" * 24
    finding = Finding(
        type_id="stripe_live",
        provider="Stripe",
        category="payment",
        risk="critical",
        secret_redacted="sk_l…ZZZZ",
        repo="acme/demo",
        path=".env",
        commit="c" * 40,
        blob_sha="b" * 40,
        line=7,
        secret_raw=raw,
    )
    finding_id, _ = store.upsert_finding(finding)
    notification_id = store.list_notifications()[0]["id"]

    detail = store.get_finding(finding_id)
    draft = store.get_notification(notification_id)
    serialized = repr((detail, draft, store.list_jobs(), store.list_runs()))

    assert detail is not None
    assert detail["platform"] == "Stripe"
    assert detail["locations"][0]["path"] == ".env"
    assert draft is not None and draft["private_body"]
    assert raw not in serialized


def test_one_active_draft_aggregates_multiple_findings_per_repository(
    store: PostgresStore,
) -> None:
    first = Finding(
        "stripe_live", "Stripe", "payment", "critical", "oculto",
        repo="acme/demo", path=".env", secret_raw="sk_live_" + "A" * 24,
    )
    second = Finding(
        "postgres_uri", "PostgreSQL", "database", "critical", "oculto",
        repo="acme/demo", path="config.json",
        secret_raw="postgresql://user:password@db.invalid/app",
    )
    store.upsert_finding(first)
    store.upsert_finding(second)

    drafts = store.list_notifications()
    detail = store.get_notification(drafts[0]["id"])

    assert len(drafts) == 1
    assert detail is not None
    assert {item["type_id"] for item in detail["findings"]} == {
        "stripe_live", "postgres_uri"
    }
    assert ".env" in detail["private_body"]
    assert "config.json" in detail["private_body"]


def test_duplicate_schedule_finishes_the_empty_run(store: PostgresStore) -> None:
    _, first_created = schedule_repository(store, "acme/demo")
    second_run, second_created = schedule_repository(store, "acme/demo")

    assert first_created is True
    assert second_created is False
    runs = {item["id"]: item for item in store.list_runs()}
    assert runs[second_run]["status"] == "completed"
    assert runs[second_run]["jobs_created"] == 0


def test_rescan_after_success_does_not_create_an_empty_draft(
    store: PostgresStore,
) -> None:
    def finding() -> Finding:
        return Finding(
            "stripe_live", "Stripe", "payment", "critical", "oculto",
            repo="acme/demo", path=".env", secret_raw="sk_live_" + "R" * 24,
        )

    store.upsert_finding(finding())
    notification_id = store.list_notifications()[0]["id"]
    assert store.approve_notification(notification_id, "tester")
    assert store.claim_notification()["id"] == notification_id
    store.finish_notification(notification_id, status="sent", external_url="https://example.invalid")

    store.upsert_finding(finding())

    drafts = store.list_notifications()
    assert len(drafts) == 1
    assert drafts[0]["status"] == "sent"


def test_rejected_draft_is_stable_until_manual_requeue(store: PostgresStore) -> None:
    finding = Finding(
        "stripe_live", "Stripe", "payment", "critical", "oculto",
        repo="acme/demo", path=".env", secret_raw="sk_live_" + "S" * 24,
    )
    store.upsert_finding(finding)
    notification_id = store.list_notifications()[0]["id"]
    assert store.reject_notification(notification_id, "reviewer")

    finding.secret_raw = "sk_live_" + "S" * 24
    store.upsert_finding(finding)
    assert len(store.list_notifications()) == 1
    assert store.list_notifications()[0]["status"] == "rejected"

    assert store.requeue_notification(notification_id, "reviewer")
    assert store.list_notifications()[0]["status"] == "pending_review"


def test_discovery_window_ledger_prioritizes_head_and_tracks_reconciliation(
    store: PostgresStore,
) -> None:
    collector = "window-ledger-test"
    owner = "window-ledger-owner"
    checkpoint = store.claim_discovery_checkpoint(
        collector,
        owner,
        lease_seconds=120,
    )
    assert checkpoint is not None

    now = datetime.now(timezone.utc).replace(second=0, microsecond=0)
    windows = store.prepare_discovery_windows(
        collector,
        owner,
        cutoff=now - timedelta(minutes=10),
        head_end=now,
        window_seconds=60,
        limit=3,
    )

    assert [item["window_end"] for item in windows] == [
        now,
        now - timedelta(minutes=1),
        now - timedelta(minutes=2),
    ]

    store.persist_discovery_poll(
        collector,
        owner,
        [],
        etag="",
        newest_event_id="",
        poll_interval=60,
        gap_detected=False,
        window_results=[
            {
                "id": windows[0]["id"],
                "source_items_seen": 25,
                "repositories_seen": 25,
                "request_count": 1,
            }
        ],
        reconcile_seconds=900,
    )

    with store.pool.connection() as conn:
        row = conn.execute(
            """
            SELECT first_completed_at, reconciled_at, source_items_seen,
                   repositories_seen, request_count, next_attempt_at
            FROM discovery_windows
            WHERE id = %s
            """,
            (windows[0]["id"],),
        ).fetchone()
        total = conn.execute(
            """
            SELECT count(*) AS n
            FROM discovery_windows
            WHERE collector_key = %s
            """,
            (collector,),
        ).fetchone()["n"]

    assert total == 10
    assert row["first_completed_at"] is not None
    assert row["reconciled_at"] is None
    assert row["source_items_seen"] == 25
    assert row["repositories_seen"] == 25
    assert row["request_count"] == 1
    assert row["next_attempt_at"] > row["first_completed_at"]

def test_claim_job_by_id_targets_only_the_redis_message(store: PostgresStore) -> None:
    assert store.enqueue_job("fetch_blob", "redis-job-1", {"repo": "acme/one"}) is True
    assert store.enqueue_job("fetch_blob", "redis-job-2", {"repo": "acme/two"}) is True
    ids = {job["natural_key"]: job["id"] for job in store.list_jobs_after(0)}
    first = ids["redis-job-1"]
    second = ids["redis-job-2"]

    claimed = store.claim_job_by_id(second, "redis:blob-worker")

    assert claimed is not None
    assert claimed["id"] == second
    assert claimed["attempts"] == 1
    assert store.get_job_state(first)["status"] == "pending"
    assert store.get_job_state(second)["status"] == "running"
    assert store.complete_job(second, "redis:blob-worker") is True


def test_pipeline_event_index_is_idempotent(store: PostgresStore) -> None:
    fields = {
        "event_key": "job:42:completed",
        "event_type": "job.completed",
        "stage": "head",
        "job_id": "",
        "kind": "scan_history",
        "payload": '{"attempts": 1, "repository_ref": "abc123"}',
        "occurred_at": datetime.now(timezone.utc).isoformat(),
    }

    assert store.record_pipeline_event("1-0", fields) is True
    assert store.record_pipeline_event("2-0", fields) is False

    events = store.list_pipeline_events()
    assert len(events) == 1
    assert events[0]["event_key"] == "job:42:completed"
    assert events[0]["payload"]["attempts"] == 1


def test_redis_dispatcher_round_trip_is_bound_to_postgres_job(store: PostgresStore) -> None:
    cfg = Config.from_env()
    if not cfg.event_bus_enabled or not cfg.evidence_redis_password:
        pytest.skip("Redis de integração não configurado")

    prefix = f"secret-hunter-integration:{uuid4().hex}"
    bus = RedisStreamBus.from_config(
        replace(cfg, event_bus_prefix=prefix, event_bus_block_ms=10)
    )
    try:
        assert store.enqueue_job(
            "fetch_blob",
            "redis-postgres-round-trip",
            {"repo": "acme/demo", "token": "must-not-leak"},
        ) is True
        job_id = store.list_jobs_after(0, limit=1)[0]["id"]

        scanned, published = dispatch_jobs_once(store, bus, batch=10)
        assert (scanned, published) == (1, 1)

        messages = bus.read_new("blob", "integration-worker")
        assert len(messages) == 1
        entry_id, fields = messages[0]
        assert fields["job_id"] == str(job_id)
        assert "must-not-leak" not in fields["payload"]
        assert "[redacted]" in fields["payload"]

        claimed = store.claim_job_by_id(job_id, "redis:integration-worker")
        assert claimed is not None
        assert claimed["id"] == job_id
        assert store.complete_job(job_id, "redis:integration-worker") is True
        assert bus.ack_job("blob", entry_id) == 1

        dispatched = bus.read_events("integration-indexer", count=10)
        assert len(dispatched) == 1
        assert dispatched[0][1]["event_type"] == "job.dispatched"
        assert dispatched[0][1]["job_id"] == str(job_id)
        assert bus.ack_event(dispatched[0][0]) == 1
    finally:
        for key in bus.client.scan_iter(match=f"{prefix}:*"):
            bus.client.delete(key)
        bus.close()
