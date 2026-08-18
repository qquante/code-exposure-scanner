from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from secret_hunter.queue_policy import (
    BACKFILL_HEAD_LANE,
    LIVE_HEAD_LANE,
    classify_head_lane,
    stage_for_job,
)


def _metadata_job(payload: dict) -> dict:
    return {"kind": "enrich_repository_candidate", "payload": payload}


def _job(payload: dict) -> dict:
    return {"kind": "scan_history", "payload": payload}


def test_head_jobs_route_to_explicit_live_and_backfill_lanes() -> None:
    assert stage_for_job(_job({"mode": "head", "queue_lane": LIVE_HEAD_LANE})) == "head-live"
    assert (
        stage_for_job(_job({"mode": "head", "queue_lane": BACKFILL_HEAD_LANE}))
        == "head-backfill"
    )


def test_metadata_jobs_use_the_same_explicit_lanes() -> None:
    assert stage_for_job(_metadata_job({"queue_lane": LIVE_HEAD_LANE})) == "metadata-live"
    assert (
        stage_for_job(_metadata_job({"queue_lane": BACKFILL_HEAD_LANE}))
        == "metadata-backfill"
    )


def test_head_job_without_lane_keeps_legacy_stream_for_backlog_migration() -> None:
    assert stage_for_job(_job({"mode": "head"})) == "head"


def test_history_job_never_uses_head_lanes() -> None:
    assert stage_for_job(_job({"mode": "history", "queue_lane": LIVE_HEAD_LANE})) == "history"


def test_unknown_head_lane_is_rejected() -> None:
    with pytest.raises(ValueError, match="lane HEAD desconhecida"):
        stage_for_job(_job({"mode": "head", "queue_lane": "typo"}))


def test_classify_head_lane_uses_repository_event_age() -> None:
    now = datetime(2026, 8, 17, 23, 0, tzinfo=timezone.utc)

    assert classify_head_lane(
        (now - timedelta(minutes=19)).isoformat(),
        live_max_age_minutes=20,
        now=now,
    ) == LIVE_HEAD_LANE
    assert classify_head_lane(
        (now - timedelta(minutes=21)).isoformat(),
        live_max_age_minutes=20,
        now=now,
    ) == BACKFILL_HEAD_LANE


def test_invalid_event_timestamp_is_backfill_not_live() -> None:
    assert (
        classify_head_lane("invalid", live_max_age_minutes=20)
        == BACKFILL_HEAD_LANE
    )
