"""Política única de roteamento dos jobs distribuídos.

O PostgreSQL decide a lane no enqueue; o Redis apenas transporta a referência.
Jobs HEAD antigos, criados antes das lanes explícitas, permanecem no estágio
``head`` para que o backlog existente seja drenado sem reset de dados.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any


LIVE_HEAD_LANE = "live"
BACKFILL_HEAD_LANE = "backfill"
HEAD_LANES = (LIVE_HEAD_LANE, BACKFILL_HEAD_LANE)

# ``head`` é mantido temporariamente como lane de compatibilidade do backlog.
STAGES = (
    "metadata-live",
    "metadata-backfill",
    "metadata",
    "search",
    "blob",
    "head-live",
    "head-backfill",
    "head",
    "history",
    "ingest",
)


def job_payload(job: dict[str, Any]) -> dict[str, Any]:
    value = job.get("payload") or {}
    if isinstance(value, str):
        value = json.loads(value)
    return dict(value) if isinstance(value, dict) else {}


def classify_head_lane(
    event_created_at: Any,
    *,
    live_max_age_minutes: int,
    now: datetime | None = None,
) -> str:
    """Classifica pelo horário de criação real, nunca pela ordem de chegada."""
    try:
        event_time = datetime.fromisoformat(
            str(event_created_at).replace("Z", "+00:00")
        )
    except (TypeError, ValueError):
        return BACKFILL_HEAD_LANE
    if event_time.tzinfo is None:
        event_time = event_time.replace(tzinfo=timezone.utc)
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    age_seconds = max(
        (current - event_time.astimezone(timezone.utc)).total_seconds(), 0
    )
    live_seconds = max(int(live_max_age_minutes), 1) * 60
    return LIVE_HEAD_LANE if age_seconds <= live_seconds else BACKFILL_HEAD_LANE


def _stage_for_lane(stage: str, payload: dict[str, Any]) -> str:
    lane = str(payload.get("queue_lane") or "")
    if not lane:
        return stage
    if lane not in HEAD_LANES:
        raise ValueError(f"lane {stage.upper()} desconhecida: {lane}")
    return f"{stage}-{lane}"


def stage_for_job(job: dict[str, Any]) -> str:
    """Retorna o único estágio Redis responsável pelo job PostgreSQL."""
    kind = str(job.get("kind") or "")
    if kind == "enrich_repository_candidate":
        return _stage_for_lane("metadata", job_payload(job))
    if kind == "github_search":
        return "search"
    if kind == "fetch_blob":
        return "blob"
    if kind == "scan_ingested_file":
        return "ingest"
    if kind == "scan_history":
        payload = job_payload(job)
        if str(payload.get("mode") or "history") != "head":
            return "history"
        return _stage_for_lane("head", payload)
    raise ValueError(f"job sem rota Redis: {kind}")
