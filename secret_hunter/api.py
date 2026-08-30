"""API administrativa segura; nunca retorna segredo bruto ou contexto de código."""

from __future__ import annotations

import hmac
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, status
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from .ai_detection.catalog import AI_SECRET_SPECS
from .config import Config
from .event_bus import RedisStreamBus
from .patterns import SECRET_TYPES
from .scan_policy import AUTOMATIC_SECRET_TYPE_IDS
from .patterns import PATTERN_SET_ID
from .pipeline import schedule_ingest, schedule_repository, schedule_search
from .postgres import PostgresStore


@asynccontextmanager
async def lifespan(app: FastAPI):
    cfg = Config.from_env()
    app.state.cfg = cfg
    app.state.store = PostgresStore(cfg)
    try:
        yield
    finally:
        app.state.store.close()


app = FastAPI(
    title="Secret Hunter Admin API",
    version="0.4.0",
    docs_url=None,
    redoc_url=None,
    lifespan=lifespan,
)

_DASHBOARD_DIR = Path(__file__).with_name("dashboard")
_AI_DETECTOR_METADATA = {
    spec.type_id: {
        "detection_mode": spec.detection_mode,
        "search_signal": spec.search_literal.strip('"'),
        "docs_url": spec.docs_url,
    }
    for spec in AI_SECRET_SPECS
}


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = (
        "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
    )
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; "
        "img-src 'self' data:; connect-src 'self'; font-src 'self'; "
        "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; "
        "form-action 'self'"
    )
    if request.url.path in {"/", "/dashboard.js", "/dashboard.css"}:
        response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/", include_in_schema=False)
def dashboard() -> FileResponse:
    return FileResponse(_DASHBOARD_DIR / "index.html", media_type="text/html")


@app.get("/dashboard.css", include_in_schema=False)
def dashboard_css() -> FileResponse:
    return FileResponse(_DASHBOARD_DIR / "dashboard.css", media_type="text/css")


@app.get("/dashboard.js", include_in_schema=False)
def dashboard_js() -> FileResponse:
    return FileResponse(
        _DASHBOARD_DIR / "dashboard.js",
        media_type="application/javascript",
    )


class RepositoryJob(BaseModel):
    repository: str = Field(examples=["owner/repository"], min_length=3, max_length=200)
    trufflehog: bool = True


class IngestJob(BaseModel):
    adapter: Literal["tree", "manifest"] = "tree"
    source: str = Field(default="", max_length=500)


class CandidateAuthorization(BaseModel):
    authorization_reference: str = Field(min_length=8, max_length=500)
    trufflehog: bool = True


def _store(request: Request) -> PostgresStore:
    return request.app.state.store


def _admin(
    request: Request,
    authorization: str | None = Header(default=None),
) -> str:
    expected = request.app.state.cfg.admin_api_token
    if not expected:
        raise HTTPException(status_code=503, detail="token administrativo não configurado")
    supplied = ""
    if authorization and authorization.startswith("Bearer "):
        supplied = authorization.removeprefix("Bearer ").strip()
    if not supplied or not hmac.compare_digest(supplied, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="não autorizado",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return "api-admin"


@app.get("/health")
def health(store: PostgresStore = Depends(_store)) -> dict:
    return {"status": "ok" if store.health() else "error"}


@app.get("/stats")
def stats(
    _: str = Depends(_admin), store: PostgresStore = Depends(_store)
) -> dict:
    return store.stats()


@app.get("/findings")
def findings(
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    _: str = Depends(_admin),
    store: PostgresStore = Depends(_store),
) -> list[dict]:
    return store.list_findings(limit=limit, offset=offset)


@app.get("/findings/{finding_id}")
def finding_detail(
    finding_id: int,
    _: str = Depends(_admin),
    store: PostgresStore = Depends(_store),
) -> dict:
    item = store.get_finding(finding_id)
    if item is None:
        raise HTTPException(status_code=404, detail="achado não encontrado")
    return item


@app.get("/detectors")
def detectors(_: str = Depends(_admin)) -> list[dict]:
    return [
        {
            "type_id": detector.type_id,
            "name": detector.name,
            "platform": detector.provider,
            "category": detector.category,
            "risk": detector.risk,
            "description": detector.description,
            "validation": detector.verify_note,
            **_AI_DETECTOR_METADATA.get(detector.type_id, {}),
        }
        for detector in SECRET_TYPES
        if detector.type_id in AUTOMATIC_SECRET_TYPE_IDS
    ]


@app.get("/notifications")
def notifications(
    limit: int = Query(100, ge=1, le=500),
    _: str = Depends(_admin),
    store: PostgresStore = Depends(_store),
) -> list[dict]:
    return store.list_notifications(limit=limit)


@app.get("/notifications/{notification_id}")
def notification_detail(
    notification_id: int,
    _: str = Depends(_admin),
    store: PostgresStore = Depends(_store),
) -> dict:
    item = store.get_notification(notification_id)
    if item is None:
        raise HTTPException(status_code=404, detail="draft não encontrado")
    return item


@app.get("/jobs")
def jobs(
    limit: int = Query(100, ge=1, le=500),
    _: str = Depends(_admin),
    store: PostgresStore = Depends(_store),
) -> list[dict]:
    return store.list_jobs(limit=limit)


@app.get("/runs")
def runs(
    limit: int = Query(100, ge=1, le=500),
    _: str = Depends(_admin),
    store: PostgresStore = Depends(_store),
) -> list[dict]:
    return store.list_runs(limit=limit)


@app.get("/events")
def events(
    limit: int = Query(100, ge=1, le=500),
    _: str = Depends(_admin),
    store: PostgresStore = Depends(_store),
) -> list[dict]:
    return store.list_pipeline_events(limit=limit)


@app.get("/streams")
def streams(request: Request, _: str = Depends(_admin)) -> list[dict]:
    bus = RedisStreamBus.from_config(request.app.state.cfg)
    try:
        return bus.stream_stats()
    finally:
        bus.close()


@app.get("/candidates")
def candidates(
    candidate_status: Literal[
        "pending_metadata", "pending_review", "filtered", "unavailable",
        "scan_queued", "rejected",
    ] | None = Query(default=None, alias="status"),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    _: str = Depends(_admin),
    store: PostgresStore = Depends(_store),
) -> list[dict]:
    return store.list_discovery_candidates(
        status=candidate_status,
        limit=limit,
        offset=offset,
    )


@app.get("/candidates/{candidate_id}")
def candidate_detail(
    candidate_id: int,
    _: str = Depends(_admin),
    store: PostgresStore = Depends(_store),
) -> dict:
    item = store.get_discovery_candidate(candidate_id)
    if item is None:
        raise HTTPException(status_code=404, detail="candidato não encontrado")
    return item


@app.post("/candidates/{candidate_id}/authorize-scan", status_code=202)
def authorize_candidate_scan(
    candidate_id: int,
    body: CandidateAuthorization,
    x_actor: str = Header(default="api-admin", max_length=100),
    _: str = Depends(_admin),
    store: PostgresStore = Depends(_store),
) -> dict:
    result = store.authorize_candidate_scan(
        candidate_id,
        x_actor,
        body.authorization_reference,
        trufflehog=body.trufflehog,
        pattern_set_id=PATTERN_SET_ID,
    )
    if result is None:
        raise HTTPException(
            status_code=409,
            detail="candidato não está elegível e pendente de revisão",
        )
    return result


@app.post("/candidates/{candidate_id}/reject")
def reject_candidate(
    candidate_id: int,
    x_actor: str = Header(default="api-admin", max_length=100),
    _: str = Depends(_admin),
    store: PostgresStore = Depends(_store),
) -> dict:
    if not store.reject_discovery_candidate(candidate_id, x_actor):
        raise HTTPException(status_code=409, detail="candidato não está pendente")
    return {"rejected": True, "id": candidate_id}


@app.post("/jobs/search", status_code=202)
def enqueue_search(
    _: str = Depends(_admin), store: PostgresStore = Depends(_store)
) -> dict:
    try:
        run_id, created = schedule_search(store, store.cfg)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {"run_id": run_id, "jobs_created": created}


@app.post("/jobs/repository", status_code=202)
def enqueue_repository(
    body: RepositoryJob,
    _: str = Depends(_admin),
    store: PostgresStore = Depends(_store),
) -> dict:
    try:
        run_id, created = schedule_repository(
            store, body.repository, trufflehog=body.trufflehog
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {"run_id": run_id, "job_created": created}


@app.post("/jobs/ingest", status_code=202)
def enqueue_ingest(
    body: IngestJob,
    _: str = Depends(_admin),
    store: PostgresStore = Depends(_store),
) -> dict:
    try:
        run_id, discovered, created = schedule_ingest(
            store, store.cfg, adapter=body.adapter, source=body.source
        )
    except (OSError, ValueError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {
        "run_id": run_id,
        "files_discovered": discovered,
        "jobs_created": created,
    }


@app.post("/notifications/{notification_id}/approve")
def approve_notification(
    notification_id: int,
    x_actor: str = Header(default="api-admin", max_length=100),
    _: str = Depends(_admin),
    store: PostgresStore = Depends(_store),
) -> dict:
    if not store.approve_notification(notification_id, x_actor):
        raise HTTPException(status_code=409, detail="draft não está pendente")
    return {"approved": True, "id": notification_id}


@app.post("/notifications/{notification_id}/reject")
def reject_notification(
    notification_id: int,
    x_actor: str = Header(default="api-admin", max_length=100),
    _: str = Depends(_admin),
    store: PostgresStore = Depends(_store),
) -> dict:
    if not store.reject_notification(notification_id, x_actor):
        raise HTTPException(status_code=409, detail="draft não está pendente")
    return {"rejected": True, "id": notification_id}


@app.post("/notifications/{notification_id}/requeue")
def requeue_notification(
    notification_id: int,
    x_actor: str = Header(default="api-admin", max_length=100),
    _: str = Depends(_admin),
    store: PostgresStore = Depends(_store),
) -> dict:
    if not store.requeue_notification(notification_id, x_actor):
        raise HTTPException(
            status_code=409,
            detail="draft não está em estado recuperável",
        )
    return {"requeued": True, "id": notification_id}
