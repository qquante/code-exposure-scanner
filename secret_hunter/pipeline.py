"""Pipeline distribuído baseado em jobs idempotentes no PostgreSQL."""

from __future__ import annotations

import json
import hashlib
import os
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from typing import Any

from .config import Config
from .disclosure import GitHubDisclosureClient
from .event_bus import RedisStreamBus, STAGES, stage_for_job
from .discovery import (
    PUBLIC_REPOSITORIES_KEY,
    GitHubPublicEventsClient,
    evaluate_repository_metadata,
    RepositoryMetadata,
)
from .extract import Finding, dedupe, extract_from_text
from .github_search import SEARCH_QUERIES, GitHubClient
from .head_scan import HeadGitScanner
from .history_scan import (
    NativeGitScanner,
    normalize_github_repo,
    trufflehog_available,
    trufflehog_scan,
)
from .ingest import build_ingest_adapter, read_verified_text
from .postgres import PostgresStore
from .patterns import PATTERN_SET_ID
from .scan_policy import filter_crypto_wallet_findings, is_dependency_path
from .validate import validate as validate_finding


def _payload(job: dict[str, Any]) -> dict[str, Any]:
    value = job["payload"]
    return json.loads(value) if isinstance(value, str) else dict(value)


def schedule_search(store: PostgresStore, cfg: Config) -> tuple[int, int]:
    """Cria uma rodada; a janela torna o enqueue idempotente entre schedulers."""
    scope = cfg.search_scope.strip()
    if not scope and not cfg.allow_global_search:
        raise ValueError(
            "defina SH_SEARCH_SCOPE (org:, user: ou repo:) ou habilite "
            "SH_ALLOW_GLOBAL_SEARCH explicitamente"
        )
    if scope and not re.fullmatch(
        r"(?:org:[A-Za-z0-9_.-]+|user:[A-Za-z0-9_.-]+|repo:[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)",
        scope,
    ):
        raise ValueError("SH_SEARCH_SCOPE deve ser exatamente org:, user: ou repo:")
    selected_types = cfg.search_types or tuple(SEARCH_QUERIES)
    unknown_types = tuple(item for item in selected_types if item not in SEARCH_QUERIES)
    if unknown_types:
        raise ValueError(
            "SH_SEARCH_TYPES contém tipos desconhecidos: " + ", ".join(unknown_types)
        )
    run_scope = scope or "github.com/global-public-code"
    run_id = store.create_run("search", run_scope)
    window_seconds = max(cfg.search_window_hours, 1) * 3600
    bucket = int(datetime.now(timezone.utc).timestamp()) // window_seconds
    scope_key = hashlib.sha256(run_scope.encode("utf-8")).hexdigest()[:12]
    created = 0
    for type_id in selected_types:
        query = SEARCH_QUERIES[type_id]
        scoped_query = f"{query} {scope}".strip()
        created += int(
            store.enqueue_job(
                "github_search",
                f"github-search:{PATTERN_SET_ID}:{scope_key}:{type_id}:{bucket}",
                {"type_id": type_id, "query": scoped_query, "scope": run_scope},
                run_id=run_id,
                priority=10,
            )
        )
    if created == 0:
        store.complete_empty_run(run_id)
    return run_id, created


def schedule_repository(store: PostgresStore, repo: str, *, trufflehog: bool = True) -> tuple[int, bool]:
    canonical = normalize_github_repo(repo)
    if canonical is None:
        raise ValueError("use owner/repo ou https://github.com/owner/repo")
    run_id = store.create_run("history", canonical)
    day_bucket = datetime.now(timezone.utc).strftime("%Y%m%d")
    created = store.enqueue_job(
        "scan_history",
        f"history:{PATTERN_SET_ID}:{canonical}:{day_bucket}",
        {"repo": canonical, "trufflehog": bool(trufflehog), "mode": "history"},
        run_id=run_id,
        priority=20,
        max_attempts=3,
    )
    if not created:
        store.complete_empty_run(run_id)
    return run_id, created


def schedule_ingest(
    store: PostgresStore,
    cfg: Config,
    *,
    adapter: str | None = None,
    source: str | None = None,
) -> tuple[int | None, int, int]:
    """Enumera arquivos locais autorizados e cria jobs idempotentes sem guardar conteudo."""
    adapter_name = adapter or cfg.ingest_adapter
    source_name = cfg.ingest_source if source is None else source
    ingest_adapter = build_ingest_adapter(
        cfg.ingest_root,
        adapter_name,
        source_name,
        max_bytes=cfg.ingest_max_file_bytes,
        allow_symlinks=cfg.ingest_allow_symlinks,
    )
    run_scope = f"{adapter_name}:{source_name or '.'}"
    discovered = 0
    jobs: list[tuple[str, dict[str, Any]]] = []
    for candidate in ingest_adapter.iter_candidates():
        discovered += 1
        identity = "\0".join(
            (
                candidate.repository,
                candidate.source_path,
                candidate.logical_path,
                candidate.sha256,
            )
        )
        natural_hash = hashlib.sha256(identity.encode("utf-8")).hexdigest()
        jobs.append(
            (
                f"ingest:{PATTERN_SET_ID}:{natural_hash}",
                candidate.payload(),
            )
        )
    run_id, created = store.enqueue_ingest_batch(run_scope, jobs)
    return run_id, discovered, created


def _persist_findings(
    store: PostgresStore,
    cfg: Config,
    findings: list[Finding],
    *,
    run_id: int | None,
    job_id: int | None = None,
    stage: str = "finding",
    event_bus: RedisStreamBus | None = None,
) -> int:
    created = 0
    scoped_findings = filter_crypto_wallet_findings(dedupe(findings))
    scoped_ids = {id(finding) for finding in scoped_findings}
    for finding in findings:
        if id(finding) not in scoped_ids:
            finding.secret_raw = ""
    for finding in scoped_findings:
        try:
            canonical = normalize_github_repo(finding.repo)
            if (
                cfg.validate
                and canonical is not None
                and cfg.is_validation_authorized(canonical)
            ):
                validate_finding(finding, cfg)
            finding_id, inserted = store.upsert_finding(finding, run_id=run_id)
            created += int(inserted)
            if event_bus is not None:
                location_key = hashlib.sha256(
                    (
                        f"{finding_id}\0{finding.source}\0{finding.path}\0"
                        f"{finding.commit}\0{finding.blob_sha}\0{finding.line}"
                    ).encode("utf-8")
                ).hexdigest()[:20]
                event_bus.publish_event(
                    "finding.detected",
                    event_key=f"finding:{finding_id}:{location_key}",
                    stage=stage,
                    job_id=job_id,
                    kind="finding",
                    payload={
                        "finding_id": finding_id,
                        "repository": canonical or finding.repo,
                        "type_id": finding.type_id,
                        "platform": finding.provider,
                        "category": finding.category,
                        "risk": finding.risk,
                        "fingerprint": finding.fingerprint,
                        "validation_status": finding.validate_status or "not_checked",
                        "source": finding.source,
                        "path": finding.path,
                        "branch": finding.branch,
                        "commit_sha": finding.commit,
                        "blob_sha": finding.blob_sha,
                        "line": max(finding.line, 0),
                        "inserted": bool(inserted),
                    },
                )
        finally:
            # Strings Python são imutáveis: isto remove a referência, não promete zeroização.
            finding.secret_raw = ""
    return created


def _handle_search(
    store: PostgresStore,
    cfg: Config,
    job: dict[str, Any],
    *,
    event_bus: RedisStreamBus | None = None,
) -> None:
    payload = _payload(job)

    def reserve_search_request() -> None:
        # Chamado para CADA página; coordena todos os processos/containers.
        while True:
            delay = store.reserve_rate_slot(
                "github-code-search",
                cfg.search_requests_per_minute,
                60,
            )
            if delay <= 0:
                return
            time.sleep(min(delay + 0.1, 60))

    def reserve_metadata_request() -> None:
        while True:
            delay = store.reserve_rate_slot(
                "github-core-code-search-metadata",
                max(cfg.discovery_metadata_requests_per_hour, 1),
                3600,
            )
            if delay <= 0:
                return
            time.sleep(min(delay + 0.1, 60))

    client = GitHubClient(cfg, before_search_request=reserve_search_request)
    try:
        items = client.search_code(str(payload["query"]))
    finally:
        client.close()

    metadata_client = GitHubPublicEventsClient(cfg)
    metadata_cache: dict[str, RepositoryMetadata | None] = {}
    eligible_repositories: set[str] = set()
    queued = 0
    try:
        for item in items:
            repo = item.get("repository", {}).get("full_name", "")
            path = item.get("path", "")
            blob_sha = item.get("sha", "")
            if is_dependency_path(path):
                continue
            canonical = normalize_github_repo(repo)
            if canonical is None or not path or not blob_sha:
                continue
            if canonical not in metadata_cache:
                reserve_metadata_request()
                metadata_cache[canonical] = metadata_client.get_repository(canonical)
            metadata = metadata_cache[canonical]
            if metadata is None:
                continue
            eligible, _reason = evaluate_repository_metadata(
                metadata,
                metadata.created_at or "",
                cfg,
            )
            if not eligible:
                continue
            eligible_repositories.add(canonical)
            queued += int(
                store.enqueue_job(
                    "fetch_blob",
                    f"blob:{PATTERN_SET_ID}:{canonical}:{blob_sha}",
                    {
                        "repo": canonical,
                        "path": path,
                        "blob_sha": blob_sha,
                        "branch": metadata.default_branch,
                        "matched_type": payload.get("type_id", ""),
                    },
                    run_id=job.get("run_id"),
                    priority=5,
                )
            )
    finally:
        metadata_client.close()

    print(
        f"code-search: itens={len(items)} repos={len(metadata_cache)} "
        f"elegiveis={len(eligible_repositories)} blobs={queued}"
    )


def _handle_blob(
    store: PostgresStore,
    cfg: Config,
    job: dict[str, Any],
    *,
    event_bus: RedisStreamBus | None = None,
) -> None:
    payload = _payload(job)
    repo = str(payload["repo"])
    path = str(payload["path"])
    if is_dependency_path(path):
        return
    client = GitHubClient(cfg)
    try:
        text = client.fetch_blob(repo, str(payload["blob_sha"]))
    finally:
        client.close()
    if text is None:
        raise RuntimeError("blob indisponível ou acima do limite")
    findings = filter_crypto_wallet_findings(
        extract_from_text(text, repo=repo, path=path, source="code")
    )
    for finding in findings:
        finding.blob_sha = str(payload["blob_sha"])
        finding.branch = str(payload.get("branch") or "")
    _persist_findings(
        store,
        cfg,
        findings,
        run_id=job.get("run_id"),
        job_id=int(job.get("id") or 0),
        stage=stage_for_job(job),
        event_bus=event_bus,
    )


def _handle_history(
    store: PostgresStore,
    cfg: Config,
    job: dict[str, Any],
    *,
    event_bus: RedisStreamBus | None = None,
) -> None:
    payload = _payload(job)
    repo = str(payload["repo"])
    url = f"https://github.com/{repo}"
    mode = str(payload.get("mode") or "history")
    if mode == "head":
        result = HeadGitScanner(cfg).scan_repo(url)
        findings = filter_crypto_wallet_findings(result.findings)
        expand_history = bool(findings)
        repository_ref = hashlib.sha256(repo.encode("utf-8")).hexdigest()[:12]
        print(
            f"head-scan repository_ref={repository_ref} files={result.files_scanned} "
            f"bytes={result.bytes_scanned} findings={len(findings)} "
            f"truncated={result.truncated} history={expand_history}"
        )
        _persist_findings(
            store,
            cfg,
            findings,
            run_id=job.get("run_id"),
            job_id=int(job.get("id") or 0),
            stage=stage_for_job(job),
            event_bus=event_bus,
        )
        if expand_history:
            natural_key = str(payload.get("history_natural_key") or "")
            if not natural_key:
                repo_key = hashlib.sha256(repo.encode("utf-8")).hexdigest()[:16]
                natural_key = f"head-signal-history:{PATTERN_SET_ID}:{repo_key}"
            store.enqueue_job(
                "scan_history",
                natural_key,
                {
                    "repo": repo,
                    "trufflehog": bool(payload.get("trufflehog", True)),
                    "candidate_id": payload.get("candidate_id"),
                    "mode": "history",
                    "trigger": "head_crypto_signal",
                },
                run_id=job.get("run_id"),
                priority=5,
                max_attempts=3,
            )
        return
    if mode != "history":
        raise ValueError(f"modo de scan desconhecido: {mode}")
    if payload.get("trufflehog") and trufflehog_available():
        findings = trufflehog_scan(url, cfg)
    else:
        findings = NativeGitScanner(cfg).scan_repo(url)
    findings = filter_crypto_wallet_findings(findings)
    _persist_findings(
        store,
        cfg,
        findings,
        run_id=job.get("run_id"),
        job_id=int(job.get("id") or 0),
        stage=stage_for_job(job),
        event_bus=event_bus,
    )


def _handle_ingested_file(
    store: PostgresStore,
    cfg: Config,
    job: dict[str, Any],
    *,
    event_bus: RedisStreamBus | None = None,
) -> None:
    payload = _payload(job)
    logical_path = str(payload["logical_path"])
    if is_dependency_path(logical_path):
        return
    text = read_verified_text(
        cfg.ingest_root,
        str(payload["source_path"]),
        str(payload["sha256"]),
        max_bytes=cfg.ingest_max_file_bytes,
        allow_symlinks=cfg.ingest_allow_symlinks,
    )
    findings = extract_from_text(
        text,
        repo=str(payload["repository"]),
        path=logical_path,
        source="ingest",
    )
    for finding in findings:
        finding.branch = str(payload.get("branch", ""))
        finding.commit = str(payload.get("commit_sha", ""))
    _persist_findings(
        store,
        cfg,
        findings,
        run_id=job.get("run_id"),
        job_id=int(job.get("id") or 0),
        stage=stage_for_job(job),
        event_bus=event_bus,
    )


def _selected_for_head_scan(github_repository_id: int, sample_percent: int) -> bool:
    bounded_percent = min(max(sample_percent, 0), 100)
    return github_repository_id % 100 < bounded_percent


def _handle_repository_candidate(
    store: PostgresStore,
    cfg: Config,
    job: dict[str, Any],
    *,
    event_bus: RedisStreamBus | None = None,
) -> None:
    payload = _payload(job)
    candidate_id = int(payload["candidate_id"])
    candidate = store.get_discovery_candidate(candidate_id)
    if candidate is None:
        raise ValueError("candidato de descoberta não encontrado")
    # Um operador pode rejeitar enquanto o job aguardava; nesse caso é no-op.
    if candidate["status"] != "pending_metadata":
        return
    raw_metadata = payload.get("metadata")
    if isinstance(raw_metadata, dict):
        try:
            metadata = RepositoryMetadata(**raw_metadata)
        except (TypeError, ValueError):
            store.mark_candidate_unavailable(candidate_id, "invalid_search_metadata")
            return
    else:
        while True:
            delay = store.reserve_rate_slot(
                "github-core-discovery-metadata",
                max(cfg.discovery_metadata_requests_per_hour, 1),
                3600,
            )
            if delay <= 0:
                break
            time.sleep(min(delay + 0.1, 60))
        client = GitHubPublicEventsClient(cfg)
        try:
            metadata = client.get_repository(str(candidate["repository"]))
        finally:
            client.close()
    if metadata is None:
        store.mark_candidate_unavailable(candidate_id, "repository_not_found")
        return
    if metadata.github_repository_id != int(candidate["github_repository_id"]):
        store.mark_candidate_unavailable(candidate_id, "repository_identity_mismatch")
        return
    eligible, reason = evaluate_repository_metadata(
        metadata,
        str(metadata.created_at or candidate["event_created_at"]),
        cfg,
    )
    completed = store.complete_candidate_metadata(
        candidate_id,
        metadata.payload(),
        eligible=eligible,
        filter_reason=reason,
    )
    selected_for_head_scan = _selected_for_head_scan(
        metadata.github_repository_id,
        cfg.discovery_head_scan_sample_percent,
    )
    if (
        completed
        and eligible
        and cfg.discovery_auto_queue_scans
        and selected_for_head_scan
    ):
        store.queue_candidate_scan_automatically(
            candidate_id,
            trufflehog=True,
            pattern_set_id=PATTERN_SET_ID,
            queue_lane=str(payload.get("queue_lane") or "") or None,
        )


def handle_job(
    store: PostgresStore,
    cfg: Config,
    job: dict[str, Any],
    *,
    event_bus: RedisStreamBus | None = None,
) -> None:
    handlers = {
        "github_search": _handle_search,
        "fetch_blob": _handle_blob,
        "scan_history": _handle_history,
        "scan_ingested_file": _handle_ingested_file,
        "enrich_repository_candidate": _handle_repository_candidate,
    }
    handler = handlers.get(str(job["kind"]))
    if handler is None:
        raise ValueError(f"tipo de job desconhecido: {job['kind']}")
    handler(store, cfg, job, event_bus=event_bus)


def run_worker(
    cfg: Config,
    *,
    concurrency: int | None = None,
    once: bool = False,
    kinds: tuple[str, ...] | None = None,
) -> None:
    workers = max(1, concurrency or cfg.worker_concurrency)
    stop = threading.Event()

    def loop(slot: int) -> None:
        store = PostgresStore(cfg)
        worker = f"{cfg.worker_name}:{os.getpid()}:{slot}"
        try:
            while not stop.is_set():
                job = store.claim_job(worker, kinds=kinds)
                if job is None:
                    if once:
                        return
                    stop.wait(cfg.worker_poll_seconds)
                    continue
                heartbeat_stop = threading.Event()

                def heartbeat() -> None:
                    interval = max(cfg.job_lease_seconds / 3, 5)
                    while not heartbeat_stop.wait(interval):
                        try:
                            if not store.extend_job_lease(int(job["id"]), worker):
                                return
                        except Exception:
                            # O lease expirará e o job idempotente poderá ser retomado.
                            return

                heartbeat_thread = threading.Thread(
                    target=heartbeat,
                    name=f"lease-{job['id']}",
                    daemon=True,
                )
                heartbeat_thread.start()
                try:
                    handle_job(store, cfg, job)
                except Exception as exc:
                    store.fail_job(job, worker, f"{type(exc).__name__}: {exc}")
                else:
                    store.complete_job(int(job["id"]), worker)
                finally:
                    heartbeat_stop.set()
                    heartbeat_thread.join(timeout=2)
        finally:
            store.close()

    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="scan-worker") as executor:
        futures = [executor.submit(loop, slot) for slot in range(workers)]
        try:
            for future in futures:
                future.result()
        except KeyboardInterrupt:
            stop.set()
            for future in futures:
                future.result()


def dispatch_jobs_once(
    store: PostgresStore,
    bus: RedisStreamBus,
    *,
    batch: int = 500,
) -> tuple[int, int]:
    """Move o log monotônico de jobs PostgreSQL para streams Redis por estágio."""
    cursor = bus.dispatcher_cursor()
    jobs = store.list_jobs_after(cursor, limit=batch)
    published = 0
    for job in jobs:
        job_id = int(job["id"])
        if str(job.get("status") or "") in {"pending", "running"}:
            entry_id, created = bus.publish_job(job)
            stage = stage_for_job(job)
            bus.publish_event(
                "job.dispatched",
                event_key=f"job:{job_id}:dispatched",
                stage=stage,
                job_id=job_id,
                kind=str(job.get("kind") or ""),
                payload={
                    "redis_entry_id": entry_id,
                    "created": created,
                    "priority": int(job.get("priority") or 0),
                    "status": str(job.get("status") or "pending"),
                },
            )
            published += int(created)
        bus.advance_dispatcher_cursor(job_id)
    return len(jobs), published


def run_redis_dispatcher(cfg: Config, *, once: bool = False) -> None:
    store = PostgresStore(cfg)
    bus = RedisStreamBus.from_config(cfg)
    try:
        while True:
            scanned, published = dispatch_jobs_once(
                store,
                bus,
                batch=cfg.event_bus_dispatch_batch,
            )
            if scanned:
                print(f"redis-dispatcher: lidos={scanned} publicados={published}")
            if once:
                return
            if scanned < cfg.event_bus_dispatch_batch:
                time.sleep(cfg.event_bus_dispatch_interval_ms / 1000)
    finally:
        bus.close()
        store.close()


def _process_redis_job_message(
    store: PostgresStore,
    cfg: Config,
    bus: RedisStreamBus,
    *,
    stage: str,
    consumer: str,
    message_id: str,
    fields: dict[str, str],
) -> str:
    try:
        job_id = int(fields["job_id"])
        advertised = {
            "kind": fields.get("kind", ""),
            "payload": fields.get("payload", "{}"),
        }
        if fields.get("stage") != stage or stage_for_job(advertised) != stage:
            raise ValueError("mensagem roteada para stage incorreto")
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        bus.publish_dead_letter(
            stage=stage,
            message_id=message_id,
            fields=fields,
            error=f"invalid_message: {exc}",
        )
        bus.ack_job(stage, message_id)
        return "dead_letter"

    worker = f"redis:{consumer}"
    job = store.claim_job_by_id(job_id, worker)
    if job is None:
        state = store.get_job_state(job_id)
        if state is None:
            bus.publish_dead_letter(
                stage=stage,
                message_id=message_id,
                fields=fields,
                error="job_not_found",
            )
            bus.ack_job(stage, message_id)
            return "dead_letter"
        status = str(state.get("status") or "")
        if status in {"completed", "failed"}:
            bus.publish_event(
                f"job.{status}",
                event_key=f"job:{job_id}:{status}",
                stage=stage,
                job_id=job_id,
                kind=str(state.get("kind") or fields.get("kind") or ""),
                payload={"reconciled": True, "attempts": int(state.get("attempts") or 0)},
            )
            bus.ack_job(stage, message_id)
            return status
        return "deferred"

    heartbeat_stop = threading.Event()

    def heartbeat() -> None:
        interval = max(cfg.job_lease_seconds / 3, 5)
        while not heartbeat_stop.wait(interval):
            try:
                if not store.extend_job_lease(job_id, worker):
                    return
            except Exception:
                return

    heartbeat_thread = threading.Thread(
        target=heartbeat,
        name=f"redis-lease-{job_id}",
        daemon=True,
    )
    heartbeat_thread.start()
    try:
        handle_job(store, cfg, job, event_bus=bus)
    except Exception as exc:
        terminal = int(job["attempts"]) >= int(job["max_attempts"])
        store.fail_job(job, worker, f"{type(exc).__name__}: {exc}")
        event_type = "job.failed" if terminal else "job.retry"
        bus.publish_event(
            event_type,
            event_key=(
                f"job:{job_id}:failed"
                if terminal
                else f"job:{job_id}:retry:{int(job['attempts'])}"
            ),
            stage=stage,
            job_id=job_id,
            kind=str(job.get("kind") or ""),
            payload={
                "attempts": int(job["attempts"]),
                "max_attempts": int(job["max_attempts"]),
                "error_type": type(exc).__name__,
            },
        )
        if terminal:
            bus.ack_job(stage, message_id)
            return "failed"
        return "retry"
    else:
        if not store.complete_job(job_id, worker):
            return "deferred"
        bus.publish_event(
            "job.completed",
            event_key=f"job:{job_id}:completed",
            stage=stage,
            job_id=job_id,
            kind=str(job.get("kind") or ""),
            payload={"attempts": int(job["attempts"])},
        )
        bus.ack_job(stage, message_id)
        return "completed"
    finally:
        heartbeat_stop.set()
        heartbeat_thread.join(timeout=2)


def run_redis_stage_worker(
    cfg: Config,
    *,
    stage: str,
    once: bool = False,
) -> None:
    if stage not in STAGES:
        raise ValueError(f"stage Redis inválido: {stage}")
    store = PostgresStore(cfg)
    bus = RedisStreamBus.from_config(cfg)
    consumer = f"{cfg.worker_name}:{os.getpid()}:{stage}"
    try:
        while True:
            messages = bus.reclaim_idle(stage, consumer, count=1)
            if not messages:
                messages = bus.read_new(stage, consumer, count=1)
            if not messages:
                if once:
                    return
                continue
            for message_id, fields in messages:
                result = _process_redis_job_message(
                    store,
                    cfg,
                    bus,
                    stage=stage,
                    consumer=consumer,
                    message_id=message_id,
                    fields=fields,
                )
                print(
                    f"redis-worker stage={stage} message={message_id} "
                    f"job={fields.get('job_id', '')} result={result}"
                )
    finally:
        bus.close()
        store.close()


def _index_pipeline_event(
    store: PostgresStore,
    bus: RedisStreamBus,
    *,
    message_id: str,
    fields: dict[str, str],
) -> str:
    try:
        store.record_pipeline_event(message_id, fields)
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        bus.publish_dead_letter(
            stage="events",
            message_id=message_id,
            fields=fields,
            error=f"invalid_event: {exc}",
        )
        bus.ack_event(message_id)
        return "dead_letter"
    bus.ack_event(message_id)
    return "indexed"


def run_event_indexer(cfg: Config, *, once: bool = False) -> None:
    store = PostgresStore(cfg)
    bus = RedisStreamBus.from_config(cfg)
    consumer = f"{cfg.worker_name}:{os.getpid()}:event-indexer"
    try:
        while True:
            messages = bus.reclaim_events(consumer, count=25)
            if not messages:
                messages = bus.read_events(consumer, count=25)
            if not messages:
                if once:
                    return
                continue
            for message_id, fields in messages:
                _index_pipeline_event(
                    store,
                    bus,
                    message_id=message_id,
                    fields=fields,
                )
    finally:
        bus.close()
        store.close()


def run_notification_worker(cfg: Config, *, once: bool = False) -> None:
    store = PostgresStore(cfg)
    client = GitHubDisclosureClient(cfg)
    try:
        while True:
            item = store.claim_notification()
            if item is None:
                if once:
                    return
                time.sleep(cfg.worker_poll_seconds)
                continue
            status, external_url, error = client.deliver(
                str(item["repository"]),
                str(item["title"]),
                str(item["private_body"]),
                str(item["public_body"]),
            )
            store.finish_notification(
                int(item["id"]), status=status, external_url=external_url, error=error
            )
    finally:
        client.close()
        store.close()


def run_scheduler(cfg: Config, *, once: bool = False) -> None:
    store = PostgresStore(cfg)
    try:
        while True:
            schedule_search(store, cfg)
            if once:
                return
            time.sleep(max(cfg.search_window_hours, 1) * 3600)
    finally:
        store.close()


def run_ingest_watcher(cfg: Config, *, once: bool = False) -> None:
    """Reenumera o drop-zone; natural keys impedem reprocessamento concorrente."""
    store = PostgresStore(cfg)
    try:
        while True:
            schedule_ingest(store, cfg)
            if once:
                return
            time.sleep(max(cfg.ingest_poll_seconds, 5))
    finally:
        store.close()


def poll_public_repositories_once(
    store: PostgresStore,
    cfg: Config,
    *,
    client: GitHubPublicEventsClient | None = None,
    owner: str | None = None,
) -> dict[str, Any]:
    """Processa o head primeiro e usa o horizonte configurado só para recuperação."""
    lease_owner = owner or f"{cfg.worker_name}:{os.getpid()}:discovery"
    checkpoint = store.claim_discovery_checkpoint(
        PUBLIC_REPOSITORIES_KEY,
        lease_owner,
        lease_seconds=cfg.discovery_lease_seconds,
    )
    if checkpoint is None:
        return {
            "claimed": False,
            "events_seen": 0,
            "source_items_seen": 0,
            "repository_events": 0,
            "candidates_created": 0,
        }

    step = max(cfg.discovery_window_seconds, 10)
    now = datetime.now(timezone.utc)
    safe_now = now - timedelta(seconds=max(cfg.discovery_head_delay_seconds, 0))
    head_epoch = int(safe_now.timestamp()) // step * step
    cutoff_epoch = (
        int(
            (
                now
                - timedelta(hours=max(cfg.discovery_max_event_age_hours, 1))
            ).timestamp()
        )
        // step
        * step
    )
    head_end = datetime.fromtimestamp(head_epoch, timezone.utc)
    cutoff = datetime.fromtimestamp(cutoff_epoch, timezone.utc)

    def reserve_search_slot() -> float:
        return store.reserve_rate_slot(
            "github-search-discovery",
            max(cfg.discovery_search_requests_per_minute, 1),
            60,
        )

    api = client or GitHubPublicEventsClient(
        cfg,
        before_search_request=reserve_search_slot,
    )
    owns_client = client is None
    try:
        windows = store.prepare_discovery_windows(
            PUBLIC_REPOSITORIES_KEY,
            lease_owner,
            cutoff=cutoff,
            head_end=head_end,
            window_seconds=step,
            limit=cfg.discovery_windows_per_poll,
        )
        by_id: dict[int, Any] = {}
        window_results: list[dict[str, Any]] = []
        source_items_seen = 0
        search_requests = 0
        failed_windows = 0
        highest_repository_id = 0

        for window in windows:
            try:
                poll = api.search_repository_window(
                    window_start=window["window_start"],
                    window_end=window["window_end"],
                )
            except Exception as exc:
                failed_windows += 1
                window_results.append(
                    {
                        "id": window["id"],
                        "error": f"{type(exc).__name__}: {exc}",
                        "retry_seconds": cfg.discovery_poll_seconds,
                    }
                )
                continue
            source_items_seen += poll.source_items_seen
            search_requests += poll.request_count
            for item in poll.repositories:
                by_id[item.github_repository_id] = item
                highest_repository_id = max(
                    highest_repository_id, item.github_repository_id
                )
            window_results.append(
                {
                    "id": window["id"],
                    "source_items_seen": poll.source_items_seen,
                    "repositories_seen": len(poll.repositories),
                    "request_count": poll.request_count,
                }
            )

        searched = sorted(
            by_id.values(),
            key=lambda item: (
                item.event_created_at,
                item.github_repository_id,
            ),
            reverse=True,
        )
        known_ids = store.existing_discovery_repository_ids(
            [item.github_repository_id for item in searched]
        )
        candidates = [
            item
            for item in searched
            if item.github_repository_id not in known_ids
        ]
        created = store.persist_discovery_poll(
            PUBLIC_REPOSITORIES_KEY,
            lease_owner,
            [candidate.payload() for candidate in candidates],
            etag="",
            newest_event_id=str(
                highest_repository_id
                or checkpoint.get("last_event_id")
                or ""
            ),
            poll_interval=max(cfg.discovery_poll_seconds, 5),
            gap_detected=failed_windows > 0,
            window_results=window_results,
            reconcile_seconds=cfg.discovery_reconcile_seconds,
        )
        pruned = store.prune_discovery(
            retention_days=cfg.discovery_retention_days
        )
        return {
            "claimed": True,
            "events_seen": source_items_seen,
            "source_items_seen": source_items_seen,
            "repository_events": len(candidates),
            "candidates_created": created,
            "windows_processed": len(windows) - failed_windows,
            "windows_failed": failed_windows,
            "search_requests": search_requests,
            "checkpoint_gap": failed_windows > 0,
            "repository_cursor": str(
                highest_repository_id
                or checkpoint.get("last_event_id")
                or ""
            ),
            "head_at": head_end.isoformat(),
            "next_poll_seconds": max(cfg.discovery_poll_seconds, 5),
            "pruned": pruned,
        }
    except Exception as exc:
        store.fail_discovery_checkpoint(
            PUBLIC_REPOSITORIES_KEY,
            lease_owner,
            f"{type(exc).__name__}: {exc}",
            retry_seconds=cfg.discovery_poll_seconds,
        )
        raise
    finally:
        if owns_client:
            api.close()


def run_discovery_watcher(cfg: Config, *, once: bool = False) -> None:
    """Prioriza a janela recente e enfileira automaticamente candidatos elegíveis."""
    store = PostgresStore(cfg)
    try:
        while True:
            try:
                result = poll_public_repositories_once(store, cfg)
                if result.get("claimed"):
                    print(
                        "discovery: "
                        f"vistos={result['source_items_seen']} "
                        f"repos={result.get('repository_events', 0)} "
                        f"novos={result['candidates_created']} "
                        f"janelas={result.get('windows_processed', 0)} "
                        f"falhas={result.get('windows_failed', 0)} "
                        f"requests={result.get('search_requests', 0)} "
                        f"head={result.get('head_at', '')}"
                    )
            except Exception as exc:
                if once:
                    raise
                print(f"[discovery-error] {type(exc).__name__}: {exc}")
            if once:
                return
            time.sleep(min(max(cfg.discovery_poll_seconds, 5), 60))
    finally:
        store.close()
