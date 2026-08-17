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


def _filter_findings_by_category(
    findings: list[Finding],
    categories: tuple[str, ...],
) -> list[Finding]:
    allowed = {item.strip().lower() for item in categories if item.strip()}
    if "*" in allowed:
        return findings
    return [finding for finding in findings if finding.category.lower() in allowed]


def _persist_findings(
    store: PostgresStore,
    cfg: Config,
    findings: list[Finding],
    *,
    run_id: int | None,
) -> int:
    created = 0
    for finding in dedupe(findings):
        try:
            canonical = normalize_github_repo(finding.repo)
            if (
                cfg.validate
                and canonical is not None
                and cfg.is_validation_authorized(canonical)
            ):
                validate_finding(finding, cfg)
            _, inserted = store.upsert_finding(finding, run_id=run_id)
            created += int(inserted)
        finally:
            # Strings Python são imutáveis: isto remove a referência, não promete zeroização.
            finding.secret_raw = ""
    return created


def _handle_search(store: PostgresStore, cfg: Config, job: dict[str, Any]) -> None:
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


def _handle_blob(store: PostgresStore, cfg: Config, job: dict[str, Any]) -> None:
    payload = _payload(job)
    repo = str(payload["repo"])
    client = GitHubClient(cfg)
    try:
        text = client.fetch_blob(repo, str(payload["blob_sha"]))
    finally:
        client.close()
    if text is None:
        raise RuntimeError("blob indisponível ou acima do limite")
    findings = extract_from_text(text, repo=repo, path=str(payload["path"]), source="code")
    if cfg.search_types and str(payload.get("matched_type") or "") in cfg.search_types:
        findings = _filter_findings_by_category(
            findings,
            cfg.discovery_head_trigger_categories,
        )
    for finding in findings:
        finding.blob_sha = str(payload["blob_sha"])
    _persist_findings(store, cfg, findings, run_id=job.get("run_id"))


def _handle_history(store: PostgresStore, cfg: Config, job: dict[str, Any]) -> None:
    payload = _payload(job)
    repo = str(payload["repo"])
    url = f"https://github.com/{repo}"
    mode = str(payload.get("mode") or "history")
    if mode == "head":
        result = HeadGitScanner(cfg).scan_repo(url)
        detected_findings = list(result.findings)
        trigger_categories = {
            item.strip().lower()
            for item in cfg.discovery_head_trigger_categories
            if item.strip()
        }
        findings = _filter_findings_by_category(
            detected_findings,
            tuple(trigger_categories),
        )
        expand_history = bool(findings)
        repository_ref = hashlib.sha256(repo.encode("utf-8")).hexdigest()[:12]
        print(
            f"head-scan repository_ref={repository_ref} files={result.files_scanned} "
            f"bytes={result.bytes_scanned} findings={len(findings)} "
            f"truncated={result.truncated} history={expand_history}"
        )
        _persist_findings(store, cfg, findings, run_id=job.get("run_id"))
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
    _persist_findings(store, cfg, findings, run_id=job.get("run_id"))


def _handle_ingested_file(store: PostgresStore, cfg: Config, job: dict[str, Any]) -> None:
    payload = _payload(job)
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
        path=str(payload["logical_path"]),
        source="ingest",
    )
    for finding in findings:
        finding.branch = str(payload.get("branch", ""))
        finding.commit = str(payload.get("commit_sha", ""))
    _persist_findings(store, cfg, findings, run_id=job.get("run_id"))


def _selected_for_head_scan(github_repository_id: int, sample_percent: int) -> bool:
    bounded_percent = min(max(sample_percent, 0), 100)
    return github_repository_id % 100 < bounded_percent


def _handle_repository_candidate(
    store: PostgresStore, cfg: Config, job: dict[str, Any]
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
        )


def handle_job(store: PostgresStore, cfg: Config, job: dict[str, Any]) -> None:
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
    handler(store, cfg, job)


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
    """Processa primeiro o head e usa 48h apenas como limite de recuperação."""
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
