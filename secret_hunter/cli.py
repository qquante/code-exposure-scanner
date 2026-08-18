"""CLI do secret_hunter.

Comandos:
  search             Busca por segredos via GitHub Code Search (precisa de token).
  scan-repo <url>    Clona e varre código atual + histórico (TruffleHog-like).
  list               Lista achados persistidos (redigidos).
  report             Gera o texto das Issues de alerta (dry-run).
  notify             Cria as Issues nos repositórios (--send para enviar).

Exemplos:
  python -m secret_hunter.cli search
  python -m secret_hunter.cli scan-repo https://github.com/user/repo
  python -m secret_hunter.cli list --repo user/repo
  python -m secret_hunter.cli notify --repo user/repo --send
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from . import __version__
from .config import Config
from .queue_policy import STAGES
from .extract import Finding, dedupe, extract_from_text
from .github_search import SEARCH_QUERIES, GitHubClient
from .history_scan import NativeGitScanner, trufflehog_available, trufflehog_scan
from .notify import create_issue
from .report import build_issue_body, build_issue_title
from .storage import Store
from .validate import validate as do_validate

_RISK_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _process_findings(findings: list[Finding], cfg: Config, store: Store) -> int:
    """Valida (opt-in), persiste (redigido) e zera o segredo bruto da memória."""
    added = 0
    for f in findings:
        if cfg.validate and cfg.is_validation_authorized(f.repo):
            do_validate(f, cfg)
        elif cfg.validate:
            f.validate_status = "not_checked"
            f.validate_detail = "repositório fora de SH_AUTHORIZED_VALIDATION_REPOS"
        if store.upsert(f):
            added += 1
        f.secret_raw = ""  # nunca fica em memória além do necessário
    return added


def _print_findings(findings: list[Finding]) -> None:
    if not findings:
        print("  (nenhum achado)")
        return
    for f in sorted(findings, key=lambda x: (_RISK_ORDER.get(x.risk, 9), x.type_id)):
        flag = f" [{f.validate_status}]" if f.validate_status else ""
        print(f"  [{f.risk.upper():8}] {f.provider:<16} {f.secret_redacted:<20} "
              f"{f.path or '(hist)'}{flag}")
        if f.validate_detail:
            print(f"             ↳ {f.validate_detail}")


# --------------------------------------------------------------------------- #
# Comandos
# --------------------------------------------------------------------------- #
def cmd_search(cfg: Config, args) -> int:
    if not cfg.github_token:
        print(
            "ERRO: Code Search exige token. Configure GITHUB_SEARCH_TOKEN_FILE "
            "(preferido) ou GITHUB_SEARCH_TOKEN."
        )
        return 1
    client = GitHubClient(cfg)
    store = Store(cfg)
    total_added = 0

    queries = SEARCH_QUERIES
    if args.types:
        queries = {t: SEARCH_QUERIES[t] for t in args.types.split(",") if t in SEARCH_QUERIES}

    for type_id, literal in queries.items():
        print(f"\n▶ Buscando: {literal}  ({type_id})")
        try:
            items = client.search_code(literal)
        except Exception as exc:
            print(f"  [erro] {exc}")
            continue
        print(f"  {len(items)} arquivo(s) candidato(s)")
        for item in items:
            repo = item.get("repository", {}).get("full_name", "")
            path = item.get("path", "")
            text = client.fetch_file(repo, path)
            if text is None:
                continue
            found = extract_from_text(text, repo=repo, path=path)
            found = dedupe(found)
            if found:
                added = _process_findings(found, cfg, store)
                total_added += added
                print(f"  → {repo}/{path}: {len(found)} achado(s)")
                _print_findings(found)

    total = store.count()
    store.close()
    print(f"\n✔ Concluído. {total_added} novo(s) achado(s) persistido(s). Total no DB: {total}")
    return 0


def cmd_scan_repo(cfg: Config, args) -> int:
    store = Store(cfg)
    scanner = NativeGitScanner(cfg)

    print(f"\n▶ Clonando e varrendo histórico de {args.url}")
    findings = scanner.scan_repo(args.url)
    print(f"  histórico (nativo): {len(findings)} achado(s)")

    if args.trufflehog:
        if trufflehog_available():
            th = trufflehog_scan(args.url, cfg)
            print(f"  trufflehog: {len(th)} achado(s)")
            findings.extend(th)
        else:
            print("  [aviso] TruffleHog não instalado — ignorando --trufflehog")

    findings = dedupe(findings)
    added = _process_findings(findings, cfg, store)
    _print_findings(findings)
    store.close()
    print(f"\n✔ {added} novo(s) achado(s) persistido(s).")
    return 0


def cmd_list(cfg: Config, args) -> int:
    store = Store(cfg)
    rows = store.all_findings() if not args.repo else store.unnotified(args.repo)
    if not rows:
        print("(nenhum achado)")
        store.close()
        return 0
    for r in rows:
        print(f"[{r['risk']:8}] {r['provider']:<16} {r['secret_redacted']:<20} "
              f"{r['repo']}/{r['path']}  {'notified' if r['notified'] else 'pendente'} "
              f"[{r['validate_status'] or 'não-validado'}]")
    print(f"\nTotal: {len(rows)}")
    store.close()
    return 0


def cmd_report(cfg: Config, args) -> int:
    store = Store(cfg)
    rows = store.unnotified(args.repo)
    # agrupa por repositório
    by_repo: dict[str, list[dict]] = {}
    for r in rows:
        by_repo.setdefault(r["repo"] or "(sem repo)", []).append(r)
    for repo, fs in by_repo.items():
        print("\n" + "=" * 70)
        print(build_issue_body(fs))
    store.close()
    return 0


def cmd_notify(cfg: Config, args) -> int:
    if args.send and not cfg.allow_public_contact_issue:
        print(
            "ERRO: envio público legado está desabilitado. Prefira a outbox PostgreSQL "
            "com aprovação e private vulnerability reporting."
        )
        return 2
    store = Store(cfg)
    rows = store.unnotified(args.repo)
    by_repo: dict[str, list[dict]] = {}
    for r in rows:
        by_repo.setdefault(r["repo"], []).append(r)

    ok = 0
    for repo, fs in by_repo.items():
        if not repo or "/" not in repo:
            continue
        # Issue pública nunca recebe tipo, arquivo, commit ou fragmento. O caminho
        # distribuído moderno prefere private vulnerability reporting + aprovação.
        body = build_issue_body(fs, visibility="public")
        if create_issue(repo, build_issue_title(), body, cfg, dry_run=not args.send):
            if args.send:
                for f in fs:
                    store.mark_notified(f["id"])
            ok += 1
    print(f"\n✔ {ok} repositório(s) processado(s).")
    store.close()
    return 0


def cmd_db_init(cfg: Config, args) -> int:
    from .postgres import PostgresStore

    store = PostgresStore(cfg, init_schema=True)
    store.close()
    print("PostgreSQL inicializado.")
    return 0


def cmd_enqueue_search(cfg: Config, args) -> int:
    from .pipeline import schedule_search
    from .postgres import PostgresStore

    store = PostgresStore(cfg)
    try:
        run_id, created = schedule_search(store, cfg)
    finally:
        store.close()
    print(f"run={run_id} jobs_criados={created}")
    return 0


def cmd_enqueue_repo(cfg: Config, args) -> int:
    from .pipeline import schedule_repository
    from .postgres import PostgresStore

    store = PostgresStore(cfg)
    try:
        run_id, created = schedule_repository(
            store, args.repository, trufflehog=not args.no_trufflehog
        )
    finally:
        store.close()
    print(f"run={run_id} job_criado={created}")
    return 0


def cmd_worker(cfg: Config, args) -> int:
    from .pipeline import run_worker

    kinds = tuple(item.strip() for item in (args.kinds or "").split(",") if item.strip())
    run_worker(
        cfg,
        concurrency=args.concurrency,
        once=args.once,
        kinds=kinds or None,
    )
    return 0


def cmd_redis_dispatcher(cfg: Config, args) -> int:
    from .pipeline import run_redis_dispatcher

    run_redis_dispatcher(cfg, once=args.once)
    return 0


def cmd_redis_worker(cfg: Config, args) -> int:
    from .pipeline import run_redis_stage_worker

    run_redis_stage_worker(cfg, stage=args.stage, once=args.once)
    return 0


def cmd_event_indexer(cfg: Config, args) -> int:
    from .pipeline import run_event_indexer

    run_event_indexer(cfg, once=args.once)
    return 0


def cmd_stream_stats(cfg: Config, _args) -> int:
    import json

    from .event_bus import RedisStreamBus

    bus = RedisStreamBus.from_config(cfg)
    try:
        print(json.dumps(bus.stream_stats(), ensure_ascii=False, indent=2))
    finally:
        bus.close()
    return 0


def cmd_redis_evidence_proof(cfg: Config, args) -> int:
    """Prova presença e integridade no Redis sem expor o payload bruto."""
    import json
    import secrets
    from datetime import datetime, timezone

    from .evidence import RedisEvidenceStore

    store = RedisEvidenceStore.from_config(cfg)
    try:
        target_entry = args.entry_id
        if args.demo:
            payload = json.dumps(
                {
                    "kind": "controlled-tcc-demo",
                    "generated_at": datetime.now(timezone.utc).isoformat(),
                    "nonce": secrets.token_hex(16),
                    "contains_real_secret": False,
                },
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
            target_entry = store.append_bytes(
                "tcc.controlled-demo",
                payload,
                metadata={
                    "controlled": True,
                    "contains_real_secret": False,
                    "purpose": "redis-integrity-proof",
                },
            )
        proofs = store.proof(entry_id=target_entry, limit=args.limit)
        result = {
            "backend": "redis",
            "stream": store.stream_key,
            "access_layer": "single-redis-password",
            "raw_payload_printed": False,
            "records": proofs,
        }
        print(json.dumps(result, ensure_ascii=False, indent=2))
    finally:
        store.close()
    accepted = {"verified", "legacy_encrypted"}
    return 0 if proofs and all(item["status"] in accepted for item in proofs) else 2


def cmd_notification_worker(cfg: Config, args) -> int:
    from .pipeline import run_notification_worker

    run_notification_worker(cfg, once=args.once)
    return 0


def cmd_db_stats(cfg: Config, args) -> int:
    import json
    from .postgres import PostgresStore

    store = PostgresStore(cfg)
    try:
        print(json.dumps(store.stats(), ensure_ascii=False, indent=2))
    finally:
        store.close()
    return 0


def cmd_scheduler(cfg: Config, args) -> int:
    from .pipeline import run_scheduler

    run_scheduler(cfg, once=args.once)
    return 0


def cmd_enqueue_ingest(cfg: Config, args) -> int:
    from .pipeline import schedule_ingest
    from .postgres import PostgresStore

    store = PostgresStore(cfg)
    try:
        run_id, discovered, created = schedule_ingest(
            store, cfg, adapter=args.adapter, source=args.source
        )
    finally:
        store.close()
    print(f"run={run_id} arquivos_descobertos={discovered} jobs_criados={created}")
    return 0


def cmd_ingest_watcher(cfg: Config, args) -> int:
    from .pipeline import run_ingest_watcher

    run_ingest_watcher(cfg, once=args.once)
    return 0


def cmd_discovery_watcher(cfg: Config, args) -> int:
    from .pipeline import run_discovery_watcher

    run_discovery_watcher(cfg, once=args.once)
    return 0


def cmd_candidates(cfg: Config, args) -> int:
    import json
    from .postgres import PostgresStore

    store = PostgresStore(cfg)
    try:
        rows = store.list_discovery_candidates(
            status=args.status,
            limit=args.limit,
            offset=args.offset,
        )
        print(json.dumps(rows, ensure_ascii=False, indent=2, default=str))
    finally:
        store.close()
    return 0


def cmd_authorize_candidate(cfg: Config, args) -> int:
    import json
    from .patterns import PATTERN_SET_ID
    from .postgres import PostgresStore

    store = PostgresStore(cfg)
    try:
        result = store.authorize_candidate_scan(
            args.candidate_id,
            args.actor,
            args.authorization_reference,
            trufflehog=not args.no_trufflehog,
            pattern_set_id=PATTERN_SET_ID,
        )
    finally:
        store.close()
    if result is None:
        print("ERRO: candidato não está elegível e pendente de revisão.")
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


def cmd_reject_candidate(cfg: Config, args) -> int:
    from .postgres import PostgresStore

    store = PostgresStore(cfg)
    try:
        rejected = store.reject_discovery_candidate(args.candidate_id, args.actor)
    finally:
        store.close()
    if not rejected:
        print("ERRO: candidato não está pendente.")
        return 2
    print(f"candidato={args.candidate_id} rejeitado=true")
    return 0


# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="secret-hunter",
        description="Descoberta defensiva de segredos vazados no GitHub (white-hat).",
    )
    p.add_argument("--version", action="version", version=f"secret-hunter {__version__}")
    p.add_argument("--config", default=None, help="caminho do config.yaml")
    p.add_argument("--validate", action="store_true", help="valida credenciais (opt-in, mínima)")
    p.add_argument("--validate-crypto", action="store_true", help="habilita validação cripto (deriva endereço)")

    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("search", help="busca via GitHub Code Search")
    s.add_argument("--types", help="filtra tipos por id separados por vírgula")
    s.set_defaults(func=cmd_search)

    r = sub.add_parser("scan-repo", help="varre código + histórico de um repo")
    r.add_argument("url")
    r.add_argument("--trufflehog", action="store_true", help="usa o TruffleHog real se instalado")
    r.set_defaults(func=cmd_scan_repo)

    l = sub.add_parser("list", help="lista achados (redigidos)")
    l.add_argument("--repo", help="filtra por owner/name")
    l.set_defaults(func=cmd_list)

    rep = sub.add_parser("report", help="gera o texto das Issues de alerta")
    rep.add_argument("--repo", help="filtra por owner/name")
    rep.set_defaults(func=cmd_report)

    n = sub.add_parser("notify", help="cria Issues de alerta")
    n.add_argument("--repo", help="filtra por owner/name")
    n.add_argument("--send", action="store_true", help="envia de fato (default: dry-run)")
    n.set_defaults(func=cmd_notify)

    db = sub.add_parser("db-init", help="inicializa o schema PostgreSQL")
    db.set_defaults(func=cmd_db_init)

    eq = sub.add_parser("enqueue-search", help="enfileira uma rodada de Code Search")
    eq.set_defaults(func=cmd_enqueue_search)

    er = sub.add_parser("enqueue-repo", help="enfileira histórico de um repositório GitHub")
    er.add_argument("repository", help="owner/repo ou URL github.com")
    er.add_argument("--no-trufflehog", action="store_true")
    er.set_defaults(func=cmd_enqueue_repo)

    w = sub.add_parser("worker", help="processa jobs PostgreSQL em paralelo")
    w.add_argument("--concurrency", type=int, default=None)
    w.add_argument("--kinds", help="tipos de job permitidos, separados por virgula")
    w.add_argument("--once", action="store_true", help="drena a fila atual e encerra")
    w.set_defaults(func=cmd_worker)

    rd = sub.add_parser("redis-dispatcher", help="publica jobs PostgreSQL em Redis Streams")
    rd.add_argument("--once", action="store_true")
    rd.set_defaults(func=cmd_redis_dispatcher)

    rw = sub.add_parser("redis-worker", help="consome um estágio independente do Redis")
    rw.add_argument(
        "--stage",
        required=True,
        choices=STAGES,
    )
    rw.add_argument("--once", action="store_true")
    rw.set_defaults(func=cmd_redis_worker)

    ei = sub.add_parser("event-indexer", help="indexa eventos Redis sanitizados no PostgreSQL")
    ei.add_argument("--once", action="store_true")
    ei.set_defaults(func=cmd_event_indexer)

    rs = sub.add_parser("stream-stats", help="mostra lag e pendências dos Redis Streams")
    rs.set_defaults(func=cmd_stream_stats)

    proof = sub.add_parser(
        "redis-evidence-proof",
        help="prova integridade da evidência Redis sem mostrar o conteúdo",
    )
    proof.add_argument("--entry-id", help="ID exato do Redis Stream")
    proof.add_argument("--limit", type=int, default=3, help="quantidade recente (1-100)")
    proof.add_argument("--demo", action="store_true", help="grava e verifica amostra controlada")
    proof.set_defaults(func=cmd_redis_evidence_proof)

    nw = sub.add_parser("notification-worker", help="envia apenas drafts aprovados")
    nw.add_argument("--once", action="store_true")
    nw.set_defaults(func=cmd_notification_worker)

    ds = sub.add_parser("db-stats", help="mostra contadores sanitizados do PostgreSQL")
    ds.set_defaults(func=cmd_db_stats)

    sch = sub.add_parser("scheduler", help="agenda Code Search por janela idempotente")
    sch.add_argument("--once", action="store_true")
    sch.set_defaults(func=cmd_scheduler)

    ing = sub.add_parser("enqueue-ingest", help="enfileira arquivos do drop-zone read-only")
    ing.add_argument("--adapter", choices=("tree", "manifest"), default=None)
    ing.add_argument("--source", default=None, help="subdiretorio tree ou manifest JSONL")
    ing.set_defaults(func=cmd_enqueue_ingest)

    iw = sub.add_parser("ingest-watcher", help="observa o drop-zone por polling idempotente")
    iw.add_argument("--once", action="store_true")
    iw.set_defaults(func=cmd_ingest_watcher)

    dw = sub.add_parser(
        "discovery-watcher",
        help="coleta metadados de novos repositórios públicos",
    )
    dw.add_argument("--once", action="store_true")
    dw.set_defaults(func=cmd_discovery_watcher)

    candidates = sub.add_parser("candidates", help="lista candidatos de descoberta")
    candidates.add_argument(
        "--status",
        choices=(
            "pending_metadata", "pending_review", "filtered", "unavailable",
            "scan_queued", "rejected",
        ),
    )
    candidates.add_argument("--limit", type=int, default=100)
    candidates.add_argument("--offset", type=int, default=0)
    candidates.set_defaults(func=cmd_candidates)

    authorize = sub.add_parser(
        "authorize-candidate",
        help="registra autorização explícita e agenda o scan",
    )
    authorize.add_argument("candidate_id", type=int)
    authorize.add_argument("--authorization-reference", required=True)
    authorize.add_argument("--actor", default="cli-admin")
    authorize.add_argument("--no-trufflehog", action="store_true")
    authorize.set_defaults(func=cmd_authorize_candidate)

    reject = sub.add_parser("reject-candidate", help="rejeita candidato pendente")
    reject.add_argument("candidate_id", type=int)
    reject.add_argument("--actor", default="cli-admin")
    reject.set_defaults(func=cmd_reject_candidate)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    cfg = Config.from_env(Path(args.config) if args.config else None)
    # flags da linha de comando sobrepõem o config
    if getattr(args, "validate", False):
        cfg.validate = True
    if getattr(args, "validate_crypto", False):
        cfg.validate_crypto = True
        cfg.validate = True
    _setup_logging(cfg)
    return args.func(cfg, args)


def _setup_logging(cfg: Config) -> None:
    """Log estruturado para stdout e arquivo — registra toda ação (validação, retry, falha)."""
    import logging

    handlers: list[logging.Handler] = [logging.StreamHandler()]
    log_file = os.environ.get("SH_LOG_FILE", "")
    if log_file:
        try:
            handlers.append(logging.FileHandler(log_file, encoding="utf-8"))
        except OSError:
            pass
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        handlers=handlers,
    )


if __name__ == "__main__":
    sys.exit(main())
