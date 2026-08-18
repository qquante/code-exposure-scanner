"""PostgreSQL: fonte de verdade, fila de jobs e outbox de notificações.

Nenhuma coluna aceita o segredo bruto. A identidade é um HMAC-SHA256 calculado
em memória com uma chave compartilhada entregue por Docker Secret.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .config import Config
from .extract import Finding
from .history_scan import normalize_github_repo
from .queue_policy import HEAD_LANES, classify_head_lane
from .report import build_issue_body, build_issue_title

try:
    from psycopg.rows import dict_row
    from psycopg_pool import ConnectionPool
except ImportError as exc:  # pragma: no cover - exercitado pelo CLI sem extra postgres
    dict_row = None
    ConnectionPool = None
    _IMPORT_ERROR = exc
else:
    _IMPORT_ERROR = None


_RISK_SQL = (
    "CASE f.risk WHEN 'critical' THEN 4 WHEN 'high' THEN 3 "
    "WHEN 'medium' THEN 2 ELSE 1 END"
)

_HINTS = {
    "stripe_live": "sk_live_…",
    "stripe_restricted": "rk_live_…",
    "stripe_test": "sk_test_…",
    "mercadopago": "APP_USR-…",
    "mercadopago_test": "TEST-…",
    "aws_akia": "AKIA…",
    "aws_asia": "ASIA…",
    "google_api_key": "AIza…",
    "mongodb_uri": "mongodb URI (credenciais ocultas)",
    "postgres_uri": "postgresql URI (credenciais ocultas)",
    "mysql_uri": "mysql URI (credenciais ocultas)",
    "redis_uri": "redis URI (credenciais ocultas)",
    "generic_uri_creds": "URI com credenciais ocultas",
    "github_pat": "ghp_…",
    "github_fine_grained": "github_pat_…",
    "github_oauth": "gh*_…",
    "gitlab_pat": "glpat-…",
    "openai_proj": "sk-proj-…",
    "openai_legacy": "sk-…",
    "huggingface": "hf_…",
    "slack_token": "xox*-…",
    "telegram_bot": "token de bot (oculto)",
    "evm_private_key": "chave privada EVM (oculta)",
    "bitcoin_wif": "chave privada Bitcoin WIF (oculta)",
    "solana_keypair_json": "keypair Solana em array (oculto)",
    "solana_keypair_base58": "keypair Solana Base58 (oculto)",
    "solana_keypair_base64": "keypair Solana Base64 (oculto)",
    "solana_keypair_hex": "keypair Solana hexadecimal (oculto)",
    "solana_seed_array": "seed Solana em array (oculta)",
    "solana_seed_base58": "seed Solana Base58 (oculta)",
    "solana_seed_base64": "seed Solana Base64 (oculta)",
    "solana_seed_hex": "seed Solana hexadecimal (oculta)",
    "evm_keystore_v3": "keystore EVM v3 criptografado (oculto)",
    "bip39_mnemonic": "frase-semente (oculta)",
    "private_key_pem": "bloco PEM privado (oculto)",
    "generic_assignment": "valor de alta entropia (oculto)",
    "jwt": "JWT (oculto)",
}


def _split_schema(sql: str) -> list[str]:
    return [statement.strip() for statement in sql.split(";") if statement.strip()]


def _environment(type_id: str) -> str:
    if "test" in type_id:
        return "test"
    if type_id in {"stripe_live", "stripe_restricted", "mercadopago"}:
        return "live"
    if type_id == "aws_asia":
        return "temporary"
    return "unknown"


def _confidence(type_id: str) -> str:
    if type_id in {"generic_assignment", "jwt", "evm_private_key"}:
        return "medium"
    return "high"


def _validation_status(value: str) -> str:
    return {
        "valid": "provider_active",
        "invalid": "provider_inactive",
        "provider_active": "provider_active",
        "provider_inactive": "provider_inactive",
        "format_valid": "format_valid",
        "unknown": "unknown",
        "error": "unknown",
        "unverified": "not_checked",
        "": "not_checked",
    }.get(value, "not_checked")


def _discovery_recency_priority(value: Any) -> int:
    """Prioridade SMALLINT: quanto mais recente o repositório, maior o valor."""
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return 1000
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    age_minutes = max(
        int((datetime.now(timezone.utc) - parsed.astimezone(timezone.utc)).total_seconds() // 60),
        0,
    )
    return max(1000, min(30000, 30000 - age_minutes))


class PostgresStore:
    def __init__(self, cfg: Config, *, init_schema: bool = False):
        if ConnectionPool is None:
            raise RuntimeError("instale o extra postgres: pip install 'secret-hunter[postgres]'") from _IMPORT_ERROR
        cfg.require_distributed_secrets()
        self.cfg = cfg
        self._fingerprint_key = cfg.fingerprint_key.encode("utf-8")
        self.fingerprint_key_id = hashlib.sha256(self._fingerprint_key).hexdigest()[:12]
        self.pool = ConnectionPool(
            conninfo=cfg.postgres_dsn(),
            min_size=cfg.db_pool_min,
            max_size=cfg.db_pool_max,
            kwargs={"row_factory": dict_row},
            open=True,
            timeout=30,
        )
        self.pool.wait(timeout=30)
        if init_schema:
            self.init_schema()

    def close(self) -> None:
        self.pool.close()

    def init_schema(self) -> None:
        schema = Path(__file__).with_name("schema.sql").read_text(encoding="utf-8")
        with self.pool.connection() as conn:
            for statement in _split_schema(schema):
                conn.execute(statement)

    def health(self) -> bool:
        with self.pool.connection() as conn:
            return bool(conn.execute("SELECT 1 AS ok").fetchone()["ok"])

    def fingerprint(self, type_id: str, secret: str) -> str:
        material = f"{type_id}\0{secret}".encode("utf-8")
        return hmac.new(self._fingerprint_key, material, hashlib.sha256).hexdigest()

    def create_run(self, mode: str, scope: str) -> int:
        with self.pool.connection() as conn:
            row = conn.execute(
                "INSERT INTO scan_runs (mode, scope) VALUES (%s, %s) RETURNING id",
                (mode, scope),
            ).fetchone()
            return int(row["id"])

    def complete_empty_run(self, run_id: int) -> None:
        with self.pool.connection() as conn:
            conn.execute(
                """
                UPDATE scan_runs
                SET status = 'completed', finished_at = now()
                WHERE id = %s AND status = 'running' AND jobs_created = 0
                """,
                (run_id,),
            )

    def enqueue_job(
        self,
        kind: str,
        natural_key: str,
        payload: dict[str, Any],
        *,
        run_id: int | None = None,
        priority: int = 0,
        max_attempts: int = 5,
    ) -> bool:
        encoded = json.dumps(payload, ensure_ascii=False)
        with self.pool.connection() as conn:
            row = conn.execute(
                """
                INSERT INTO scan_jobs
                    (run_id, kind, natural_key, payload, priority, max_attempts)
                VALUES (%s, %s, %s, %s::jsonb, %s, %s)
                ON CONFLICT (natural_key) DO NOTHING
                RETURNING id
                """,
                (run_id, kind, natural_key, encoded, priority, max_attempts),
            ).fetchone()
            if row and run_id:
                conn.execute(
                    "UPDATE scan_runs SET jobs_created = jobs_created + 1 WHERE id = %s",
                    (run_id,),
                )
            return row is not None

    def enqueue_ingest_batch(
        self,
        scope: str,
        jobs: list[tuple[str, dict[str, Any]]],
    ) -> tuple[int | None, int]:
        """Cria run + jobs atomicamente; remove o run se todo o batch for duplicado."""
        if not jobs:
            return None, 0
        with self.pool.connection() as conn:
            run = conn.execute(
                "INSERT INTO scan_runs (mode, scope) VALUES ('ingest', %s) RETURNING id",
                (scope,),
            ).fetchone()
            run_id = int(run["id"])
            created = 0
            for natural_key, payload in jobs:
                row = conn.execute(
                    """
                    INSERT INTO scan_jobs
                        (run_id, kind, natural_key, payload, priority, max_attempts)
                    VALUES (%s, 'scan_ingested_file', %s, %s::jsonb, 15, 2)
                    ON CONFLICT (natural_key) DO NOTHING
                    RETURNING id
                    """,
                    (run_id, natural_key, json.dumps(payload, ensure_ascii=False)),
                ).fetchone()
                created += int(row is not None)
            if created == 0:
                conn.execute("DELETE FROM scan_runs WHERE id = %s", (run_id,))
                return None, 0
            conn.execute(
                "UPDATE scan_runs SET jobs_created = %s WHERE id = %s",
                (created, run_id),
            )
            return run_id, created

    def claim_discovery_checkpoint(
        self, collector_key: str, owner: str, *, lease_seconds: int
    ) -> dict[str, Any] | None:
        """Obtém lease exclusivo do poller sem manter transação durante a rede."""
        with self.pool.connection() as conn:
            conn.execute(
                """
                INSERT INTO discovery_checkpoints (collector_key)
                VALUES (%s)
                ON CONFLICT (collector_key) DO NOTHING
                """,
                (collector_key,),
            )
            row = conn.execute(
                """
                SELECT * FROM discovery_checkpoints
                WHERE collector_key = %s
                FOR UPDATE
                """,
                (collector_key,),
            ).fetchone()
            if (
                row["next_poll_at"] > datetime.now(timezone.utc)
                or (
                    row["leased_until"] is not None
                    and row["leased_until"] > datetime.now(timezone.utc)
                )
            ):
                return None
            claimed = conn.execute(
                """
                UPDATE discovery_checkpoints
                SET lease_owner = %s,
                    leased_until = now() + (%s * interval '1 second'),
                    updated_at = now()
                WHERE collector_key = %s
                RETURNING *
                """,
                (owner, max(lease_seconds, 30), collector_key),
            ).fetchone()
            return dict(claimed)

    def prepare_discovery_windows(
        self,
        collector_key: str,
        owner: str,
        *,
        cutoff: datetime,
        head_end: datetime,
        window_seconds: int,
        limit: int,
    ) -> list[dict[str, Any]]:
        """Cria o ledger de até 48h e devolve as janelas mais recentes pendentes."""
        step = max(int(window_seconds), 10)
        if head_end <= cutoff:
            return []
        with self.pool.connection() as conn:
            checkpoint = conn.execute(
                """
                SELECT collector_key
                FROM discovery_checkpoints
                WHERE collector_key = %s AND lease_owner = %s
                FOR UPDATE
                """,
                (collector_key, owner),
            ).fetchone()
            if checkpoint is None:
                raise RuntimeError("lease do coletor perdido")

            conn.execute(
                """
                DELETE FROM discovery_windows
                WHERE collector_key = %s AND window_end <= %s
                """,
                (collector_key, cutoff),
            )
            latest = conn.execute(
                """
                SELECT max(window_end) AS window_end
                FROM discovery_windows
                WHERE collector_key = %s
                """,
                (collector_key,),
            ).fetchone()
            seed_start = latest["window_end"] if latest else None
            if seed_start is None or seed_start < cutoff:
                seed_start = cutoff

            if seed_start < head_end:
                conn.execute(
                    """
                    INSERT INTO discovery_windows
                        (collector_key, window_start, window_end)
                    SELECT %s, point, point + (%s * interval '1 second')
                    FROM generate_series(
                        %s::timestamptz,
                        %s::timestamptz - (%s * interval '1 second'),
                        (%s * interval '1 second')
                    ) AS point
                    ON CONFLICT (collector_key, window_start, window_end)
                    DO NOTHING
                    """,
                    (
                        collector_key,
                        step,
                        seed_start,
                        head_end,
                        step,
                        step,
                    ),
                )

            rows = conn.execute(
                """
                SELECT id, window_start, window_end, first_completed_at,
                       reconciled_at, attempts
                FROM discovery_windows
                WHERE collector_key = %s
                  AND reconciled_at IS NULL
                  AND next_attempt_at <= now()
                ORDER BY window_end DESC, id DESC
                LIMIT %s
                """,
                (collector_key, max(int(limit), 1)),
            ).fetchall()
            return [dict(row) for row in rows]


    def persist_discovery_poll(
        self,
        collector_key: str,
        owner: str,
        events: list[dict[str, Any]],
        *,
        etag: str,
        newest_event_id: str,
        poll_interval: int,
        gap_detected: bool,
        window_results: list[dict[str, Any]] | None = None,
        reconcile_seconds: int = 900,
    ) -> int:
        """Persiste candidatos, jobs e checkpoint na mesma transação."""
        with self.pool.connection() as conn:
            checkpoint = conn.execute(
                """
                SELECT collector_key FROM discovery_checkpoints
                WHERE collector_key = %s AND lease_owner = %s
                FOR UPDATE
                """,
                (collector_key, owner),
            ).fetchone()
            if checkpoint is None:
                raise RuntimeError("lease do coletor perdido")

            created = 0
            for event in events:
                repository = normalize_github_repo(str(event.get("repository") or ""))
                if repository is None:
                    continue
                owner_name, repo_name = repository.split("/", 1)
                repo = conn.execute(
                    """
                    INSERT INTO repositories (owner, name, full_name, html_url, is_public)
                    VALUES (%s, %s, %s, %s, true)
                    ON CONFLICT (full_name) DO UPDATE
                    SET last_seen = now(), is_public = true
                    RETURNING id
                    """,
                    (
                        owner_name,
                        repo_name,
                        repository,
                        f"https://github.com/{repository}",
                    ),
                ).fetchone()
                candidate = conn.execute(
                    """
                    INSERT INTO discovery_candidates
                        (repository_id, github_event_id, github_repository_id,
                         event_created_at)
                    VALUES (%s, %s, %s, %s::timestamptz)
                    ON CONFLICT DO NOTHING
                    RETURNING id
                    """,
                    (
                        repo["id"],
                        str(event["event_id"]),
                        int(event["github_repository_id"]),
                        str(event["event_created_at"]),
                    ),
                ).fetchone()
                if candidate is None:
                    continue
                candidate_id = int(candidate["id"])
                queue_lane = classify_head_lane(
                    event.get("event_created_at"),
                    live_max_age_minutes=self.cfg.discovery_live_max_age_minutes,
                )
                conn.execute(
                    """
                    INSERT INTO scan_jobs
                        (kind, natural_key, payload, priority, max_attempts)
                    VALUES (
                        'enrich_repository_candidate', %s, %s::jsonb, %s, 5
                    )
                    ON CONFLICT (natural_key) DO NOTHING
                    """,
                    (
                        f"discovery-enrich:{event['event_id']}",
                        json.dumps(
                            {
                                "candidate_id": candidate_id,
                                "repository": repository,
                                "queue_lane": queue_lane,
                                "metadata": event.get("metadata"),
                            },
                            ensure_ascii=False,
                        ),
                        _discovery_recency_priority(event.get("event_created_at")),
                    ),
                )
                created += 1

            for result in window_results or []:
                window_id = int(result["id"])
                error = str(result.get("error") or "")
                if error:
                    conn.execute(
                        """
                        UPDATE discovery_windows
                        SET attempts = attempts + 1,
                            next_attempt_at = now() + (%s * interval '1 second'),
                            last_error = %s,
                            updated_at = now()
                        WHERE id = %s AND collector_key = %s
                        """,
                        (
                            max(int(result.get("retry_seconds") or poll_interval), 5),
                            error[:1000],
                            window_id,
                            collector_key,
                        ),
                    )
                    continue
                window_updated = conn.execute(
                    """
                    UPDATE discovery_windows
                    SET attempts = attempts + 1,
                        source_items_seen = source_items_seen + %s,
                        repositories_seen = repositories_seen + %s,
                        request_count = request_count + %s,
                        first_completed_at = COALESCE(first_completed_at, now()),
                        reconciled_at = CASE
                            WHEN first_completed_at IS NOT NULL
                              OR window_end <= now() - (%s * interval '1 second')
                            THEN now()
                            ELSE reconciled_at
                        END,
                        next_attempt_at = CASE
                            WHEN first_completed_at IS NULL
                              AND window_end > now() - (%s * interval '1 second')
                            THEN now() + (%s * interval '1 second')
                            ELSE next_attempt_at
                        END,
                        last_error = '',
                        updated_at = now()
                    WHERE id = %s AND collector_key = %s
                    RETURNING id
                    """,
                    (
                        max(int(result.get("source_items_seen") or 0), 0),
                        max(int(result.get("repositories_seen") or 0), 0),
                        max(int(result.get("request_count") or 0), 0),
                        max(int(reconcile_seconds), 1),
                        max(int(reconcile_seconds), 1),
                        max(int(reconcile_seconds), 1),
                        window_id,
                        collector_key,
                    ),
                ).fetchone()
                if window_updated is None:
                    raise RuntimeError(
                        f"janela de descoberta {window_id} não encontrada"
                    )


            updated = conn.execute(
                """
                UPDATE discovery_checkpoints
                SET etag = %s,
                    last_event_id = COALESCE(NULLIF(%s, ''), last_event_id),
                    next_poll_at = now() + (%s * interval '1 second'),
                    last_polled_at = now(),
                    lease_owner = NULL,
                    leased_until = NULL,
                    last_error = '',
                    gap_count = gap_count + %s,
                    updated_at = now()
                WHERE collector_key = %s AND lease_owner = %s
                RETURNING collector_key
                """,
                (
                    etag,
                    newest_event_id,
                    max(poll_interval, 1),
                    int(gap_detected),
                    collector_key,
                    owner,
                ),
            ).fetchone()
            if updated is None:
                raise RuntimeError("lease do coletor perdido durante commit")
            return created

    def fail_discovery_checkpoint(
        self, collector_key: str, owner: str, error: str, *, retry_seconds: int
    ) -> None:
        with self.pool.connection() as conn:
            conn.execute(
                """
                UPDATE discovery_checkpoints
                SET lease_owner = NULL,
                    leased_until = NULL,
                    next_poll_at = now() + (%s * interval '1 second'),
                    last_error = %s,
                    updated_at = now()
                WHERE collector_key = %s AND lease_owner = %s
                """,
                (max(retry_seconds, 5), error[:1000], collector_key, owner),
            )

    def prune_discovery(self, *, retention_days: int) -> dict[str, int]:
        """Limita crescimento sem apagar candidatos já autorizados."""
        days = max(retention_days, 1)
        with self.pool.connection() as conn:
            candidates = conn.execute(
                """
                DELETE FROM discovery_candidates
                WHERE status IN ('filtered', 'unavailable', 'rejected', 'pending_review')
                  AND updated_at < now() - (%s * interval '1 day')
                RETURNING id
                """,
                (days,),
            ).fetchall()
            jobs = conn.execute(
                """
                DELETE FROM scan_jobs
                WHERE kind = 'enrich_repository_candidate'
                  AND status IN ('completed', 'failed')
                  AND updated_at < now() - (%s * interval '1 day')
                RETURNING id
                """,
                (days,),
            ).fetchall()
            repositories = conn.execute(
                """
                DELETE FROM repositories r
                WHERE r.last_seen < now() - (%s * interval '1 day')
                  AND NOT EXISTS (
                      SELECT 1 FROM discovery_candidates c WHERE c.repository_id = r.id
                  )
                  AND NOT EXISTS (
                      SELECT 1 FROM findings f WHERE f.repository_id = r.id
                  )
                RETURNING id
                """,
                (days,),
            ).fetchall()
            return {
                "candidates": len(candidates),
                "jobs": len(jobs),
                "repositories": len(repositories),
            }

    def list_jobs_after(self, job_id: int, *, limit: int = 500) -> list[dict[str, Any]]:
        """Lista o log monotônico usado pelo dispatcher Redis."""
        with self.pool.connection() as conn:
            rows = conn.execute(
                """
                SELECT id, run_id, kind, natural_key, payload, status, priority,
                       attempts, max_attempts, available_at, lease_owner, leased_until,
                       last_error, created_at, updated_at, completed_at
                FROM scan_jobs
                WHERE id > %s
                ORDER BY id
                LIMIT %s
                """,
                (max(int(job_id), 0), min(max(int(limit), 1), 5000)),
            ).fetchall()
            return [dict(row) for row in rows]

    def claim_job_by_id(self, job_id: int, worker: str) -> dict[str, Any] | None:
        """Claim idempotente do job apontado por uma mensagem Redis."""
        with self.pool.connection() as conn:
            row = conn.execute(
                """
                WITH candidate AS (
                    SELECT id
                    FROM scan_jobs
                    WHERE id = %s
                      AND attempts < max_attempts
                      AND (
                        (status = 'pending' AND available_at <= now())
                        OR (status = 'running' AND leased_until < now())
                      )
                    FOR UPDATE SKIP LOCKED
                )
                UPDATE scan_jobs AS job
                SET status = 'running',
                    attempts = attempts + 1,
                    lease_owner = %s,
                    leased_until = now() + (%s * interval '1 second'),
                    updated_at = now()
                FROM candidate
                WHERE job.id = candidate.id
                RETURNING job.*
                """,
                (int(job_id), worker, self.cfg.job_lease_seconds),
            ).fetchone()
            return dict(row) if row else None

    def get_job_state(self, job_id: int) -> dict[str, Any] | None:
        with self.pool.connection() as conn:
            row = conn.execute(
                """
                SELECT id, kind, status, attempts, max_attempts, available_at,
                       lease_owner, leased_until, completed_at
                FROM scan_jobs
                WHERE id = %s
                """,
                (int(job_id),),
            ).fetchone()
            return dict(row) if row else None

    def claim_job(
        self, worker: str, *, kinds: tuple[str, ...] | None = None
    ) -> dict[str, Any] | None:
        allowed = list(kinds) if kinds else None
        with self.pool.connection() as conn:
            row = conn.execute(
                """
                WITH candidate AS (
                    SELECT id
                    FROM scan_jobs
                    WHERE attempts < max_attempts
                      AND (%s::text[] IS NULL OR kind = ANY(%s::text[]))
                      AND (
                        (status = 'pending' AND available_at <= now())
                        OR (status = 'running' AND leased_until < now())
                      )
                    ORDER BY priority DESC, created_at, id
                    FOR UPDATE SKIP LOCKED
                    LIMIT 1
                )
                UPDATE scan_jobs AS job
                SET status = 'running',
                    attempts = attempts + 1,
                    lease_owner = %s,
                    leased_until = now() + (%s * interval '1 second'),
                    updated_at = now()
                FROM candidate
                WHERE job.id = candidate.id
                RETURNING job.*
                """,
                (allowed, allowed, worker, self.cfg.job_lease_seconds),
            ).fetchone()
            return dict(row) if row else None

    def complete_job(self, job_id: int, worker: str) -> bool:
        with self.pool.connection() as conn:
            row = conn.execute(
                """
                UPDATE scan_jobs
                SET status = 'completed', completed_at = now(), updated_at = now(),
                    leased_until = NULL
                WHERE id = %s AND status = 'running' AND lease_owner = %s
                RETURNING id, run_id
                """,
                (job_id, worker),
            ).fetchone()
            if row and row["run_id"]:
                self._refresh_run(conn, int(row["run_id"]))
            return row is not None

    def extend_job_lease(self, job_id: int, worker: str) -> bool:
        with self.pool.connection() as conn:
            row = conn.execute(
                """
                UPDATE scan_jobs
                SET leased_until = now() + (%s * interval '1 second'), updated_at = now()
                WHERE id = %s AND status = 'running' AND lease_owner = %s
                RETURNING id
                """,
                (self.cfg.job_lease_seconds, job_id, worker),
            ).fetchone()
            return row is not None

    def fail_job(self, job: dict[str, Any], worker: str, error: str) -> None:
        terminal = int(job["attempts"]) >= int(job["max_attempts"])
        delay = min(300, 2 ** min(int(job["attempts"]), 8))
        with self.pool.connection() as conn:
            row = conn.execute(
                """
                UPDATE scan_jobs
                SET status = %s,
                    available_at = now() + (%s * interval '1 second'),
                    leased_until = NULL,
                    last_error = %s,
                    updated_at = now()
                WHERE id = %s AND status = 'running' AND lease_owner = %s
                RETURNING run_id
                """,
                (
                    "failed" if terminal else "pending",
                    delay,
                    error[:1000],
                    job["id"],
                    worker,
                ),
            ).fetchone()
            if row and terminal and str(job.get("kind")) == "enrich_repository_candidate":
                payload = job.get("payload")
                if isinstance(payload, str):
                    payload = json.loads(payload)
                if isinstance(payload, dict) and payload.get("candidate_id"):
                    conn.execute(
                        """
                        UPDATE discovery_candidates
                        SET status = 'unavailable',
                            filter_reason = 'metadata_job_failed',
                            metadata_checked_at = now(), updated_at = now()
                        WHERE id = %s AND status = 'pending_metadata'
                        """,
                        (int(payload["candidate_id"]),),
                    )
            if row and row["run_id"] and terminal:
                self._refresh_run(conn, int(row["run_id"]))

    @staticmethod
    def _refresh_run(conn, run_id: int) -> None:
        counts = conn.execute(
            """
            SELECT
                count(*) FILTER (WHERE status IN ('pending', 'running'))::int AS active,
                count(*) FILTER (WHERE status = 'failed')::int AS failed
            FROM scan_jobs WHERE run_id = %s
            """,
            (run_id,),
        ).fetchone()
        if counts and int(counts["active"]) == 0:
            conn.execute(
                """
                UPDATE scan_runs
                SET status = %s, finished_at = now(), errors = %s
                WHERE id = %s AND status = 'running'
                """,
                ("partial" if int(counts["failed"]) else "completed", counts["failed"], run_id),
            )

    def reserve_rate_slot(self, bucket: str, limit: int, window_seconds: int) -> float:
        now = datetime.now(timezone.utc)
        with self.pool.connection() as conn:
            conn.execute(
                """
                INSERT INTO rate_limit_buckets (bucket_key, window_started_at, used)
                VALUES (%s, %s, 0)
                ON CONFLICT (bucket_key) DO NOTHING
                """,
                (bucket, now),
            )
            row = conn.execute(
                "SELECT * FROM rate_limit_buckets WHERE bucket_key = %s FOR UPDATE",
                (bucket,),
            ).fetchone()
            window_end = row["window_started_at"] + timedelta(seconds=window_seconds)
            if now >= window_end:
                conn.execute(
                    "UPDATE rate_limit_buckets SET window_started_at = %s, used = 1 WHERE bucket_key = %s",
                    (now, bucket),
                )
                return 0.0
            if int(row["used"]) < limit:
                conn.execute(
                    "UPDATE rate_limit_buckets SET used = used + 1 WHERE bucket_key = %s",
                    (bucket,),
                )
                return 0.0
            return max((window_end - now).total_seconds(), 0.1)

    def upsert_finding(self, finding: Finding, *, run_id: int | None = None) -> tuple[int, bool]:
        repo_name = normalize_github_repo(finding.repo)
        if not repo_name or not finding.secret_raw:
            raise ValueError("finding sem repositório canônico ou sem material transitório")
        owner, name = repo_name.split("/", 1)
        fp = self.fingerprint(finding.type_id, finding.secret_raw)
        finding.fingerprint = fp
        source_kind = (
            finding.source
            if finding.source in {"code", "history", "trufflehog", "ingest"}
            else "code"
        )
        validation = _validation_status(finding.validate_status)

        with self.pool.connection() as conn:
            repo = conn.execute(
                """
                INSERT INTO repositories (owner, name, full_name, html_url)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (full_name) DO UPDATE SET last_seen = now()
                RETURNING id
                """,
                (owner, name, repo_name, f"https://github.com/{repo_name}"),
            ).fetchone()
            finding_row = conn.execute(
                """
                INSERT INTO findings
                    (repository_id, fingerprint, fingerprint_key_id, type_id, platform,
                     category, environment, risk, confidence, secret_hint, validation_status)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (repository_id, type_id, fingerprint, fingerprint_key_id)
                DO UPDATE SET last_seen = now(), validation_status = EXCLUDED.validation_status
                RETURNING id, (xmax = 0) AS inserted
                """,
                (
                    repo["id"], fp, self.fingerprint_key_id, finding.type_id,
                    finding.provider, finding.category, _environment(finding.type_id),
                    finding.risk, _confidence(finding.type_id),
                    _HINTS.get(finding.type_id, "segredo (oculto)"), validation,
                ),
            ).fetchone()
            finding_id = int(finding_row["id"])
            location = conn.execute(
                """
                INSERT INTO finding_locations
                    (finding_id, source_kind, path, branch, commit_sha, blob_sha,
                     line_start, line_end)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT
                    (finding_id, source_kind, path, branch, commit_sha, blob_sha, line_start)
                DO UPDATE SET last_seen = now()
                RETURNING id
                """,
                (
                    finding_id, source_kind, finding.path, finding.branch, finding.commit,
                    getattr(finding, "blob_sha", ""), max(finding.line, 0), max(finding.line, 0),
                ),
            ).fetchone()

            report_rows = conn.execute(
                """
                SELECT f.id, %s AS repo, f.platform AS provider, f.type_id, f.risk,
                       f.category, f.validation_status,
                       COALESCE(location.path, '') AS path,
                       COALESCE(location.commit_sha, '') AS commit_sha
                FROM findings f
                LEFT JOIN LATERAL (
                    SELECT path, commit_sha
                    FROM finding_locations
                    WHERE finding_id = f.id
                    ORDER BY last_seen DESC, id DESC
                    LIMIT 1
                ) location ON true
                WHERE f.repository_id = %s
                  AND f.status = 'open'
                  AND NOT EXISTS (
                      SELECT 1
                      FROM notification_findings nf
                      JOIN notification_outbox sent ON sent.id = nf.notification_id
                      WHERE nf.finding_id = f.id AND sent.status = 'sent'
                  )
                ORDER BY CASE f.risk WHEN 'critical' THEN 4 WHEN 'high' THEN 3
                         WHEN 'medium' THEN 2 ELSE 1 END DESC, f.id
                """,
                (repo_name, repo["id"]),
            ).fetchall()
            report_findings = [dict(item) for item in report_rows]
            if report_findings:
                idempotency = hmac.new(
                    self._fingerprint_key,
                    f"notification\0{repo_name}\0{finding_id}".encode("utf-8"),
                    hashlib.sha256,
                ).hexdigest()
                notification = conn.execute(
                    """
                    INSERT INTO notification_outbox
                        (finding_id, repository_id, idempotency_key, title, private_body, public_body)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    ON CONFLICT (repository_id, channel)
                        WHERE status IN (
                            'pending_review', 'approved', 'rejected', 'sending',
                            'needs_contact', 'failed'
                        )
                    DO UPDATE SET
                        private_body = EXCLUDED.private_body,
                        public_body = EXCLUDED.public_body,
                        updated_at = now()
                    RETURNING id
                    """,
                    (
                        finding_id,
                        repo["id"],
                        idempotency,
                        build_issue_title(),
                        build_issue_body(report_findings, visibility="private"),
                        build_issue_body(report_findings, visibility="public"),
                    ),
                ).fetchone()
                conn.execute(
                    """
                    INSERT INTO notification_findings (notification_id, finding_id)
                    SELECT %s, f.id
                    FROM findings f
                    WHERE f.repository_id = %s AND f.status = 'open'
                      AND NOT EXISTS (
                          SELECT 1
                          FROM notification_findings nf
                          JOIN notification_outbox sent ON sent.id = nf.notification_id
                          WHERE nf.finding_id = f.id AND sent.status = 'sent'
                      )
                    ON CONFLICT DO NOTHING
                    """,
                    (notification["id"], repo["id"]),
                )
            if run_id and bool(finding_row["inserted"]):
                conn.execute(
                    "UPDATE scan_runs SET findings_created = findings_created + 1 WHERE id = %s",
                    (run_id,),
                )
            return finding_id, bool(finding_row["inserted"] and location)

    def list_findings(self, *, limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
        with self.pool.connection() as conn:
            rows = conn.execute(
                f"""
                SELECT f.id, r.full_name AS repository, f.type_id, f.platform, f.category,
                       f.environment, f.risk, f.confidence, f.secret_hint,
                       f.validation_status, f.status, f.first_seen, f.last_seen,
                       (SELECT count(*)::int FROM finding_locations counted
                        WHERE counted.finding_id = f.id) AS location_count,
                       latest.path AS latest_path,
                       latest.branch AS latest_branch,
                       latest.commit_sha AS latest_commit_sha,
                       latest.line_start AS latest_line_start
                FROM findings f
                JOIN repositories r ON r.id = f.repository_id
                LEFT JOIN LATERAL (
                    SELECT path, branch, commit_sha, line_start
                    FROM finding_locations
                    WHERE finding_id = f.id
                    ORDER BY last_seen DESC, id DESC
                    LIMIT 1
                ) latest ON true
                ORDER BY {_RISK_SQL} DESC, f.last_seen DESC, f.id DESC
                LIMIT %s OFFSET %s
                """,
                (min(max(limit, 1), 500), max(offset, 0)),
            ).fetchall()
            return [dict(row) for row in rows]

    def get_finding(self, finding_id: int) -> dict[str, Any] | None:
        with self.pool.connection() as conn:
            row = conn.execute(
                """
                SELECT f.*, r.host, r.owner, r.name, r.full_name AS repository,
                       r.html_url AS repository_url, r.is_public
                FROM findings f
                JOIN repositories r ON r.id = f.repository_id
                WHERE f.id = %s
                """,
                (finding_id,),
            ).fetchone()
            if not row:
                return None
            locations = conn.execute(
                """
                SELECT id, source_kind, path, branch, commit_sha, blob_sha,
                       line_start, line_end, first_seen, last_seen
                FROM finding_locations
                WHERE finding_id = %s
                ORDER BY last_seen DESC, id
                """,
                (finding_id,),
            ).fetchall()
            result = dict(row)
            result["locations"] = [dict(location) for location in locations]
            return result
    def existing_discovery_repository_ids(self, repository_ids: list[int]) -> set[int]:
        if not repository_ids:
            return set()
        with self.pool.connection() as conn:
            rows = conn.execute(
                """
                SELECT github_repository_id
                FROM discovery_candidates
                WHERE github_repository_id = ANY(%s::bigint[])
                """,
                (repository_ids,),
            ).fetchall()
            return {int(row["github_repository_id"]) for row in rows}


    def get_discovery_candidate(self, candidate_id: int) -> dict[str, Any] | None:
        with self.pool.connection() as conn:
            row = conn.execute(
                """
                SELECT c.*, r.full_name AS repository, r.html_url AS repository_url
                FROM discovery_candidates c
                JOIN repositories r ON r.id = c.repository_id
                WHERE c.id = %s
                """,
                (candidate_id,),
            ).fetchone()
            return dict(row) if row else None

    def list_discovery_candidates(
        self,
        *,
        status: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        allowed = {
            "pending_metadata", "pending_review", "filtered", "unavailable",
            "scan_queued", "rejected",
        }
        if status is not None and status not in allowed:
            raise ValueError("status de candidato inválido")
        with self.pool.connection() as conn:
            rows = conn.execute(
                """
                SELECT c.id, r.full_name AS repository, r.html_url AS repository_url,
                       c.github_event_id, c.github_repository_id, c.event_created_at,
                       c.repository_created_at, c.status, c.language, c.size_kb,
                       c.is_fork, c.is_archived, c.is_disabled, c.default_branch,
                       c.filter_reason, c.metadata_checked_at,
                       c.authorization_reference, c.authorized_by, c.authorized_at,
                       c.scan_job_id, c.first_seen, c.updated_at
                FROM discovery_candidates c
                JOIN repositories r ON r.id = c.repository_id
                WHERE (%s::text IS NULL OR c.status = %s)
                ORDER BY c.event_created_at DESC, c.id DESC
                LIMIT %s OFFSET %s
                """,
                (
                    status,
                    status,
                    min(max(limit, 1), 500),
                    max(offset, 0),
                ),
            ).fetchall()
            return [dict(row) for row in rows]

    def complete_candidate_metadata(
        self,
        candidate_id: int,
        metadata: dict[str, Any],
        *,
        eligible: bool,
        filter_reason: str,
    ) -> bool:
        with self.pool.connection() as conn:
            row = conn.execute(
                """
                UPDATE discovery_candidates
                SET repository_created_at = %s::timestamptz,
                    status = %s,
                    language = %s,
                    size_kb = %s,
                    is_fork = %s,
                    is_archived = %s,
                    is_disabled = %s,
                    default_branch = %s,
                    filter_reason = %s,
                    metadata_checked_at = now(),
                    updated_at = now()
                WHERE id = %s AND status = 'pending_metadata'
                RETURNING repository_id
                """,
                (
                    metadata.get("created_at"),
                    "pending_review" if eligible else "filtered",
                    metadata.get("language"),
                    int(metadata.get("size_kb") or 0),
                    bool(metadata.get("is_fork")),
                    bool(metadata.get("is_archived")),
                    bool(metadata.get("is_disabled")),
                    str(metadata.get("default_branch") or ""),
                    filter_reason,
                    candidate_id,
                ),
            ).fetchone()
            if row:
                conn.execute(
                    """
                    UPDATE repositories
                    SET is_public = %s, last_seen = now()
                    WHERE id = %s
                    """,
                    (bool(metadata.get("is_public")), row["repository_id"]),
                )
            return row is not None

    def mark_candidate_unavailable(self, candidate_id: int, reason: str) -> bool:
        with self.pool.connection() as conn:
            row = conn.execute(
                """
                UPDATE discovery_candidates
                SET status = 'unavailable', filter_reason = %s,
                    metadata_checked_at = now(), updated_at = now()
                WHERE id = %s AND status = 'pending_metadata'
                RETURNING id
                """,
                (reason[:200], candidate_id),
            ).fetchone()
            return row is not None

    def authorize_candidate_scan(
        self,
        candidate_id: int,
        actor: str,
        authorization_reference: str,
        *,
        trufflehog: bool,
        pattern_set_id: str,
    ) -> dict[str, Any] | None:
        """Registra autorização e enfileira o scan em uma única transação."""
        reference = authorization_reference.strip()
        if len(reference) < 8:
            raise ValueError("authorization_reference deve explicar a autorização")
        return self._queue_candidate_scan(
            candidate_id,
            actor=actor,
            authorization_reference=reference,
            trufflehog=trufflehog,
            pattern_set_id=pattern_set_id,
        )

    def queue_candidate_scan_automatically(
        self,
        candidate_id: int,
        *,
        trufflehog: bool,
        pattern_set_id: str,
        queue_lane: str | None = None,
    ) -> dict[str, Any] | None:
        """Enfileira candidato elegível sem registrar autorização humana."""
        return self._queue_candidate_scan(
            candidate_id,
            actor="system:discovery-auto",
            authorization_reference=None,
            trufflehog=trufflehog,
            pattern_set_id=pattern_set_id,
            queue_lane=queue_lane,
        )

    def _queue_candidate_scan(
        self,
        candidate_id: int,
        *,
        actor: str,
        authorization_reference: str | None,
        trufflehog: bool,
        pattern_set_id: str,
        queue_lane: str | None = None,
    ) -> dict[str, Any] | None:
        """Cria run/job uma única vez e avança o candidato atomicamente."""
        with self.pool.connection() as conn:
            candidate = conn.execute(
                """
                SELECT c.id, c.github_event_id, c.event_created_at, r.full_name AS repository
                FROM discovery_candidates c
                JOIN repositories r ON r.id = c.repository_id
                WHERE c.id = %s AND c.status = 'pending_review'
                FOR UPDATE OF c
                """,
                (candidate_id,),
            ).fetchone()
            if candidate is None:
                return None
            run = conn.execute(
                """
                INSERT INTO scan_runs (mode, scope)
                VALUES ('history', %s)
                RETURNING id
                """,
                (candidate["repository"],),
            ).fetchone()
            run_id = int(run["id"])
            history_natural_key = (
                f"candidate-history:{pattern_set_id}:{candidate['github_event_id']}"
            )
            head_first = authorization_reference is None
            effective_queue_lane: str | None = None
            if head_first:
                if queue_lane is not None and queue_lane not in HEAD_LANES:
                    raise ValueError(f"lane HEAD desconhecida: {queue_lane}")
                effective_queue_lane = queue_lane or classify_head_lane(
                    candidate["event_created_at"],
                    live_max_age_minutes=self.cfg.discovery_live_max_age_minutes,
                )
            natural_key = (
                f"candidate-head:{pattern_set_id}:{candidate['github_event_id']}"
                if head_first
                else history_natural_key
            )
            scan_payload = {
                "repo": candidate["repository"],
                "trufflehog": bool(trufflehog),
                "candidate_id": candidate_id,
                "mode": "head" if head_first else "history",
                "event_created_at": candidate["event_created_at"].isoformat(),
            }
            if head_first:
                scan_payload["history_natural_key"] = history_natural_key
                scan_payload["queue_lane"] = effective_queue_lane
            job = conn.execute(
                """
                INSERT INTO scan_jobs
                    (run_id, kind, natural_key, payload, priority, max_attempts)
                VALUES (%s, 'scan_history', %s, %s::jsonb, %s, 3)
                ON CONFLICT (natural_key) DO NOTHING
                RETURNING id
                """,
                (
                    run_id,
                    natural_key,
                    json.dumps(scan_payload, ensure_ascii=False),
                    _discovery_recency_priority(candidate["event_created_at"]),
                ),
            ).fetchone()
            created = job is not None
            if job is None:
                existing = conn.execute(
                    "SELECT id, run_id FROM scan_jobs WHERE natural_key = %s",
                    (natural_key,),
                ).fetchone()
                conn.execute("DELETE FROM scan_runs WHERE id = %s", (run_id,))
                if existing is None:
                    raise RuntimeError("job do candidato não pôde ser localizado")
                job_id = int(existing["id"])
                run_id = int(existing["run_id"]) if existing["run_id"] else 0
            else:
                job_id = int(job["id"])
                conn.execute(
                    "UPDATE scan_runs SET jobs_created = 1 WHERE id = %s",
                    (run_id,),
                )
            if authorization_reference is None:
                conn.execute(
                    """
                    UPDATE discovery_candidates
                    SET status = 'scan_queued', scan_job_id = %s, updated_at = now()
                    WHERE id = %s
                    """,
                    (job_id, candidate_id),
                )
                audit_action = "candidate.scan_auto_queued"
                audit_metadata = {
                    "trigger": "eligible_metadata",
                    "stage": f"head-{effective_queue_lane}",
                    "queue_lane": effective_queue_lane,
                }
            else:
                conn.execute(
                    """
                    UPDATE discovery_candidates
                    SET status = 'scan_queued', authorization_reference = %s,
                        authorized_by = %s, authorized_at = now(), scan_job_id = %s,
                        updated_at = now()
                    WHERE id = %s
                    """,
                    (
                        authorization_reference[:500],
                        actor[:100],
                        job_id,
                        candidate_id,
                    ),
                )
                audit_action = "candidate.scan_authorized"
                audit_metadata = {
                    "authorization_reference": authorization_reference[:500]
                }
            self._audit(
                conn,
                actor[:100],
                audit_action,
                "discovery_candidate",
                candidate_id,
                metadata=audit_metadata,
            )
            return {
                "candidate_id": candidate_id,
                "run_id": run_id,
                "job_id": job_id,
                "job_created": created,
            }

    def reject_discovery_candidate(self, candidate_id: int, actor: str) -> bool:
        with self.pool.connection() as conn:
            row = conn.execute(
                """
                UPDATE discovery_candidates
                SET status = 'rejected', updated_at = now()
                WHERE id = %s AND status IN ('pending_metadata', 'pending_review')
                RETURNING id
                """,
                (candidate_id,),
            ).fetchone()
            if row:
                self._audit(
                    conn,
                    actor[:100],
                    "candidate.rejected",
                    "discovery_candidate",
                    candidate_id,
                )
            return row is not None

    def list_notifications(self, *, limit: int = 100) -> list[dict[str, Any]]:
        with self.pool.connection() as conn:
            rows = conn.execute(
                """
                SELECT n.id, r.full_name AS repository, n.finding_id, n.channel, n.status,
                       n.title, n.approved_by, n.approved_at, n.sent_at, n.external_url,
                       n.last_error, n.created_at, n.updated_at
                FROM notification_outbox n
                JOIN repositories r ON r.id = n.repository_id
                ORDER BY n.created_at DESC, n.id DESC
                LIMIT %s
                """,
                (min(max(limit, 1), 500),),
            ).fetchall()
            return [dict(row) for row in rows]

    def get_notification(self, notification_id: int) -> dict[str, Any] | None:
        with self.pool.connection() as conn:
            row = conn.execute(
                """
                SELECT n.*, r.full_name AS repository
                FROM notification_outbox n
                JOIN repositories r ON r.id = n.repository_id
                WHERE n.id = %s
                """,
                (notification_id,),
            ).fetchone()
            if not row:
                return None
            related = conn.execute(
                """
                SELECT f.id, f.type_id, f.platform, f.category, f.risk,
                       f.environment, f.confidence, f.secret_hint,
                       f.validation_status, f.status
                FROM notification_findings nf
                JOIN findings f ON f.id = nf.finding_id
                WHERE nf.notification_id = %s
                ORDER BY CASE f.risk WHEN 'critical' THEN 4 WHEN 'high' THEN 3
                         WHEN 'medium' THEN 2 ELSE 1 END DESC, f.id
                """,
                (notification_id,),
            ).fetchall()
            result = dict(row)
            result["findings"] = [dict(item) for item in related]
            return result

    def list_jobs(self, *, limit: int = 100) -> list[dict[str, Any]]:
        with self.pool.connection() as conn:
            rows = conn.execute(
                """
                SELECT id, run_id, kind, natural_key, payload, status, priority,
                       attempts, max_attempts, available_at, lease_owner, leased_until,
                       last_error, created_at, updated_at, completed_at
                FROM scan_jobs
                ORDER BY created_at DESC, id DESC
                LIMIT %s
                """,
                (min(max(limit, 1), 500),),
            ).fetchall()
            return [dict(row) for row in rows]

    def record_pipeline_event(
        self, redis_entry_id: str, fields: dict[str, Any]
    ) -> bool:
        """Indexa um evento Redis sanitizado de forma idempotente."""
        raw_payload = fields.get("payload") or {}
        if isinstance(raw_payload, str):
            raw_payload = json.loads(raw_payload)
        payload = dict(raw_payload) if isinstance(raw_payload, dict) else {}
        raw_job_id = str(fields.get("job_id") or "").strip()
        job_id = int(raw_job_id) if raw_job_id.isdigit() else None
        occurred_at = str(fields.get("occurred_at") or datetime.now(timezone.utc).isoformat())
        with self.pool.connection() as conn:
            row = conn.execute(
                """
                INSERT INTO pipeline_events
                    (redis_entry_id, event_key, event_type, stage, job_id, kind,
                     payload, occurred_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb, %s::timestamptz)
                ON CONFLICT (event_key) DO NOTHING
                RETURNING id
                """,
                (
                    redis_entry_id,
                    str(fields.get("event_key") or redis_entry_id),
                    str(fields.get("event_type") or "unknown"),
                    str(fields.get("stage") or "unknown"),
                    job_id,
                    str(fields.get("kind") or ""),
                    json.dumps(payload, ensure_ascii=False),
                    occurred_at,
                ),
            ).fetchone()
            return row is not None

    def list_pipeline_events(self, *, limit: int = 100) -> list[dict[str, Any]]:
        with self.pool.connection() as conn:
            rows = conn.execute(
                """
                SELECT id, redis_entry_id, event_key, event_type, stage, job_id,
                       kind, payload, occurred_at, indexed_at
                FROM pipeline_events
                ORDER BY occurred_at DESC, id DESC
                LIMIT %s
                """,
                (min(max(int(limit), 1), 500),),
            ).fetchall()
            return [dict(row) for row in rows]

    def list_runs(self, *, limit: int = 100) -> list[dict[str, Any]]:
        with self.pool.connection() as conn:
            rows = conn.execute(
                """
                SELECT id, mode, scope, status, jobs_created, findings_created,
                       errors, started_at, finished_at
                FROM scan_runs
                ORDER BY started_at DESC, id DESC
                LIMIT %s
                """,
                (min(max(limit, 1), 500),),
            ).fetchall()
            return [dict(row) for row in rows]

    def stats(self) -> dict[str, int]:
        with self.pool.connection() as conn:
            row = conn.execute(
                """
                SELECT
                    (SELECT count(*) FROM findings WHERE status = 'open')::int AS open_findings,
                    (SELECT count(*) FROM scan_jobs WHERE status = 'pending')::int AS pending_jobs,
                    (SELECT count(*) FROM scan_jobs WHERE status = 'running')::int AS running_jobs,
                    (SELECT count(*) FROM notification_outbox WHERE status = 'pending_review')::int
                        AS pending_reviews,
                    (SELECT count(*) FROM discovery_candidates WHERE status = 'pending_metadata')::int
                        AS pending_candidate_metadata,
                    (SELECT count(*) FROM discovery_candidates WHERE status = 'pending_review')::int
                        AS pending_candidate_reviews
                """
            ).fetchone()
            return dict(row)

    def approve_notification(self, notification_id: int, actor: str) -> bool:
        with self.pool.connection() as conn:
            row = conn.execute(
                """
                UPDATE notification_outbox
                SET status = 'approved', approved_by = %s, approved_at = now(), updated_at = now()
                WHERE id = %s AND status = 'pending_review'
                RETURNING id
                """,
                (actor, notification_id),
            ).fetchone()
            if row:
                self._audit(conn, actor, "notification.approved", "notification", notification_id)
            return row is not None

    def reject_notification(self, notification_id: int, actor: str) -> bool:
        with self.pool.connection() as conn:
            row = conn.execute(
                """
                UPDATE notification_outbox
                SET status = 'rejected', updated_at = now()
                WHERE id = %s AND status = 'pending_review'
                RETURNING id
                """,
                (notification_id,),
            ).fetchone()
            if row:
                self._audit(conn, actor, "notification.rejected", "notification", notification_id)
            return row is not None

    def requeue_notification(self, notification_id: int, actor: str) -> bool:
        """Recuperação manual após conferir que a tentativa externa não foi criada."""
        with self.pool.connection() as conn:
            row = conn.execute(
                """
                UPDATE notification_outbox
                SET status = CASE WHEN status = 'rejected' THEN 'pending_review'
                                  ELSE 'approved' END,
                    last_error = '', updated_at = now()
                WHERE id = %s
                  AND status IN ('rejected', 'failed', 'needs_contact', 'sending')
                RETURNING id
                """,
                (notification_id,),
            ).fetchone()
            if row:
                self._audit(conn, actor, "notification.requeued", "notification", notification_id)
            return row is not None

    def claim_notification(self) -> dict[str, Any] | None:
        """Transição at-most-once: approved -> sending antes da chamada externa."""
        with self.pool.connection() as conn:
            row = conn.execute(
                """
                WITH candidate AS (
                    SELECT id FROM notification_outbox
                    WHERE status = 'approved'
                    ORDER BY approved_at, id
                    FOR UPDATE SKIP LOCKED
                    LIMIT 1
                )
                UPDATE notification_outbox n
                SET status = 'sending', updated_at = now()
                FROM candidate
                WHERE n.id = candidate.id
                RETURNING n.*,
                    (SELECT full_name FROM repositories WHERE id = n.repository_id) AS repository
                """
            ).fetchone()
            return dict(row) if row else None

    def finish_notification(
        self,
        notification_id: int,
        *,
        status: str,
        external_url: str = "",
        error: str = "",
    ) -> None:
        if status not in {"sent", "needs_contact", "failed"}:
            raise ValueError("status final de notificação inválido")
        with self.pool.connection() as conn:
            conn.execute(
                """
                UPDATE notification_outbox
                SET status = %s, sent_at = CASE WHEN %s = 'sent' THEN now() ELSE sent_at END,
                    external_url = NULLIF(%s, ''), last_error = %s, updated_at = now()
                WHERE id = %s AND status = 'sending'
                """,
                (status, status, external_url, error[:1000], notification_id),
            )
            if status == "sent":
                conn.execute(
                    """
                    UPDATE findings f
                    SET status = 'notified', last_seen = last_seen
                    FROM notification_findings nf
                    WHERE nf.notification_id = %s AND nf.finding_id = f.id
                      AND f.status = 'open'
                    """,
                    (notification_id,),
                )
            self._audit(
                conn, "notification-worker", f"notification.{status}",
                "notification", notification_id,
            )

    @staticmethod
    def _audit(
        conn,
        actor: str,
        action: str,
        entity_type: str,
        entity_id: int,
        *,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        conn.execute(
            """
            INSERT INTO audit_events (actor, action, entity_type, entity_id, metadata)
            VALUES (%s, %s, %s, %s, %s::jsonb)
            """,
            (actor, action, entity_type, entity_id, json.dumps(metadata or {})),
        )
