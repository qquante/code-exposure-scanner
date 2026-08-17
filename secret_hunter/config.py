"""Configuração do secret_hunter.

Prioridade: env vars > config.yaml > defaults.
O token de busca e o token de notificacao sao independentes. Valores podem vir
de variaveis de ambiente ou, preferencialmente, de Docker Secrets via *_FILE.
"""

from __future__ import annotations

import os
import socket
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import quote_plus

try:
    import yaml  # type: ignore
except ImportError:  # pragma: no cover
    yaml = None


DEFAULT_CONFIG_PATH = Path("config.yaml")


@dataclass
class Config:
    # Compatibilidade: github_token e o token somente de leitura usado na busca.
    github_token: str = field(default="", repr=False)
    github_notify_token: str = field(default="", repr=False)
    output_dir: Path = field(default_factory=lambda: Path("output"))
    db_path: Path = field(default_factory=lambda: Path("output") / "findings.db")
    salt_path: Path = field(default_factory=lambda: Path("output") / ".salt")
    validate: bool = False           # validação é OPT-IN (ética/legal)
    validate_crypto: bool = False    # valida formato e deriva endereço localmente
    scan_history: bool = True
    entropy_min: float = 3.5
    request_timeout: int = 10
    http_retries: int = 3             # retry de validação de API (transitórios)
    evm_rpc_retries: int = 3          # retry por RPC EVM antes de trocar de endpoint
    max_file_bytes: int = 1_000_000  # pula arquivos > 1 MB no fetch
    search_per_page: int = 30
    search_max_pages: int = 1
    user_agent: str = "secret-hunter/0.2 (white-hat responsible disclosure)"
    github_api_version: str = "2026-03-10"

    # PostgreSQL é a fonte de verdade no deploy distribuído.
    database_url: str = field(default="", repr=False)
    database_host: str = "postgres"
    database_port: int = 5432
    database_name: str = "secret_hunter"
    database_user: str = "secret_hunter"
    database_password: str = field(default="", repr=False)
    fingerprint_key: str = field(default="", repr=False)
    admin_api_token: str = field(default="", repr=False)
    db_pool_min: int = 1
    db_pool_max: int = 12

    # Evidência bruta opcional. PostgreSQL continua como fonte de verdade.
    evidence_enabled: bool = False
    evidence_redis_host: str = "redis-evidence"
    evidence_redis_port: int = 6379
    evidence_redis_db: int = 0
    evidence_redis_password: str = field(default="", repr=False)
    evidence_stream_key: str = "secret-hunter:raw-evidence"

    worker_concurrency: int = 4
    job_lease_seconds: int = 120
    worker_poll_seconds: float = 2.0
    search_window_hours: int = 1
    search_requests_per_minute: int = 8
    search_types: tuple[str, ...] = ()
    search_scope: str = ""
    allow_global_search: bool = False
    ingest_root: Path = field(default_factory=lambda: Path("/ingest"))
    ingest_adapter: str = "tree"
    ingest_source: str = ""
    ingest_poll_seconds: int = 60
    ingest_max_file_bytes: int = 1_000_000
    ingest_allow_symlinks: bool = False
    # Descoberta global segura: janelas fechadas da Search API, sempre head-first.
    # O enfileiramento automatico de scan e opt-in e nao autoriza validacao ativa.
    discovery_poll_seconds: int = 60
    discovery_lease_seconds: int = 180
    discovery_max_pages: int = 10
    discovery_window_seconds: int = 60
    discovery_head_delay_seconds: int = 3_600
    discovery_reconcile_seconds: int = 900
    discovery_windows_per_poll: int = 4
    discovery_search_requests_per_minute: int = 24
    discovery_metadata_requests_per_hour: int = 3_000
    discovery_repositories_per_poll: int = 8
    discovery_auto_queue_scans: bool = False
    discovery_include_forks: bool = False
    discovery_languages: tuple[str, ...] = ()
    discovery_min_size_kb: int = 1
    discovery_max_size_kb: int = 50_000
    discovery_head_scan_max_files: int = 2_000
    discovery_head_scan_max_total_bytes: int = 20_000_000
    discovery_head_scan_timeout_seconds: int = 120
    discovery_head_scan_sample_percent: int = 5
    discovery_head_trigger_categories: tuple[str, ...] = ("crypto",)
    discovery_max_event_age_hours: int = 48
    discovery_retention_days: int = 30
    allow_public_contact_issue: bool = False
    authorized_validation_repos: tuple[str, ...] = ()
    worker_name: str = field(default_factory=lambda: socket.gethostname())

    # ------------------------------------------------------------------ #
    @classmethod
    def from_env(cls, path: Path | None = None) -> "Config":
        cfg = cls()

        if path is None:
            path = DEFAULT_CONFIG_PATH
        if yaml is not None and path.exists():
            try:
                data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            except Exception as exc:  # pragma: no cover
                print(f"[warn] falha ao ler {path}: {exc}")
                data = {}
            _apply(cfg, data)

        # env vars e Docker Secrets sobrescrevem o arquivo
        cfg.github_token = _read_secret(
            ("GITHUB_SEARCH_TOKEN", "GITHUB_TOKEN", "GH_TOKEN"),
            ("GITHUB_SEARCH_TOKEN_FILE", "GITHUB_TOKEN_FILE", "GH_TOKEN_FILE"),
            cfg.github_token,
        )
        cfg.github_notify_token = _read_secret(
            ("GITHUB_NOTIFY_TOKEN", "SH_GITHUB_NOTIFY_TOKEN"),
            ("GITHUB_NOTIFY_TOKEN_FILE", "SH_GITHUB_NOTIFY_TOKEN_FILE"),
            cfg.github_notify_token,
        )
        cfg.database_password = _read_secret(
            ("SH_DATABASE_PASSWORD",), ("SH_DATABASE_PASSWORD_FILE",), ""
        )
        cfg.fingerprint_key = _read_secret(
            ("SH_FINGERPRINT_KEY",), ("SH_FINGERPRINT_KEY_FILE",), ""
        )
        cfg.admin_api_token = _read_secret(
            ("SH_ADMIN_API_TOKEN",), ("SH_ADMIN_API_TOKEN_FILE",), ""
        )
        cfg.evidence_redis_password = _read_secret(
            ("SH_EVIDENCE_REDIS_PASSWORD",),
            ("SH_EVIDENCE_REDIS_PASSWORD_FILE",),
            "",
        )

        for key, env in {
            "validate": "SH_VALIDATE",
            "validate_crypto": "SH_VALIDATE_CRYPTO",
            "scan_history": "SH_SCAN_HISTORY",
            "entropy_min": "SH_ENTROPY_MIN",
            "request_timeout": "SH_REQUEST_TIMEOUT",
            "http_retries": "SH_HTTP_RETRIES",
            "evm_rpc_retries": "SH_EVM_RPC_RETRIES",
            "max_file_bytes": "SH_MAX_FILE_BYTES",
            "search_per_page": "SH_SEARCH_PER_PAGE",
            "search_max_pages": "SH_SEARCH_MAX_PAGES",
            "database_url": "SH_DATABASE_URL",
            "database_host": "SH_DATABASE_HOST",
            "database_port": "SH_DATABASE_PORT",
            "database_name": "SH_DATABASE_NAME",
            "database_user": "SH_DATABASE_USER",
            "db_pool_min": "SH_DB_POOL_MIN",
            "db_pool_max": "SH_DB_POOL_MAX",
            "evidence_enabled": "SH_EVIDENCE_ENABLED",
            "evidence_redis_host": "SH_EVIDENCE_REDIS_HOST",
            "evidence_redis_port": "SH_EVIDENCE_REDIS_PORT",
            "evidence_redis_db": "SH_EVIDENCE_REDIS_DB",
            "evidence_stream_key": "SH_EVIDENCE_STREAM_KEY",
            "worker_concurrency": "SH_WORKER_CONCURRENCY",
            "job_lease_seconds": "SH_JOB_LEASE_SECONDS",
            "worker_poll_seconds": "SH_WORKER_POLL_SECONDS",
            "search_window_hours": "SH_SEARCH_WINDOW_HOURS",
            "search_requests_per_minute": "SH_SEARCH_REQUESTS_PER_MINUTE",

            "search_scope": "SH_SEARCH_SCOPE",
            "allow_global_search": "SH_ALLOW_GLOBAL_SEARCH",
            "ingest_root": "SH_INGEST_ROOT",
            "ingest_adapter": "SH_INGEST_ADAPTER",
            "ingest_source": "SH_INGEST_SOURCE",
            "ingest_poll_seconds": "SH_INGEST_POLL_SECONDS",
            "ingest_max_file_bytes": "SH_INGEST_MAX_FILE_BYTES",
            "ingest_allow_symlinks": "SH_INGEST_ALLOW_SYMLINKS",
            "discovery_poll_seconds": "SH_DISCOVERY_POLL_SECONDS",
            "discovery_lease_seconds": "SH_DISCOVERY_LEASE_SECONDS",
            "discovery_max_pages": "SH_DISCOVERY_MAX_PAGES",
            "discovery_window_seconds": "SH_DISCOVERY_WINDOW_SECONDS",
            "discovery_head_delay_seconds": "SH_DISCOVERY_HEAD_DELAY_SECONDS",
            "discovery_reconcile_seconds": "SH_DISCOVERY_RECONCILE_SECONDS",
            "discovery_windows_per_poll": "SH_DISCOVERY_WINDOWS_PER_POLL",
            "discovery_search_requests_per_minute": "SH_DISCOVERY_SEARCH_REQUESTS_PER_MINUTE",
            "discovery_metadata_requests_per_hour": "SH_DISCOVERY_METADATA_REQUESTS_PER_HOUR",
            "discovery_repositories_per_poll": "SH_DISCOVERY_REPOSITORIES_PER_POLL",
            "discovery_auto_queue_scans": "SH_DISCOVERY_AUTO_QUEUE_SCANS",
            "discovery_include_forks": "SH_DISCOVERY_INCLUDE_FORKS",
            "discovery_min_size_kb": "SH_DISCOVERY_MIN_SIZE_KB",
            "discovery_max_size_kb": "SH_DISCOVERY_MAX_SIZE_KB",
            "discovery_head_scan_max_files": "SH_DISCOVERY_HEAD_SCAN_MAX_FILES",
            "discovery_head_scan_max_total_bytes": "SH_DISCOVERY_HEAD_SCAN_MAX_TOTAL_BYTES",
            "discovery_head_scan_timeout_seconds": "SH_DISCOVERY_HEAD_SCAN_TIMEOUT_SECONDS",
            "discovery_head_scan_sample_percent": "SH_DISCOVERY_HEAD_SCAN_SAMPLE_PERCENT",
            "discovery_max_event_age_hours": "SH_DISCOVERY_MAX_EVENT_AGE_HOURS",
            "discovery_retention_days": "SH_DISCOVERY_RETENTION_DAYS",
            "allow_public_contact_issue": "SH_ALLOW_PUBLIC_CONTACT_ISSUE",
            "worker_name": "SH_WORKER_NAME",
        }.items():
            if isinstance(env, tuple):
                val = next((os.environ.get(e) for e in env if os.environ.get(e)), None)
            else:
                val = os.environ.get(env)
            if val is not None:
                if key in (
                    "validate", "validate_crypto", "scan_history",
                    "allow_public_contact_issue", "allow_global_search",
                    "ingest_allow_symlinks", "discovery_auto_queue_scans",
                    "discovery_include_forks", "evidence_enabled",
                ):
                    setattr(cfg, key, val.strip().lower() in ("1", "true", "yes", "on"))
                elif key in ("entropy_min", "worker_poll_seconds"):
                    setattr(cfg, key, float(val))
                elif key in (
                    "database_port", "db_pool_min", "db_pool_max",
                    "evidence_redis_port", "evidence_redis_db", "worker_concurrency",
                    "job_lease_seconds", "search_window_hours", "request_timeout",
                    "http_retries", "evm_rpc_retries",
                    "max_file_bytes", "search_per_page", "search_max_pages",
                    "ingest_poll_seconds", "ingest_max_file_bytes",
                    "search_requests_per_minute", "discovery_poll_seconds",
                    "discovery_lease_seconds", "discovery_max_pages",
                    "discovery_window_seconds", "discovery_head_delay_seconds",
                    "discovery_reconcile_seconds", "discovery_windows_per_poll",
                    "discovery_search_requests_per_minute",
                    "discovery_metadata_requests_per_hour", "discovery_repositories_per_poll",
                    "discovery_min_size_kb", "discovery_max_size_kb",
                    "discovery_head_scan_max_files",
                    "discovery_head_scan_max_total_bytes",
                    "discovery_head_scan_timeout_seconds",
                    "discovery_head_scan_sample_percent",
                    "discovery_max_event_age_hours", "discovery_retention_days",
                ):
                    setattr(cfg, key, int(val))
                elif key == "ingest_root":
                    setattr(cfg, key, Path(val))
                else:
                    setattr(cfg, key, val)

        allowed = os.environ.get("SH_AUTHORIZED_VALIDATION_REPOS", "")
        cfg.authorized_validation_repos = tuple(
            item.strip().lower() for item in allowed.split(",") if item.strip()
        )
        languages = os.environ.get("SH_DISCOVERY_LANGUAGES", "")
        cfg.discovery_languages = tuple(
            item.strip().lower() for item in languages.split(",") if item.strip()
        )
        search_types = os.environ.get("SH_SEARCH_TYPES")
        if search_types is not None:
            cfg.search_types = tuple(
                item.strip() for item in search_types.split(",") if item.strip()
            )
        trigger_categories = os.environ.get("SH_DISCOVERY_HEAD_TRIGGER_CATEGORIES")
        if trigger_categories is not None:
            cfg.discovery_head_trigger_categories = tuple(
                item.strip().lower()
                for item in trigger_categories.split(",")
                if item.strip()
            )

        return cfg

    def is_validation_authorized(self, repo: str) -> bool:
        """True se a validação está autorizada para o repositório.

        "*" na allowlist autoriza qualquer repositório (modo global).
        """
        canonical = repo.strip().lower()
        return "*" in self.authorized_validation_repos or canonical in self.authorized_validation_repos

    def postgres_dsn(self) -> str:
        if self.database_url:
            return self.database_url
        password = quote_plus(self.database_password)
        user = quote_plus(self.database_user)
        database = quote_plus(self.database_name)
        return (
            f"postgresql://{user}:{password}@{self.database_host}:"
            f"{self.database_port}/{database}"
        )

    def require_distributed_secrets(self) -> None:
        if len(self.fingerprint_key.encode("utf-8")) < 32:
            raise ValueError("SH_FINGERPRINT_KEY deve ter pelo menos 32 bytes")
        if not self.database_url and not self.database_password:
            raise ValueError("senha do PostgreSQL ausente")
        if self.evidence_enabled and not self.evidence_redis_password:
            raise ValueError("senha do Redis de evidências ausente")


def _read_secret(env_names: tuple[str, ...], file_env_names: tuple[str, ...], default: str) -> str:
    for file_env in file_env_names:
        path = os.environ.get(file_env)
        if path:
            return Path(path).read_text(encoding="utf-8").strip()
    for env_name in env_names:
        value = os.environ.get(env_name)
        if value:
            return value.strip()
    return default


def _apply(cfg: Config, data: dict) -> None:
    """Aplica chaves conhecidas do YAML ao objeto Config."""
    if "github_token" in data:
        cfg.github_token = str(data["github_token"])
    if "github_notify_token" in data:
        cfg.github_notify_token = str(data["github_notify_token"])
    if "output_dir" in data:
        cfg.output_dir = Path(str(data["output_dir"]))
        cfg.db_path = cfg.output_dir / "findings.db"
        cfg.salt_path = cfg.output_dir / ".salt"
    if "validate" in data:
        cfg.validate = bool(data["validate"])
    if "validate_crypto" in data:
        cfg.validate_crypto = bool(data["validate_crypto"])
    if "scan_history" in data:
        cfg.scan_history = bool(data["scan_history"])
    if "entropy_min" in data:
        cfg.entropy_min = float(data["entropy_min"])
    if "request_timeout" in data:
        cfg.request_timeout = int(data["request_timeout"])
    if "search_per_page" in data:
        cfg.search_per_page = int(data["search_per_page"])
    for key in (
        "database_host", "database_name", "database_user", "search_scope",
        "ingest_adapter", "ingest_source", "evidence_redis_host",
        "evidence_stream_key",
    ):
        if key in data:
            setattr(cfg, key, str(data[key]))
    for key in (
        "database_port", "db_pool_min", "db_pool_max", "evidence_redis_port",
        "evidence_redis_db", "worker_concurrency",
        "job_lease_seconds", "search_window_hours", "search_requests_per_minute", "search_max_pages",
        "ingest_poll_seconds", "ingest_max_file_bytes", "discovery_poll_seconds",
        "discovery_lease_seconds", "discovery_max_pages",
        "discovery_window_seconds", "discovery_head_delay_seconds",
        "discovery_reconcile_seconds", "discovery_windows_per_poll",
        "discovery_search_requests_per_minute",
        "discovery_metadata_requests_per_hour", "discovery_repositories_per_poll",
        "discovery_min_size_kb", "discovery_max_size_kb",
        "discovery_head_scan_max_files", "discovery_head_scan_max_total_bytes",
        "discovery_head_scan_timeout_seconds",
        "discovery_head_scan_sample_percent",
        "discovery_max_event_age_hours", "discovery_retention_days",
    ):
        if key in data:
            setattr(cfg, key, int(data[key]))
    if "worker_poll_seconds" in data:
        cfg.worker_poll_seconds = float(data["worker_poll_seconds"])
    if "ingest_root" in data:
        cfg.ingest_root = Path(str(data["ingest_root"]))
    for key in (
        "allow_global_search", "allow_public_contact_issue", "ingest_allow_symlinks",
        "discovery_auto_queue_scans", "discovery_include_forks", "evidence_enabled",
    ):
        if key in data:
            setattr(cfg, key, bool(data[key]))
    if "search_types" in data:
        values = data["search_types"]
        if isinstance(values, str):
            values = values.split(",")
        cfg.search_types = tuple(
            str(item).strip() for item in values if str(item).strip()
        )
    if "discovery_languages" in data:
        values = data["discovery_languages"]
        if isinstance(values, str):
            values = values.split(",")
        cfg.discovery_languages = tuple(
            str(item).strip().lower() for item in values if str(item).strip()
        )
    if "discovery_head_trigger_categories" in data:
        values = data["discovery_head_trigger_categories"]
        if isinstance(values, str):
            values = values.split(",")
        cfg.discovery_head_trigger_categories = tuple(
            str(item).strip().lower() for item in values if str(item).strip()
        )
