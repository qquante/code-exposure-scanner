"""Persistência segura dos achados.

REGRA DE OURO: NUNCA gravamos o segredo bruto. Apenas:
  - fingerprint = HMAC-SHA256(segredo, salt_local) — para deduplicar sem
    armazenar o valor (e sem permitir rainbow tables via salt por instalação);
  - secret_redacted = prefixo…sufixo, para o analista identificar o achado.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import sqlite3
from pathlib import Path

from .config import Config
from .extract import Finding

_SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint TEXT NOT NULL,
    type_id TEXT NOT NULL,
    provider TEXT NOT NULL,
    category TEXT NOT NULL,
    risk TEXT NOT NULL,
    secret_redacted TEXT NOT NULL,
    repo TEXT NOT NULL DEFAULT '',
    path TEXT NOT NULL DEFAULT '',
    branch TEXT NOT NULL DEFAULT '',
    commit_sha TEXT NOT NULL DEFAULT '',
    line INTEGER NOT NULL DEFAULT 0,
    context TEXT NOT NULL DEFAULT '',
    source TEXT NOT NULL DEFAULT 'code',
    validate_status TEXT NOT NULL DEFAULT '',
    validate_detail TEXT NOT NULL DEFAULT '',
    notified INTEGER NOT NULL DEFAULT 0,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_fp_repo
    ON findings (fingerprint, repo);
"""


class Store:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        cfg.output_dir.mkdir(parents=True, exist_ok=True)
        cfg.db_path.parent.mkdir(parents=True, exist_ok=True)
        cfg.salt_path.parent.mkdir(parents=True, exist_ok=True)
        self._salt = self._load_or_create_salt()
        self._conn = sqlite3.connect(str(cfg.db_path), timeout=30)
        try:
            self._conn.execute("PRAGMA busy_timeout = 30000")
            self._conn.execute("PRAGMA journal_mode = WAL")
            self._conn.executescript(_SCHEMA)
        except Exception:
            self._conn.close()
            raise

    # ------------------------------------------------------------------ #
    def _load_or_create_salt(self) -> bytes:
        if self.cfg.salt_path.exists():
            return self.cfg.salt_path.read_bytes()
        salt = secrets.token_bytes(32)
        try:
            fd = os.open(self.cfg.salt_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            return self.cfg.salt_path.read_bytes()
        with os.fdopen(fd, "wb") as stream:
            stream.write(salt)
        return salt

    def fingerprint(self, secret: str) -> str:
        return hmac.new(self._salt, secret.encode("utf-8"), hashlib.sha256).hexdigest()

    # ------------------------------------------------------------------ #
    def upsert(self, f: Finding) -> bool:
        """Insere se novo (por fingerprint+repo); atualiza last_seen se repetido."""
        import datetime as _dt
        now = _dt.datetime.utcnow().isoformat(timespec="seconds")
        fp = self.fingerprint(f.secret_raw) if f.secret_raw else (f.fingerprint or "")
        if not fp:
            return False
        f.fingerprint = fp

        cur = self._conn.execute(
            "SELECT id, notified FROM findings WHERE fingerprint = ? AND repo = ?",
            (fp, f.repo),
        )
        row = cur.fetchone()
        if row:
            self._conn.execute(
                "UPDATE findings SET last_seen = ?, validate_status = ? WHERE id = ?",
                (now, f.validate_status, row[0]),
            )
            self._conn.commit()
            return False
        self._conn.execute(
            """INSERT INTO findings
               (fingerprint, type_id, provider, category, risk, secret_redacted,
                repo, path, branch, commit_sha, line, context, source,
                validate_status, validate_detail, notified, first_seen, last_seen)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (fp, f.type_id, f.provider, f.category, f.risk, f.secret_redacted,
             f.repo, f.path, f.branch, f.commit, f.line, f.context, f.source,
             f.validate_status, f.validate_detail, 0, now, now),
        )
        self._conn.commit()
        return True

    # ------------------------------------------------------------------ #
    def mark_notified(self, finding_id: int) -> None:
        self._conn.execute("UPDATE findings SET notified = 1 WHERE id = ?", (finding_id,))
        self._conn.commit()

    def unnotified(self, repo: str | None = None) -> list[dict]:
        q = "SELECT * FROM findings WHERE notified = 0"
        args: tuple = ()
        if repo:
            q += " AND repo = ?"
            args = (repo,)
        q += " ORDER BY CASE risk WHEN 'critical' THEN 4 WHEN 'high' THEN 3 " \
             "WHEN 'medium' THEN 2 ELSE 1 END DESC, id ASC"
        return [dict(zip([c[0] for c in self._conn.execute(q, args).description], row))
                for row in self._conn.execute(q, args).fetchall()]

    def all_findings(self) -> list[dict]:
        cur = self._conn.execute("SELECT * FROM findings ORDER BY id DESC")
        cols = [c[0] for c in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]

    def count(self) -> int:
        return self._conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]

    def close(self) -> None:
        self._conn.close()
