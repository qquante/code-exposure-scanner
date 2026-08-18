"""Pré-scan limitado da árvore atual antes de qualquer histórico completo."""

from __future__ import annotations

import os
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .config import Config
from .extract import Finding, extract_from_text
from .scan_policy import is_dependency_path
from .history_scan import normalize_github_repo


_PRIORITY_NAMES = (
    ".env",
    "credential",
    "key",
    "mnemonic",
    "private",
    "secret",
    "seed",
    "wallet",
)


@dataclass(frozen=True)
class HeadScanResult:
    findings: tuple[Finding, ...]
    files_scanned: int
    bytes_scanned: int
    truncated: bool
    commit: str = ""


class HeadGitScanner:
    """Clona somente o HEAD e varre arquivos dentro de limites rígidos."""

    def __init__(self, cfg: Config):
        self.cfg = cfg

    def scan_repo(self, repo_url: str) -> HeadScanResult:
        repo = normalize_github_repo(repo_url)
        if repo is None:
            raise ValueError("repositório GitHub inválido")
        with tempfile.TemporaryDirectory() as tmp:
            clone_dir = Path(tmp) / "repo"
            env = os.environ.copy()
            env["GIT_CONFIG_GLOBAL"] = os.devnull
            env["GIT_CONFIG_NOSYSTEM"] = "1"
            try:
                result = subprocess.run(
                    [
                        "git",
                        "-c",
                        "protocol.file.allow=never",
                        "clone",
                        "--depth",
                        "1",
                        "--single-branch",
                        "--no-tags",
                        "--quiet",
                        "--",
                        f"https://github.com/{repo}.git",
                        str(clone_dir),
                    ],
                    capture_output=True,
                    text=True,
                    env=env,
                    timeout=max(self.cfg.discovery_head_scan_timeout_seconds, 10),
                )
            except subprocess.TimeoutExpired as exc:
                raise RuntimeError("clone raso excedeu o timeout") from exc
            if result.returncode != 0:
                error = result.stderr.strip().replace("\n", " ")[:200]
                raise RuntimeError(f"clone raso falhou: {error}")
            commit = self._head_commit(clone_dir, env)
            return self.scan_tree(clone_dir, repo=repo, commit=commit)

    @staticmethod
    def _head_commit(repo_dir: Path, env: dict[str, str]) -> str:
        result = subprocess.run(
            ["git", "-C", str(repo_dir), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            env=env,
            timeout=10,
        )
        return result.stdout.strip() if result.returncode == 0 else ""

    def scan_tree(self, root: Path, *, repo: str, commit: str = "") -> HeadScanResult:
        root = root.resolve()
        candidates: list[tuple[str, Path]] = []
        for current, directories, files in os.walk(root, followlinks=False):
            current_path = Path(current)
            directories[:] = sorted(
                name
                for name in directories
                if name != ".git"
                and not is_dependency_path((current_path / name).relative_to(root).as_posix())
            )
            for name in sorted(files):
                path = current_path / name
                if path.is_symlink() or not path.is_file():
                    continue
                relative = path.relative_to(root).as_posix()
                if is_dependency_path(relative):
                    continue
                candidates.append((relative, path))

        candidates.sort(key=lambda item: self._priority(item[0]))
        max_files = max(self.cfg.discovery_head_scan_max_files, 1)
        max_total = max(self.cfg.discovery_head_scan_max_total_bytes, 1)
        findings: list[Finding] = []
        files_scanned = 0
        bytes_scanned = 0
        truncated = len(candidates) > max_files

        for relative, path in candidates:
            if files_scanned >= max_files:
                break
            try:
                size = path.stat().st_size
            except OSError:
                continue
            if size > self.cfg.max_file_bytes:
                truncated = True
                continue
            if bytes_scanned + size > max_total:
                truncated = True
                continue
            try:
                raw = path.read_bytes()
            except OSError:
                continue
            files_scanned += 1
            bytes_scanned += len(raw)
            if b"\0" in raw[:8192]:
                continue
            text = raw.decode("utf-8", errors="replace")
            findings.extend(
                extract_from_text(
                    text,
                    repo=repo,
                    path=relative,
                    commit=commit,
                    source="head",
                )
            )

        return HeadScanResult(
            findings=tuple(findings),
            files_scanned=files_scanned,
            bytes_scanned=bytes_scanned,
            truncated=truncated,
            commit=commit,
        )

    @staticmethod
    def _priority(relative: str) -> tuple[int, str]:
        lowered = relative.lower()
        important = any(part in lowered for part in _PRIORITY_NAMES)
        return (0 if important else 1, lowered)
