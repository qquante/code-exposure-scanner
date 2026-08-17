"""Adaptadores seguros para arquivos entregues por conectores externos.

Este modulo nao acessa rede nem descobre repositorios. Ele recebe arquivos ja
materializados em um diretorio read-only, valida confinamento/tamanho/hash e
gera metadados seguros para a fila PostgreSQL.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
from typing import Iterator, Protocol

from .history_scan import normalize_github_repo


_COMMIT_RE = re.compile(r"[0-9a-fA-F]{7,64}")


class IngestError(ValueError):
    """Entrada invalida, insegura ou alterada durante a ingestao."""


@dataclass(frozen=True)
class IngestCandidate:
    repository: str
    source_path: str
    logical_path: str
    sha256: str
    size: int
    branch: str = ""
    commit_sha: str = ""

    def payload(self) -> dict:
        return asdict(self)


class IngestAdapter(Protocol):
    def iter_candidates(self) -> Iterator[IngestCandidate]: ...


def _safe_relative(value: str, *, label: str) -> str:
    candidate = PurePosixPath(value.replace("\\", "/"))
    if not value or candidate.is_absolute() or ".." in candidate.parts:
        raise IngestError(f"{label} deve ser um caminho relativo confinado")
    # PurePosixPath ja remove o prefixo relativo "./"; nao use lstrip aqui,
    # pois ele tambem removeria o ponto legitimo de arquivos como .env.
    normalized = candidate.as_posix()
    if not normalized or normalized == ".":
        raise IngestError(f"{label} vazio")
    return normalized


def resolve_ingest_file(root: Path, relative: str, *, allow_symlinks: bool = False) -> Path:
    """Resolve um arquivo sem permitir path traversal ou escape por symlink."""
    root_resolved = root.resolve(strict=True)
    safe = _safe_relative(relative, label="source_path")
    unresolved = root_resolved.joinpath(*PurePosixPath(safe).parts)
    try:
        resolved = unresolved.resolve(strict=True)
        resolved.relative_to(root_resolved)
    except (OSError, ValueError) as exc:
        raise IngestError("arquivo saiu de SH_INGEST_ROOT") from exc
    if not resolved.is_file():
        raise IngestError("entrada nao e arquivo regular")
    if not allow_symlinks:
        current = root_resolved
        for part in PurePosixPath(safe).parts:
            current = current / part
            if current.is_symlink():
                raise IngestError("symlinks estao desabilitados na ingestao")
    return resolved


def inspect_ingest_file(
    root: Path,
    relative: str,
    *,
    max_bytes: int,
    allow_symlinks: bool = False,
) -> tuple[Path, str, int] | None:
    path = resolve_ingest_file(root, relative, allow_symlinks=allow_symlinks)
    size = path.stat().st_size
    if size > max_bytes:
        return None
    digest = hashlib.sha256()
    head = b""
    seen = 0
    with path.open("rb") as handle:
        while chunk := handle.read(64 * 1024):
            if not head:
                head = chunk[:8192]
            seen += len(chunk)
            if seen > max_bytes:
                return None
            digest.update(chunk)
    if b"\x00" in head:
        return None
    return path, digest.hexdigest(), seen


def read_verified_text(
    root: Path,
    relative: str,
    expected_sha256: str,
    *,
    max_bytes: int,
    allow_symlinks: bool = False,
) -> str:
    path = resolve_ingest_file(root, relative, allow_symlinks=allow_symlinks)
    digest = hashlib.sha256()
    content = bytearray()
    with path.open("rb") as handle:
        while chunk := handle.read(64 * 1024):
            content.extend(chunk)
            if len(content) > max_bytes:
                raise IngestError("arquivo acima do limite")
            digest.update(chunk)
    if b"\x00" in content[:8192]:
        raise IngestError("arquivo binario")
    actual_sha256 = digest.hexdigest()
    if actual_sha256 != expected_sha256:
        raise IngestError("arquivo mudou depois do enqueue; reingira a nova versao")
    return bytes(content).decode("utf-8", errors="replace")


class TreeIngestAdapter:
    """Layout: ROOT/[source/]OWNER/REPOSITORY/caminho/do/arquivo."""

    def __init__(
        self,
        root: Path,
        *,
        source: str = "",
        max_bytes: int = 1_000_000,
        allow_symlinks: bool = False,
    ):
        self.root = root
        self.source = _safe_relative(source, label="source") if source else ""
        self.max_bytes = max_bytes
        self.allow_symlinks = allow_symlinks

    def iter_candidates(self) -> Iterator[IngestCandidate]:
        base = self.root / self.source if self.source else self.root
        base = base.resolve(strict=True)
        base.relative_to(self.root.resolve(strict=True))
        for path in sorted(base.rglob("*")):
            if not path.is_file():
                continue
            relative_to_base = path.relative_to(base)
            if len(relative_to_base.parts) < 3 or ".git" in relative_to_base.parts:
                continue
            owner, name = relative_to_base.parts[:2]
            repository = normalize_github_repo(f"{owner}/{name}")
            if repository is None:
                continue
            source_path = path.relative_to(self.root.resolve(strict=True)).as_posix()
            logical_path = PurePosixPath(*relative_to_base.parts[2:]).as_posix()
            inspected = inspect_ingest_file(
                self.root,
                source_path,
                max_bytes=self.max_bytes,
                allow_symlinks=self.allow_symlinks,
            )
            if inspected is None:
                continue
            _, digest, size = inspected
            yield IngestCandidate(
                repository=repository,
                source_path=source_path,
                logical_path=logical_path,
                sha256=digest,
                size=size,
            )


class ManifestIngestAdapter:
    """JSONL com repository, file e path; branch/commit sao opcionais."""

    def __init__(
        self,
        root: Path,
        *,
        source: str,
        max_bytes: int = 1_000_000,
        allow_symlinks: bool = False,
    ):
        self.root = root
        self.manifest = _safe_relative(source, label="manifest")
        self.max_bytes = max_bytes
        self.allow_symlinks = allow_symlinks

    def iter_candidates(self) -> Iterator[IngestCandidate]:
        manifest_path = resolve_ingest_file(
            self.root, self.manifest, allow_symlinks=self.allow_symlinks
        )
        for line_number, raw_line in enumerate(
            manifest_path.read_text(encoding="utf-8").splitlines(), start=1
        ):
            if not raw_line.strip() or raw_line.lstrip().startswith("#"):
                continue
            try:
                item = json.loads(raw_line)
            except json.JSONDecodeError as exc:
                raise IngestError(f"manifest linha {line_number}: JSON invalido") from exc
            if not isinstance(item, dict):
                raise IngestError(f"manifest linha {line_number}: objeto esperado")
            repository = normalize_github_repo(str(item.get("repository", "")))
            if repository is None:
                raise IngestError(f"manifest linha {line_number}: repository invalido")
            source_path = _safe_relative(str(item.get("file", "")), label="file")
            logical_path = _safe_relative(
                str(item.get("path") or source_path), label="path"
            )
            branch = str(item.get("branch", ""))[:255]
            commit_sha = str(item.get("commit", ""))
            if commit_sha and not _COMMIT_RE.fullmatch(commit_sha):
                raise IngestError(f"manifest linha {line_number}: commit invalido")
            inspected = inspect_ingest_file(
                self.root,
                source_path,
                max_bytes=self.max_bytes,
                allow_symlinks=self.allow_symlinks,
            )
            if inspected is None:
                continue
            _, digest, size = inspected
            yield IngestCandidate(
                repository=repository,
                source_path=source_path,
                logical_path=logical_path,
                sha256=digest,
                size=size,
                branch=branch,
                commit_sha=commit_sha.lower(),
            )


def build_ingest_adapter(
    root: Path,
    adapter: str,
    source: str,
    *,
    max_bytes: int,
    allow_symlinks: bool = False,
) -> IngestAdapter:
    if adapter == "tree":
        return TreeIngestAdapter(
            root, source=source, max_bytes=max_bytes, allow_symlinks=allow_symlinks
        )
    if adapter == "manifest":
        if not source:
            raise IngestError("adapter manifest exige source=arquivo.jsonl")
        return ManifestIngestAdapter(
            root, source=source, max_bytes=max_bytes, allow_symlinks=allow_symlinks
        )
    raise IngestError("adapter deve ser tree ou manifest")
