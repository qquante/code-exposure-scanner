"""Escaneamento do HISTÓRICO de commits.

Dois caminhos:
  1. NativeGitScanner — reproduz a lógica do TruffleHog em Python puro:
     percorre TODOS os commits e analisa os diffs (arquivos adicionados),
     pegando segredos que já foram "apagados" do código atual.
  2. trufflehog_cli — invoca o TruffleHog real (se instalado) e converte a
     saída JSON para o nosso formato Finding.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
from pathlib import Path

from . import patterns as P
from .config import Config
from .extract import Finding, extract_from_text


# --------------------------------------------------------------------------- #
# 1. Scanner nativo (sem dependências externas)
# --------------------------------------------------------------------------- #
class NativeGitScanner:
    def __init__(self, cfg: Config):
        self.cfg = cfg

    def scan_repo(self, repo_url: str) -> list[Finding]:
        """Clona (shallow=False) num dir temporário e varre o histórico completo."""
        repo_name = normalize_github_repo(repo_url)
        if repo_name is None:
            print("    [erro] apenas URLs HTTPS de repositórios github.com são aceitas")
            return []
        with tempfile.TemporaryDirectory() as tmp:
            clone_dir = Path(tmp) / "repo.git"
            env = os.environ.copy()
            env["GIT_CONFIG_GLOBAL"] = os.devnull
            env["GIT_CONFIG_NOSYSTEM"] = "1"
            r = subprocess.run(
                [
                    "git", "-c", "protocol.file.allow=never", "clone", "--mirror",
                    "--quiet", "--", f"https://github.com/{repo_name}.git", str(clone_dir),
                ],
                capture_output=True, text=True, env=env,
            )
            if r.returncode != 0:
                print(f"    [erro] clone falhou: {r.stderr.strip()[:200]}")
                return []
            return self.scan_local(clone_dir, repo=repo_name)

    def scan_local(self, repo_dir: Path, repo: str = "") -> list[Finding]:
        """Varre o histórico de um repo já clonado via `git log -p`."""
        findings: list[Finding] = []
        r = subprocess.run(
            ["git", "-C", str(repo_dir), "log", "--all", "--no-merges",
             "--no-textconv", "--no-ext-diff", "-p", "-U0",
             "--format=@@COMMIT@@%H"],
            capture_output=True, text=True, errors="replace",
        )
        if r.returncode != 0:
            print(f"    [erro] git log falhou: {r.stderr.strip()[:200]}")
            return findings

        current_commit = ""
        current_path = ""
        current_file_text: list[str] = []  # linhas ADICIONADAS do diff acumuladas

        def flush() -> None:
            if current_file_text and current_commit:
                text = "\n".join(current_file_text)
                for f in extract_from_text(
                    text, repo=repo, path=current_path, commit=current_commit, source="history"
                ):
                    # O diff agregado não preserva com precisão a linha final do arquivo.
                    # Zero é mais honesto do que publicar uma localização incorreta.
                    f.line = 0
                    findings.append(f)
            current_file_text.clear()

        for line in r.stdout.splitlines():
            if line.startswith("@@COMMIT@@"):
                flush()
                current_commit = line.removeprefix("@@COMMIT@@").strip()
            elif line.startswith("diff --git"):
                flush()
                # extrai o caminho `b/...`
                parts = line.split(" b/")
                current_path = parts[1] if len(parts) > 1 else ""
            elif line.startswith("+++ "):
                # caminho mais confiável em diff unificado
                path = line[4:]
                if path.startswith("b/"):
                    path = path[2:]
                current_path = path
            elif line.startswith("+") and not line.startswith("+++"):
                # linha adicionada (não removida)
                current_file_text.append(line[1:])
        flush()
        return findings


# --------------------------------------------------------------------------- #
# 2. Integração com o TruffleHog real (opcional)
# --------------------------------------------------------------------------- #
def trufflehog_available() -> bool:
    try:
        r = subprocess.run(["trufflehog", "--version"], capture_output=True, text=True)
        return r.returncode == 0
    except OSError:
        return False


def trufflehog_scan(repo_url: str, cfg: Config) -> list[Finding]:
    """Roda `trufflehog git <url> --json` e converte para Findings."""
    findings: list[Finding] = []
    repo = normalize_github_repo(repo_url)
    if repo is None:
        return findings
    try:
        r = subprocess.run(
            [
                "trufflehog", "git", f"https://github.com/{repo}.git", "--json", "--no-update",
                "--no-verification",
            ],
            capture_output=True, text=True, timeout=600,
        )
    except FileNotFoundError:
        return []
    except subprocess.TimeoutExpired:
        print("    [warn] trufflehog atingiu timeout")
        return findings

    for raw in r.stdout.splitlines():
        raw = raw.strip()
        if not raw:
            continue
        try:
            item = json.loads(raw)
        except json.JSONDecodeError:
            continue
        finding = _trufflehog_to_finding(item)
        if finding.secret_raw and normalize_github_repo(finding.repo):
            findings.append(finding)
    return findings


def _trufflehog_to_finding(item: dict) -> Finding:
    sid = item.get("DetectorName", "trufflehog")
    raw = item.get("Raw", "") or item.get("RawV2", "")
    detected = extract_from_text(raw)
    st = P.TYPES_BY_ID.get(detected[0].type_id) if detected else P.TYPES_BY_ID.get(sid)
    risk = st.risk if st else "medium"
    provider = st.provider if st else sid
    category = st.category if st else "generic"

    from .extract import redact

    git_data = item.get("SourceMetadata", {}).get("Data", {}).get("Git") or {}
    if not git_data:
        git_data = item.get("SourceMetadata", {}).get("Data", {}).get("Github") or {}
    repo_raw = git_data.get("repository", "")
    repo = normalize_github_repo(repo_raw) or repo_raw

    return Finding(
        type_id=st.type_id if st else "trufflehog",
        provider=provider,
        category=category,
        risk=risk,
        secret_redacted=redact(raw),
        secret_raw=raw,
        repo=repo,
        path=git_data.get("file", ""),
        commit=git_data.get("commit", ""),
        line=int(git_data.get("line") or 0),
        source="trufflehog",
        validate_status="provider_active" if item.get("Verified") else "not_checked",
    )


_GITHUB_REPO_RE = re.compile(
    r"^(?:https://github\.com/)?(?P<repo>[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?)(?:\.git)?/?$"
)


def normalize_github_repo(value: str) -> str | None:
    """Normaliza owner/repo e rejeita hosts, credenciais e opções arbitrárias."""
    match = _GITHUB_REPO_RE.fullmatch(value.strip())
    return match.group("repo").lower() if match else None
