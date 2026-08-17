"""Criação de Issues de alerta no repositório afetado.

Suporta:
  - API REST do GitHub (via token GITHUB_NOTIFY_TOKEN);
  - `gh issue create` como fallback;
  - `--dry-run` (default) que apenas imprime o que seria enviado.
"""

from __future__ import annotations

import subprocess

import requests

from .config import Config
from .report import build_issue_body, build_issue_title

BASE = "https://api.github.com"


def create_issue(repo: str, title: str, body: str, cfg: Config, dry_run: bool = True) -> bool:
    """Cria (ou simula) uma Issue no repo `owner/name`."""
    if dry_run:
        print(f"\n=== DRY-RUN ===\nRepo: {repo}\nTítulo: {title}\n{'-' * 40}")
        print(body[:1500] + ("…" if len(body) > 1500 else ""))
        print("-" * 40)
        return True

    if "/" not in repo:
        print(f"[erro] repo inválido: {repo!r}")
        return False

    if not cfg.github_notify_token:
        # fallback para o gh CLI
        r = subprocess.run(
            ["gh", "issue", "create", "--repo", repo, "--title", title, "--body", body],
            capture_output=True, text=True,
        )
        if r.returncode == 0:
            print(f"[ok] issue criada em {repo} (gh)")
            return True
        print(f"[erro] gh falhou: {r.stderr.strip()[:300]}")
        return False

    headers = {
        "Authorization": f"Bearer {cfg.github_notify_token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": cfg.github_api_version,
        "User-Agent": cfg.user_agent,
    }
    try:
        resp = requests.post(
            f"{BASE}/repos/{repo}/issues",
            json={"title": title, "body": body},
            headers=headers,
            timeout=cfg.request_timeout,
        )
    except Exception as exc:
        print(f"[erro] falha de rede: {exc}")
        return False

    if resp.status_code == 201:
        print(f"[ok] issue criada: {resp.json().get('html_url')}")
        return True
    print(f"[erro] HTTP {resp.status_code}: {resp.text[:300]}")
    return False
