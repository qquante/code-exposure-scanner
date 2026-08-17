"""Divulgação responsável com preferência por canal privado.

O worker só recebe drafts previamente aprovados. Não há retry automático da
chamada externa: isso evita Issues/advisories duplicados após uma falha ambígua.
"""

from __future__ import annotations

from typing import Literal

import requests

from .config import Config


DeliveryStatus = Literal["sent", "needs_contact", "failed"]


class GitHubDisclosureClient:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": cfg.github_api_version,
                "User-Agent": cfg.user_agent,
            }
        )
        if cfg.github_notify_token:
            self.session.headers["Authorization"] = f"Bearer {cfg.github_notify_token}"

    def close(self) -> None:
        self.session.close()

    def deliver(
        self,
        repo: str,
        title: str,
        private_body: str,
        public_body: str,
    ) -> tuple[DeliveryStatus, str, str]:
        if not self.cfg.github_notify_token:
            return "failed", "", "GITHUB_NOTIFY_TOKEN ausente"

        enabled = self._private_reporting_enabled(repo)
        if enabled is True:
            return self._send_private(repo, title, private_body)
        if enabled is None:
            return "failed", "", "não foi possível consultar private vulnerability reporting"
        if not self.cfg.allow_public_contact_issue:
            return "needs_contact", "", "repositório sem canal privado; Issue pública desabilitada"
        return self._send_public_contact(repo, title, public_body)

    def _private_reporting_enabled(self, repo: str) -> bool | None:
        try:
            response = self.session.get(
                f"https://api.github.com/repos/{repo}/private-vulnerability-reporting",
                timeout=self.cfg.request_timeout,
            )
        except requests.RequestException:
            return None
        if response.status_code == 200:
            return bool(response.json().get("enabled"))
        if response.status_code == 404:
            return False
        return None

    def _send_private(
        self, repo: str, title: str, body: str
    ) -> tuple[DeliveryStatus, str, str]:
        try:
            response = self.session.post(
                f"https://api.github.com/repos/{repo}/security-advisories/reports",
                json={"summary": title, "description": body},
                timeout=self.cfg.request_timeout,
            )
        except requests.RequestException as exc:
            return "failed", "", f"falha de rede: {type(exc).__name__}"
        if response.status_code == 201:
            return "sent", response.json().get("html_url", ""), ""
        return "failed", "", f"private report HTTP {response.status_code}"

    def _send_public_contact(
        self, repo: str, title: str, body: str
    ) -> tuple[DeliveryStatus, str, str]:
        try:
            response = self.session.post(
                f"https://api.github.com/repos/{repo}/issues",
                json={"title": title, "body": body},
                timeout=self.cfg.request_timeout,
            )
        except requests.RequestException as exc:
            return "failed", "", f"falha de rede: {type(exc).__name__}"
        if response.status_code == 201:
            return "sent", response.json().get("html_url", ""), ""
        return "failed", "", f"public contact issue HTTP {response.status_code}"
