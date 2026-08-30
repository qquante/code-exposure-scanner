"""Cliente da API do GitHub: busca em código (search/code) + fetch de arquivos.

Atenção a limites:
  - search/code exige autenticação e tem bucket próprio; o valor atual deve ser
    conferido nos headers/documentação. O deploy usa 8/min por padrão.
  - Contents API usa a cota core (5.000 req/h com token).
O cliente aplica throttle no search/code e backoff em 429/403 (secondary rate limit).
"""

from __future__ import annotations

import base64
import time
from collections import deque
from collections.abc import Callable
from urllib.parse import quote

import requests

from .ai_detection.catalog import AI_SEARCH_QUERIES
from .config import Config
from .evidence import maybe_evidence_store

BASE = "https://api.github.com"

# Literal de busca representativo por tipo (só os que fazem sentido indexar).
# Tipos sem literal útil (ex.: 0x... casa com qualquer hash) são pulados no
# search/code e cobertos apenas pelo scan de repositório/histórico.
SEARCH_QUERIES: dict[str, str] = {
    "stripe_live": '"sk_live_"',
    "stripe_restricted": '"rk_live_"',
    "stripe_test": '"sk_test_"',
    "mercadopago": '"APP_USR-"',
    "aws_akia": '"AKIA"',
    "aws_asia": '"ASIA"',
    "mongodb_uri": '"mongodb+srv://"',
    "postgres_uri": '"postgresql://"',
    "mysql_uri": '"mysql://"',
    "redis_uri": '"redis://"',
    "github_pat": '"ghp_"',
    "github_fine_grained": '"github_pat_"',
    "github_oauth": '"gho_"',
    "gitlab_pat": '"glpat-"',
    "slack_token": '"xoxb-"',
    "private_key_pem": '"PRIVATE KEY"',
    "evm_private_key_to_account": '"privateKeyToAccount"',
    "evm_ethers_wallet": '"new ethers.Wallet"',
    "evm_account_from_key": '"Account.from_key"',
    "evm_private_key_env": '"EVM_PRIVATE_KEY"',
    "solana_from_secret_key": '"Keypair.fromSecretKey"',
    "solana_from_seed": '"Keypair.fromSeed"',
    "bip39_mnemonic_to_account": '"mnemonicToAccount"',
    **AI_SEARCH_QUERIES,
}

PRIVATE_KEY_SEARCH_TYPE_IDS = frozenset(
    {
        "private_key_pem",
        "evm_private_key_to_account",
        "evm_ethers_wallet",
        "evm_account_from_key",
        "evm_private_key_env",
        "solana_from_secret_key",
        "solana_from_seed",
        "bip39_mnemonic_to_account",
    }
)


def enabled_search_type_ids(cfg: Config) -> tuple[str, ...]:
    """Filtra as queries para IA e, opcionalmente, private keys."""
    enabled: set[str] = set()
    if cfg.ai_detection_enabled:
        enabled.update(AI_SEARCH_QUERIES)
    if cfg.private_key_detection_enabled:
        enabled.update(PRIVATE_KEY_SEARCH_TYPE_IDS)
    requested = cfg.search_types or tuple(SEARCH_QUERIES)
    return tuple(type_id for type_id in requested if type_id in enabled)


class GitHubError(Exception):
    pass


class GitHubClient:
    def __init__(
        self,
        cfg: Config,
        *,
        before_search_request: Callable[[], None] | None = None,
    ):
        self.cfg = cfg
        self.before_search_request = before_search_request
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": cfg.user_agent,
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": cfg.github_api_version,
            }
        )
        if cfg.github_token:
            self.session.headers["Authorization"] = f"Bearer {cfg.github_token}"
        self.evidence = maybe_evidence_store(cfg)
        # throttle do search/code (cota autenticada atual: 10/min)
        self._search_calls: deque[float] = deque()

    # ------------------------------------------------------------------ #
    def _throttle_search(self) -> None:
        """Throttle local — usado APENAS quando não há before_search_request (DB rate limiter).
        Quando o pipeline usa o DB rate limiter (before_search_request), este método é no-op."""
        if self.before_search_request is not None:
            return  # DB rate limiter já coordena entre workers
        now = time.monotonic()
        while self._search_calls and now - self._search_calls[0] > 60:
            self._search_calls.popleft()
        limit = max(1, self.cfg.search_requests_per_minute)
        if len(self._search_calls) >= limit:
            wait = 60 - (now - self._search_calls[0]) + 0.5
            print(f"    [throttle] code-search: aguardando {wait:.1f}s")
            time.sleep(max(wait, 0))
            now = time.monotonic()
            self._search_calls.clear()
        self._search_calls.append(now)

    def _request(self, method: str, url: str, *, retries: int = 4, **kwargs) -> requests.Response:
        kwargs.setdefault("timeout", self.cfg.request_timeout)
        for attempt in range(retries):
            resp = self.session.request(method, url, **kwargs)
            if self.evidence is not None:
                self.evidence.capture_http_response(
                    source="github.rest",
                    method=method,
                    url=url,
                    response=resp,
                    request_params=kwargs.get("params"),
                    request_headers=kwargs.get("headers"),
                )
            if resp.status_code == 403 and "rate limit" in resp.text.lower():
                # secondary rate limit ou core limit: espera e tenta de novo
                wait = self._parse_retry_after(resp) or (10 * (2 ** attempt))
                print(f"    [rate-limit] 403 em {url.split('?')[0]} — esperando {wait}s")
                time.sleep(wait)
                continue
            if resp.status_code == 429:
                wait = self._parse_retry_after(resp) or (10 * (2 ** attempt))
                print(f"    [429] aguardando {wait}s")
                time.sleep(wait)
                continue
            return resp
        return resp

    @staticmethod
    def _parse_retry_after(resp: requests.Response) -> int | None:
        val = resp.headers.get("Retry-After")
        if val is None:
            val = resp.headers.get("X-RateLimit-Reset")
            if val is not None:
                try:
                    return max(int(val) - int(time.time()) + 1, 1)
                except ValueError:
                    return None
        try:
            return int(val)
        except (TypeError, ValueError):
            return None

    # ------------------------------------------------------------------ #
    def search_code(self, query: str, *, per_page: int | None = None) -> list[dict]:
        """Busca arquivos via /search/code e pagina os resultados."""
        per_page = per_page or self.cfg.search_per_page
        items: list[dict] = []
        max_pages = max(self.cfg.search_max_pages, 1)
        page = 1
        while True:
            if self.before_search_request:
                self.before_search_request()
            self._throttle_search()
            url = (
                f"{BASE}/search/code?q={quote(query)}&sort=indexed&order=desc"
                f"&per_page={per_page}&page={page}"
            )
            resp = self._request("GET", url)
            if resp.status_code == 422:
                # query inválida (ex.: literal muito curto) — encerra sem erro fatal
                print(f"    [skip] query inválida: {query!r} ({resp.json().get('message', '')})")
                return items
            if resp.status_code != 200:
                raise GitHubError(f"search/code {resp.status_code}: {resp.text[:300]}")
            data = resp.json()
            items.extend(data.get("items", []))
            result_cap = min(int(data.get("total_count", 0)), 1000)
            if page >= max_pages or page * per_page >= result_cap:
                break
            page += 1
        return items

    # ------------------------------------------------------------------ #
    def fetch_file(self, repo: str, path: str, ref: str | None = None) -> str | None:
        """Baixa o conteúdo de um arquivo e retorna como texto (None se inviável)."""
        url = f"{BASE}/repos/{repo}/contents/{quote(path)}"
        params = {"ref": ref} if ref else {}
        resp = self._request("GET", url, params=params)
        if resp.status_code != 200:
            return None
        data = resp.json()
        if isinstance(data, list):  # é um diretório
            return None
        if data.get("size", 0) > self.cfg.max_file_bytes:
            print(f"    [skip] arquivo grande demais: {repo}/{path}")
            return None
        if data.get("encoding") != "base64" or not data.get("content"):
            return None
        try:
            raw = base64.b64decode(data["content"])
        except Exception:
            return None
        try:
            return raw.decode("utf-8", errors="replace")
        except Exception:
            return None

    def fetch_blob(self, repo: str, blob_sha: str) -> str | None:
        """Busca o blob imutável retornado por search/code."""
        url = f"{BASE}/repos/{repo}/git/blobs/{quote(blob_sha, safe='')}"
        resp = self._request("GET", url)
        if resp.status_code != 200:
            return None
        data = resp.json()
        if int(data.get("size") or 0) > self.cfg.max_file_bytes:
            return None
        if data.get("encoding") != "base64" or not data.get("content"):
            return None
        try:
            raw = base64.b64decode(data["content"], validate=False)
            return raw.decode("utf-8", errors="replace")
        except (ValueError, UnicodeError):
            return None

    def close(self) -> None:
        if self.evidence is not None:
            self.evidence.close()
        self.session.close()
