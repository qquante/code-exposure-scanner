"""Descoberta segura de repositórios públicos recentes via APIs do GitHub.

Este módulo só coleta metadados. Código, arquivos e segredos não são baixados
até que o candidato elegível seja enfileirado conforme a configuração.
"""

from __future__ import annotations

import math
import time
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable
from urllib.parse import quote

import requests

from .config import Config
from .evidence import maybe_evidence_store
from .history_scan import normalize_github_repo


PUBLIC_REPOSITORIES_KEY = "github-public-repositories"
PUSHED_REPOSITORIES_KEY = "github-public-repositories-pushed"
BASE = "https://api.github.com"
PUBLIC_EVENTS_KEY = "github-public-events"


class GitHubDiscoveryError(RuntimeError):
    pass


@dataclass(frozen=True)
class RepositoryCreatedEvent:
    event_id: str
    github_repository_id: int
    repository: str
    event_created_at: str
    metadata: dict[str, Any] | None = None
    recheck_token: str = ""

    def payload(self) -> dict[str, Any]:
        result = {
            "event_id": self.event_id,
            "github_repository_id": self.github_repository_id,
            "repository": self.repository,
            "event_created_at": self.event_created_at,
        }
        if self.metadata is not None:
            result["metadata"] = self.metadata
        if self.recheck_token:
            result["recheck_token"] = self.recheck_token
        return result


@dataclass(frozen=True)
class PublicEventsPoll:
    events: tuple[dict[str, Any], ...]
    etag: str
    poll_interval: int
    newest_event_id: str
    not_modified: bool
    checkpoint_found: bool

    @property
    def gap_detected(self) -> bool:
        return not self.not_modified and not self.checkpoint_found



@dataclass(frozen=True)
class PublicRepositoriesPoll:
    repositories: tuple[RepositoryCreatedEvent, ...]
    newest_repository_id: str
    poll_interval: int
    source_items_seen: int
    bootstrapped: bool
    request_count: int = 0
    window_start: str = ""
    window_end: str = ""

@dataclass(frozen=True)
class RepositoryMetadata:
    github_repository_id: int
    full_name: str
    is_public: bool
    language: str | None
    size_kb: int
    is_fork: bool
    is_archived: bool
    is_disabled: bool
    default_branch: str
    created_at: str | None
    pushed_at: str | None = None

    def payload(self) -> dict[str, Any]:
        return {
            "github_repository_id": self.github_repository_id,
            "full_name": self.full_name,
            "is_public": self.is_public,
            "language": self.language,
            "size_kb": self.size_kb,
            "is_fork": self.is_fork,
            "is_archived": self.is_archived,
            "is_disabled": self.is_disabled,
            "default_branch": self.default_branch,
            "created_at": self.created_at,
            "pushed_at": self.pushed_at,
        }


def _positive_int(value: Any, default: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return parsed if parsed > 0 else default


def _parse_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def extract_repository_created_events(
    events: tuple[dict[str, Any], ...] | list[dict[str, Any]],
) -> list[RepositoryCreatedEvent]:
    """Aceita apenas CreateEvent público cujo ref_type seja repository."""
    result: list[RepositoryCreatedEvent] = []
    seen: set[str] = set()
    for item in events:
        if item.get("type") != "CreateEvent" or item.get("public") is not True:
            continue
        payload = item.get("payload")
        repo = item.get("repo")
        if not isinstance(payload, dict) or payload.get("ref_type") != "repository":
            continue
        if not isinstance(repo, dict):
            continue
        event_id = str(item.get("id") or "").strip()
        canonical = normalize_github_repo(str(repo.get("name") or ""))
        created_at = str(item.get("created_at") or "").strip()
        try:
            repository_id = int(repo.get("id"))
        except (TypeError, ValueError):
            continue
        if (
            not event_id
            or len(event_id) > 100
            or event_id in seen
            or canonical is None
            or repository_id <= 0
            or _parse_timestamp(created_at) is None
        ):
            continue
        seen.add(event_id)
        result.append(
            RepositoryCreatedEvent(
                event_id=event_id,
                github_repository_id=repository_id,
                repository=canonical,
                event_created_at=created_at,
            )
        )
    return result


def repository_metadata_from_api(data: dict[str, Any]) -> RepositoryMetadata:
    canonical = normalize_github_repo(str(data.get("full_name") or ""))
    if canonical is None:
        raise GitHubDiscoveryError("metadados de repositório sem full_name canônico")
    try:
        repository_id = int(data["id"])
        size_kb = max(int(data.get("size") or 0), 0)
    except (KeyError, TypeError, ValueError) as exc:
        raise GitHubDiscoveryError("metadados de repositório inválidos") from exc
    visibility = str(data.get("visibility") or "public").lower()
    is_public = data.get("private") is False and visibility == "public"
    language = data.get("language")
    return RepositoryMetadata(
        github_repository_id=repository_id,
        full_name=canonical,
        is_public=is_public,
        language=str(language) if language else None,
        size_kb=size_kb,
        is_fork=bool(data.get("fork")),
        is_archived=bool(data.get("archived")),
        is_disabled=bool(data.get("disabled")),
        default_branch=str(data.get("default_branch") or ""),
        created_at=str(data.get("created_at")) if data.get("created_at") else None,
        pushed_at=str(data.get("pushed_at")) if data.get("pushed_at") else None,
    )


def evaluate_repository_metadata(
    metadata: RepositoryMetadata,
    event_created_at: str,
    cfg: Config,
    *,
    now: datetime | None = None,
) -> tuple[bool, str]:
    """Aplica filtros apenas em metadados; não consulta árvore ou conteúdo."""
    if not metadata.is_public:
        return False, "not_public"
    if metadata.is_fork and not cfg.discovery_include_forks:
        return False, "fork"
    if metadata.is_archived:
        return False, "archived"
    if metadata.is_disabled:
        return False, "disabled"
    if metadata.size_kb < max(cfg.discovery_min_size_kb, 0):
        return False, "size_below_min"
    if cfg.discovery_max_size_kb > 0 and metadata.size_kb > cfg.discovery_max_size_kb:
        return False, "size_above_max"
    if cfg.discovery_languages:
        language = (metadata.language or "").lower()
        if language not in cfg.discovery_languages:
            return False, "language_not_allowed" if language else "language_unknown"
    event_time = _parse_timestamp(event_created_at)
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    if event_time is None:
        return False, "invalid_event_timestamp"
    max_age = max(cfg.discovery_max_event_age_hours, 1) * 3600
    if (current - event_time).total_seconds() > max_age:
        return False, "event_too_old"
    return True, ""


class GitHubPublicEventsClient:
    def __init__(
        self,
        cfg: Config,
        *,
        session: requests.Session | None = None,
        before_search_request: Callable[[], float] | None = None,
    ):
        self.cfg = cfg
        self.session = session or requests.Session()
        self._owns_session = session is None
        self.before_search_request = before_search_request
        self._search_calls: deque[float] = deque()
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

    def _throttle_search(self) -> None:
        if self.before_search_request is not None:
            while True:
                delay = float(self.before_search_request())
                if delay <= 0:
                    return
                time.sleep(min(delay + 0.05, 60))
        limit = max(self.cfg.discovery_search_requests_per_minute, 1)
        now = time.monotonic()
        while self._search_calls and now - self._search_calls[0] >= 60:
            self._search_calls.popleft()
        if len(self._search_calls) >= limit:
            delay = max(60 - (now - self._search_calls[0]), 0.05)
            time.sleep(delay)
            now = time.monotonic()
            while self._search_calls and now - self._search_calls[0] >= 60:
                self._search_calls.popleft()
        self._search_calls.append(time.monotonic())

    @staticmethod
    def _retry_delay(response: requests.Response, attempt: int) -> float:
        retry_after = response.headers.get("Retry-After")
        try:
            if retry_after is not None:
                return max(float(retry_after), 1.0)
        except ValueError:
            pass
        if response.headers.get("X-RateLimit-Remaining") == "0":
            try:
                reset_at = float(response.headers.get("X-RateLimit-Reset", "0"))
                return max(reset_at - time.time() + 1, 1.0)
            except ValueError:
                pass
        return float(10 * (2**attempt))

    def _request(self, url: str, *, retries: int = 4, **kwargs) -> requests.Response:
        kwargs.setdefault("timeout", self.cfg.request_timeout)
        response: requests.Response | None = None
        attempts = max(retries, 1)
        for attempt in range(attempts):
            if "/search/" in url:
                self._throttle_search()
            try:
                response = self.session.request("GET", url, **kwargs)
                if self.evidence is not None:
                    self.evidence.capture_http_response(
                        source="github.discovery",
                        method="GET",
                        url=url,
                        response=response,
                        request_params=kwargs.get("params"),
                        request_headers=kwargs.get("headers"),
                    )
            except requests.RequestException:
                if attempt + 1 >= attempts:
                    raise
                time.sleep(min(2**attempt, 10))
                continue
            if response.status_code not in {403, 429}:
                return response
            if (
                response.status_code == 403
                and "rate limit" not in response.text.lower()
                and response.headers.get("X-RateLimit-Remaining") != "0"
                and response.headers.get("Retry-After") is None
            ):
                return response
            if attempt + 1 >= attempts:
                return response
            time.sleep(self._retry_delay(response, attempt))
        assert response is not None
        return response

    def poll(self, *, etag: str = "", last_event_id: str = "") -> PublicEventsPoll:
        collected: list[dict[str, Any]] = []
        response_etag = etag
        poll_interval = max(self.cfg.discovery_poll_seconds, 1)
        checkpoint_found = not bool(last_event_id)
        newest_event_id = last_event_id
        max_pages = min(max(self.cfg.discovery_max_pages, 1), 3)

        for page in range(1, max_pages + 1):
            headers = {"If-None-Match": etag} if page == 1 and etag else {}
            response = self._request(
                f"{BASE}/events",
                retries=1,
                params={"per_page": 100, "page": page},
                headers=headers,
            )
            if page == 1:
                poll_interval = max(
                    poll_interval,
                    _positive_int(response.headers.get("X-Poll-Interval"), 60),
                )
                response_etag = response.headers.get("ETag", etag)
                if response.status_code == 304:
                    return PublicEventsPoll(
                        events=(),
                        etag=response_etag,
                        poll_interval=poll_interval,
                        newest_event_id=last_event_id,
                        not_modified=True,
                        checkpoint_found=True,
                    )
            if response.status_code != 200:
                raise GitHubDiscoveryError(
                    f"public events {response.status_code}: {response.text[:300]}"
                )
            data = response.json()
            if not isinstance(data, list):
                raise GitHubDiscoveryError("public events retornou payload inválido")
            if page == 1 and data:
                newest_event_id = str(data[0].get("id") or last_event_id)
            stop = False
            for item in data:
                if not isinstance(item, dict):
                    continue
                if last_event_id and str(item.get("id") or "") == last_event_id:

                    checkpoint_found = True
                    stop = True
                    break
                collected.append(item)
            if stop or len(data) < 100:
                if not last_event_id:
                    checkpoint_found = True
                break

        return PublicEventsPoll(
            events=tuple(collected),
            etag=response_etag,
            poll_interval=poll_interval,
            newest_event_id=newest_event_id,
            not_modified=False,
            checkpoint_found=checkpoint_found,
        )

    def _bootstrap_repository_cursor(self) -> int:
        response = self._request(
            f"{BASE}/events",
            retries=max(self.cfg.http_retries, 2),
            params={"per_page": 100, "page": 1},
        )
        if response.status_code != 200:
            raise GitHubDiscoveryError(
                f"repository cursor bootstrap {response.status_code}: {response.text[:300]}"
            )
        data = response.json()
        if not isinstance(data, list):
            raise GitHubDiscoveryError("repository cursor bootstrap retornou payload inválido")
        repository_ids: list[int] = []
        for item in data:
            repo = item.get("repo") if isinstance(item, dict) else None
            if not isinstance(repo, dict):
                continue
            try:
                repository_id = int(repo.get("id") or 0)
            except (TypeError, ValueError):
                continue
            if repository_id > 0:
                repository_ids.append(repository_id)
        if not repository_ids:
            raise GitHubDiscoveryError("repository cursor bootstrap não encontrou IDs")
        return max(repository_ids)

    def poll_repositories(
        self, *, last_repository_id: str = ""
    ) -> PublicRepositoriesPoll:
        try:
            cursor = int(last_repository_id or 0)
        except (TypeError, ValueError) as exc:
            raise GitHubDiscoveryError("cursor de repositório inválido") from exc
        bootstrapped = cursor <= 0
        if bootstrapped:
            cursor = self._bootstrap_repository_cursor()

        limit = max(self.cfg.discovery_repositories_per_poll, 1)
        max_pages = min(max(self.cfg.discovery_max_pages, 1), 10)
        repositories: list[RepositoryCreatedEvent] = []
        source_items_seen = 0
        discovered_at = datetime.now(timezone.utc).isoformat()

        for _page in range(max_pages):
            if len(repositories) >= limit:
                break
            per_page = min(max(limit - len(repositories), 1), 100)
            response = self._request(
                f"{BASE}/repositories",
                retries=max(self.cfg.http_retries, 2),
                params={"since": cursor, "per_page": per_page},
            )
            if response.status_code != 200:
                raise GitHubDiscoveryError(
                    f"public repositories {response.status_code}: {response.text[:300]}"
                )
            data = response.json()
            if not isinstance(data, list):
                raise GitHubDiscoveryError("public repositories retornou payload inválido")
            if not data:
                break

            previous_cursor = cursor
            for item in data:
                if not isinstance(item, dict):
                    continue
                try:
                    repository_id = int(item.get("id") or 0)
                except (TypeError, ValueError):
                    continue
                if repository_id <= cursor:
                    continue
                cursor = max(cursor, repository_id)
                source_items_seen += 1
                if item.get("private") is not False:
                    continue
                if bool(item.get("fork")) and not self.cfg.discovery_include_forks:
                    continue
                canonical = normalize_github_repo(str(item.get("full_name") or ""))
                if canonical is None:
                    continue
                repositories.append(
                    RepositoryCreatedEvent(
                        event_id=f"public-repository:{repository_id}",
                        github_repository_id=repository_id,
                        repository=canonical,
                        event_created_at=discovered_at,
                    )
                )
                if len(repositories) >= limit:
                    break
            if cursor <= previous_cursor or len(data) < per_page:
                break

        return PublicRepositoriesPoll(
            repositories=tuple(repositories),
            newest_repository_id=str(cursor),
            poll_interval=max(self.cfg.discovery_poll_seconds, 5),
            source_items_seen=source_items_seen,
            bootstrapped=bootstrapped,
        )

    def search_repository_window(
        self,
        *,
        window_start: datetime,
        window_end: datetime,
    ) -> PublicRepositoriesPoll:
        """Esgota uma janela fechada, dividindo-a antes do teto de 1.000 itens."""
        start = window_start.astimezone(timezone.utc).replace(microsecond=0)
        end = window_end.astimezone(timezone.utc).replace(microsecond=0)
        if end <= start:
            raise GitHubDiscoveryError("janela de busca inválida")

        by_id: dict[int, RepositoryCreatedEvent] = {}
        source_items_seen = 0
        request_count = 0
        highest_repository_id = 0

        def collect(left: datetime, right: datetime) -> None:
            nonlocal source_items_seen, request_count, highest_repository_id
            query = (
                f"created:{left.strftime('%Y-%m-%dT%H:%M:%SZ')}.."
                f"{right.strftime('%Y-%m-%dT%H:%M:%SZ')} is:public"
            )
            if self.cfg.discovery_include_forks:
                query += " fork:true"
            response = self._request(
                f"{BASE}/search/repositories",
                retries=max(self.cfg.http_retries, 2),
                params={
                    "q": query,
                    "sort": "updated",
                    "order": "desc",
                    "per_page": 100,
                    "page": 1,
                },
            )
            request_count += 1
            if response.status_code != 200:
                raise GitHubDiscoveryError(
                    f"repository window search {response.status_code}: {response.text[:300]}"
                )
            payload = response.json()
            if not isinstance(payload, dict) or not isinstance(payload.get("items"), list):
                raise GitHubDiscoveryError(
                    "repository window search retornou payload inválido"
                )
            if bool(payload.get("incomplete_results")):
                raise GitHubDiscoveryError(
                    "repository window search retornou resultados incompletos"
                )
            try:
                total_count = max(int(payload.get("total_count") or 0), 0)
            except (TypeError, ValueError) as exc:
                raise GitHubDiscoveryError(
                    "repository window search sem total_count válido"
                ) from exc

            if total_count > 1_000:
                span_seconds = int((right - left).total_seconds())
                if span_seconds <= 1:
                    raise GitHubDiscoveryError(
                        "mais de 1.000 repositórios no mesmo segundo; "
                        "janela não pode ser dividida"
                    )
                midpoint = left + timedelta(seconds=max(span_seconds // 2, 1))
                collect(midpoint, right)
                collect(left, midpoint)
                return

            pages = max(1, math.ceil(total_count / 100))
            page_payloads = [payload]
            for page in range(2, pages + 1):
                page_response = self._request(
                    f"{BASE}/search/repositories",
                    retries=max(self.cfg.http_retries, 2),
                    params={
                        "q": query,
                        "sort": "updated",
                        "order": "desc",
                        "per_page": 100,
                        "page": page,
                    },
                )
                request_count += 1
                if page_response.status_code != 200:
                    raise GitHubDiscoveryError(
                        f"repository window page {page} {page_response.status_code}: "
                        f"{page_response.text[:300]}"
                    )
                page_payload = page_response.json()
                if (
                    not isinstance(page_payload, dict)
                    or not isinstance(page_payload.get("items"), list)
                    or bool(page_payload.get("incomplete_results"))
                ):
                    raise GitHubDiscoveryError(
                        f"repository window page {page} retornou resultados incompletos"
                    )
                page_payloads.append(page_payload)

            for page_payload in page_payloads:
                items = page_payload["items"]
                source_items_seen += len(items)
                for item in items:
                    if not isinstance(item, dict):
                        continue
                    try:
                        metadata = repository_metadata_from_api(item)
                    except GitHubDiscoveryError:
                        continue
                    created_at = _parse_timestamp(metadata.created_at)
                    if (
                        created_at is None
                        or created_at < left
                        or created_at > right
                        or not metadata.is_public
                        or (
                            metadata.is_fork
                            and not self.cfg.discovery_include_forks
                        )
                    ):
                        continue
                    highest_repository_id = max(
                        highest_repository_id, metadata.github_repository_id
                    )
                    by_id[metadata.github_repository_id] = RepositoryCreatedEvent(
                        event_id=(
                            f"repository-search:{metadata.github_repository_id}"
                        ),
                        github_repository_id=metadata.github_repository_id,
                        repository=metadata.full_name,
                        event_created_at=created_at.isoformat(),
                        metadata=metadata.payload(),
                    )

        collect(start, end)
        repositories = sorted(
            by_id.values(),
            key=lambda item: (
                _parse_timestamp(item.event_created_at)
                or datetime.min.replace(tzinfo=timezone.utc),
                item.github_repository_id,
            ),
            reverse=True,
        )
        return PublicRepositoriesPoll(
            repositories=tuple(repositories),
            newest_repository_id=str(highest_repository_id),
            poll_interval=max(self.cfg.discovery_poll_seconds, 5),
            source_items_seen=source_items_seen,
            bootstrapped=False,
            request_count=request_count,
            window_start=start.isoformat(),
            window_end=end.isoformat(),
        )

    def search_pushed_repository_window(
        self,
        *,
        window_start: datetime,
        window_end: datetime,
        created_after: datetime,
    ) -> PublicRepositoriesPoll:
        """Revisita repos recentes quando recebem push, sem polling por repositório."""
        start = window_start.astimezone(timezone.utc).replace(microsecond=0)
        end = window_end.astimezone(timezone.utc).replace(microsecond=0)
        created_cutoff = created_after.astimezone(timezone.utc).replace(microsecond=0)
        if end <= start:
            raise GitHubDiscoveryError("janela de push inválida")

        by_id: dict[int, RepositoryCreatedEvent] = {}
        source_items_seen = 0
        request_count = 0
        highest_repository_id = 0
        min_size = max(self.cfg.discovery_min_size_kb, 0)

        def collect(left: datetime, right: datetime) -> None:
            nonlocal source_items_seen, request_count, highest_repository_id
            query = (
                f"pushed:{left.strftime('%Y-%m-%dT%H:%M:%SZ')}.."
                f"{right.strftime('%Y-%m-%dT%H:%M:%SZ')} "
                f"created:>={created_cutoff.strftime('%Y-%m-%dT%H:%M:%SZ')} "
                f"size:>={min_size} is:public"
            )
            if self.cfg.discovery_include_forks:
                query += " fork:true"
            response = self._request(
                f"{BASE}/search/repositories",
                retries=max(self.cfg.http_retries, 2),
                params={
                    "q": query,
                    "sort": "updated",
                    "order": "desc",
                    "per_page": 100,
                    "page": 1,
                },
            )
            request_count += 1
            if response.status_code != 200:
                raise GitHubDiscoveryError(
                    f"pushed repository search {response.status_code}: "
                    f"{response.text[:300]}"
                )
            payload = response.json()
            if not isinstance(payload, dict) or not isinstance(payload.get("items"), list):
                raise GitHubDiscoveryError(
                    "pushed repository search retornou payload inválido"
                )
            if bool(payload.get("incomplete_results")):
                raise GitHubDiscoveryError(
                    "pushed repository search retornou resultados incompletos"
                )
            try:
                total_count = max(int(payload.get("total_count") or 0), 0)
            except (TypeError, ValueError) as exc:
                raise GitHubDiscoveryError(
                    "pushed repository search sem total_count válido"
                ) from exc

            if total_count > 1_000:
                span_seconds = int((right - left).total_seconds())
                if span_seconds <= 1:
                    raise GitHubDiscoveryError(
                        "mais de 1.000 pushes no mesmo segundo; janela não pode ser dividida"
                    )
                midpoint = left + timedelta(seconds=max(span_seconds // 2, 1))
                collect(midpoint, right)
                collect(left, midpoint)
                return

            page_payloads = [payload]
            for page in range(2, max(1, math.ceil(total_count / 100)) + 1):
                page_response = self._request(
                    f"{BASE}/search/repositories",
                    retries=max(self.cfg.http_retries, 2),
                    params={
                        "q": query,
                        "sort": "updated",
                        "order": "desc",
                        "per_page": 100,
                        "page": page,
                    },
                )
                request_count += 1
                if page_response.status_code != 200:
                    raise GitHubDiscoveryError(
                        f"pushed repository page {page} {page_response.status_code}: "
                        f"{page_response.text[:300]}"
                    )
                page_payload = page_response.json()
                if (
                    not isinstance(page_payload, dict)
                    or not isinstance(page_payload.get("items"), list)
                    or bool(page_payload.get("incomplete_results"))
                ):
                    raise GitHubDiscoveryError(
                        f"pushed repository page {page} retornou resultados incompletos"
                    )
                page_payloads.append(page_payload)

            for page_payload in page_payloads:
                items = page_payload["items"]
                source_items_seen += len(items)
                for item in items:
                    if not isinstance(item, dict):
                        continue
                    try:
                        metadata = repository_metadata_from_api(item)
                    except GitHubDiscoveryError:
                        continue
                    created_at = _parse_timestamp(metadata.created_at)
                    pushed_at = _parse_timestamp(metadata.pushed_at)
                    if (
                        created_at is None
                        or pushed_at is None
                        or created_at < created_cutoff
                        or pushed_at < left
                        or pushed_at > right
                        or metadata.size_kb < min_size
                        or not metadata.is_public
                        or (
                            metadata.is_fork
                            and not self.cfg.discovery_include_forks
                        )
                    ):
                        continue
                    highest_repository_id = max(
                        highest_repository_id, metadata.github_repository_id
                    )
                    token = (
                        f"{metadata.github_repository_id}:{metadata.pushed_at}:"
                        f"{metadata.size_kb}:{metadata.default_branch}"
                    )
                    by_id[metadata.github_repository_id] = RepositoryCreatedEvent(
                        event_id=f"repository-pushed:{metadata.github_repository_id}",
                        github_repository_id=metadata.github_repository_id,
                        repository=metadata.full_name,
                        event_created_at=created_at.isoformat(),
                        metadata=metadata.payload(),
                        recheck_token=token,
                    )

        collect(start, end)
        repositories = sorted(
            by_id.values(),
            key=lambda item: (
                _parse_timestamp((item.metadata or {}).get("pushed_at"))
                or datetime.min.replace(tzinfo=timezone.utc),
                item.github_repository_id,
            ),
            reverse=True,
        )
        return PublicRepositoriesPoll(
            repositories=tuple(repositories),
            newest_repository_id=str(highest_repository_id),
            poll_interval=max(self.cfg.discovery_poll_seconds, 5),
            source_items_seen=source_items_seen,
            bootstrapped=False,
            request_count=request_count,
            window_start=start.isoformat(),
            window_end=end.isoformat(),
        )


    def search_recent_repositories(
        self, *, last_repository_id: str = ""
    ) -> PublicRepositoriesPoll:
        """Busca a janela recente e ordena localmente pelo created_at real."""
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(hours=max(self.cfg.discovery_max_event_age_hours, 1))
        query = f"created:>={cutoff.strftime('%Y-%m-%dT%H:%M:%SZ')}"
        max_pages = min(max(self.cfg.discovery_max_pages, 1), 10)
        by_id: dict[int, RepositoryCreatedEvent] = {}
        source_items_seen = 0
        highest_repository_id = 0

        for page in range(1, max_pages + 1):
            response = self._request(
                f"{BASE}/search/repositories",
                retries=max(self.cfg.http_retries, 2),
                params={
                    "q": query,
                    "sort": "updated",
                    "order": "desc",
                    "per_page": 100,
                    "page": page,
                },
            )
            if response.status_code != 200:
                raise GitHubDiscoveryError(
                    f"recent repository search {response.status_code}: {response.text[:300]}"
                )
            payload = response.json()
            if not isinstance(payload, dict) or not isinstance(payload.get("items"), list):
                raise GitHubDiscoveryError("recent repository search retornou payload inválido")
            if bool(payload.get("incomplete_results")):
                raise GitHubDiscoveryError("recent repository search retornou resultados incompletos")

            items = payload["items"]
            source_items_seen += len(items)
            for item in items:
                if not isinstance(item, dict):
                    continue
                try:
                    repository_id = int(item.get("id") or 0)
                except (TypeError, ValueError):
                    continue
                if repository_id <= 0:
                    continue
                highest_repository_id = max(highest_repository_id, repository_id)
                created_at = _parse_timestamp(item.get("created_at"))
                if created_at is None or created_at < cutoff or created_at > now:
                    continue
                if item.get("private") is not False:
                    continue
                if bool(item.get("fork")) and not self.cfg.discovery_include_forks:
                    continue
                canonical = normalize_github_repo(str(item.get("full_name") or ""))
                if canonical is None:
                    continue
                by_id[repository_id] = RepositoryCreatedEvent(
                    event_id=f"repository-search:{repository_id}",
                    github_repository_id=repository_id,
                    repository=canonical,
                    event_created_at=created_at.isoformat(),
                )
            if len(items) < 100:
                break

        repositories = sorted(
            by_id.values(),
            key=lambda item: (
                _parse_timestamp(item.event_created_at)
                or datetime.min.replace(tzinfo=timezone.utc),
                item.github_repository_id,
            ),
            reverse=True,
        )
        return PublicRepositoriesPoll(
            repositories=tuple(repositories),
            newest_repository_id=str(highest_repository_id or last_repository_id),
            poll_interval=max(self.cfg.discovery_poll_seconds, 5),
            source_items_seen=source_items_seen,
            bootstrapped=not bool(last_repository_id),
        )

    def get_repository(self, repository: str) -> RepositoryMetadata | None:
        canonical = normalize_github_repo(repository)
        if canonical is None:
            raise ValueError("repositório inválido")
        owner, name = canonical.split("/", 1)
        response = self._request(
            f"{BASE}/repos/{quote(owner, safe='')}/{quote(name, safe='')}"
        )
        if response.status_code in {404, 410}:
            return None
        if response.status_code != 200:
            raise GitHubDiscoveryError(
                f"repository metadata {response.status_code}: {response.text[:300]}"
            )
        data = response.json()
        if not isinstance(data, dict):
            raise GitHubDiscoveryError("repository metadata retornou payload inválido")
        return repository_metadata_from_api(data)

    def close(self) -> None:
        if self.evidence is not None:
            self.evidence.close()
        if self._owns_session:
            self.session.close()
