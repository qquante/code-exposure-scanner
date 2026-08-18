from __future__ import annotations

from datetime import datetime, timedelta, timezone

import requests
import secret_hunter.pipeline as pipeline
from secret_hunter.config import Config
from secret_hunter.discovery import (
    GitHubPublicEventsClient,
    PublicEventsPoll,
    RepositoryMetadata,
    evaluate_repository_metadata,
    extract_repository_created_events,
)


def _event(event_id: str, *, ref_type: str = "repository", public: bool = True) -> dict:
    return {
        "id": event_id,
        "type": "CreateEvent",
        "public": public,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "repo": {"id": 123, "name": "acme/demo"},
        "payload": {"ref_type": ref_type},
    }


def test_extracts_only_public_repository_create_events() -> None:
    events = [
        _event("repo"),
        _event("branch", ref_type="branch"),
        _event("private", public=False),
        {**_event("push"), "type": "PushEvent"},
    ]

    extracted = extract_repository_created_events(events)

    assert [item.event_id for item in extracted] == ["repo"]
    assert extracted[0].repository == "acme/demo"
    assert extracted[0].github_repository_id == 123


class _Response:
    def __init__(self, status: int, data, headers: dict[str, str] | None = None):
        self.status_code = status
        self._data = data
        self.headers = headers or {}
        self.text = ""

    def json(self):
        return self._data


class _Session:
    def __init__(self, responses: list[_Response | Exception]):
        self.responses = responses
        self.headers: dict[str, str] = {}
        self.calls: list[dict] = []

    def request(self, method: str, url: str, **kwargs):
        self.calls.append({"method": method, "url": url, **kwargs})
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response

    def close(self):
        pass


def test_events_poll_uses_etag_and_stops_at_checkpoint() -> None:
    session = _Session(
        [
            _Response(
                200,
                [_event("new"), _event("checkpoint"), _event("old")],
                {"ETag": '"v2"', "X-Poll-Interval": "90"},
            )
        ]
    )
    client = GitHubPublicEventsClient(
        Config(discovery_poll_seconds=60), session=session  # type: ignore[arg-type]
    )

    result = client.poll(etag='"v1"', last_event_id="checkpoint")

    assert [item["id"] for item in result.events] == ["new"]
    assert result.etag == '"v2"'
    assert result.poll_interval == 90
    assert result.checkpoint_found is True
    assert result.gap_detected is False
    assert session.calls[0]["headers"] == {"If-None-Match": '"v1"'}


def test_events_poll_honors_304_without_advancing_checkpoint() -> None:
    session = _Session(
        [_Response(304, None, {"ETag": '"same"', "X-Poll-Interval": "120"})]
    )
    client = GitHubPublicEventsClient(Config(), session=session)  # type: ignore[arg-type]

    result = client.poll(etag='"same"', last_event_id="123")

    assert result.not_modified is True
    assert result.events == ()
    assert result.newest_event_id == "123"
    assert result.poll_interval == 120


def test_events_poll_reads_at_most_three_pages_and_detects_gap() -> None:
    pages = []
    for page in range(3):
        pages.append(
            _Response(
                200,
                [_event(f"{page}-{index}") for index in range(100)],
                {"ETag": '"latest"', "X-Poll-Interval": "60"},
            )
        )
    session = _Session(pages)
    client = GitHubPublicEventsClient(
        Config(discovery_max_pages=9), session=session  # type: ignore[arg-type]
    )

    result = client.poll(last_event_id="missing")

    assert len(result.events) == 300
    assert len(session.calls) == 3
    assert result.gap_detected is True


def test_metadata_filters_are_deterministic_and_metadata_only() -> None:
    now = datetime.now(timezone.utc)
    cfg = Config(
        discovery_languages=("python",),
        discovery_min_size_kb=1,
        discovery_max_size_kb=100,
        discovery_max_event_age_hours=24,
    )
    metadata = RepositoryMetadata(
        github_repository_id=123,
        full_name="acme/demo",
        is_public=True,
        language="Python",
        size_kb=10,
        is_fork=False,
        is_archived=False,
        is_disabled=False,
        default_branch="main",
        created_at=now.isoformat(),
    )

    assert evaluate_repository_metadata(
        metadata, now.isoformat(), cfg, now=now
    ) == (True, "")
    assert evaluate_repository_metadata(
        RepositoryMetadata(**{**metadata.__dict__, "is_fork": True}),
        now.isoformat(),
        cfg,
        now=now,
    ) == (False, "fork")
    assert evaluate_repository_metadata(
        metadata,
        (now - timedelta(hours=25)).isoformat(),
        cfg,
        now=now,
    ) == (False, "event_too_old")


class FakePollClient:
    def __init__(self, events: tuple[dict, ...]):
        self.events = events

    def poll(self, *, etag: str = "", last_event_id: str = "") -> PublicEventsPoll:
        return PublicEventsPoll(
            events=self.events,
            etag='"fixture"',
            poll_interval=60,
            newest_event_id=self.events[0]["id"] if self.events else last_event_id,
            not_modified=False,
            checkpoint_found=not bool(last_event_id),
        )

class _CandidateStore:
    def __init__(self) -> None:
        self.candidate = {
            "id": 1,
            "status": "pending_metadata",
            "repository": "acme/demo",
            "github_repository_id": 123,
            "event_created_at": datetime.now(timezone.utc).isoformat(),
        }
        self.completed = False
        self.queued: list[dict] = []

    def get_discovery_candidate(self, candidate_id: int):
        assert candidate_id == 1
        return self.candidate

    def reserve_rate_slot(self, *_args):
        return 0

    def complete_candidate_metadata(self, *_args, **_kwargs):
        self.completed = True
        return True

    def queue_candidate_scan_automatically(self, candidate_id: int, **kwargs):
        self.queued.append({"candidate_id": candidate_id, **kwargs})
        return {"candidate_id": candidate_id, "job_id": 1}


class _MetadataClient:
    def __init__(self, _cfg: Config):
        pass

    def get_repository(self, _repository: str) -> RepositoryMetadata:
        return RepositoryMetadata(
            github_repository_id=123,
            full_name="acme/demo",
            is_public=True,
            language="Python",
            size_kb=10,
            is_fork=False,
            is_archived=False,
            is_disabled=False,
            default_branch="main",
            created_at=datetime.now(timezone.utc).isoformat(),
        )

    def close(self) -> None:
        pass


def test_eligible_candidate_is_auto_queued_only_when_enabled(monkeypatch) -> None:
    monkeypatch.setattr(pipeline, "GitHubPublicEventsClient", _MetadataClient)

    for enabled, expected_jobs in ((False, 0), (True, 1)):
        store = _CandidateStore()
        cfg = Config(
            discovery_auto_queue_scans=enabled,
            discovery_head_scan_sample_percent=100,
        )
        pipeline.handle_job(
            store,  # type: ignore[arg-type]
            cfg,
            {"kind": "enrich_repository_candidate", "payload": {"candidate_id": 1}},
        )

        assert store.completed is True
        assert len(store.queued) == expected_jobs
        if enabled:
            assert store.queued[0]["trufflehog"] is True
            assert store.queued[0]["pattern_set_id"] == pipeline.PATTERN_SET_ID


def test_head_scan_sampling_is_deterministic_and_bounded() -> None:
    assert pipeline._selected_for_head_scan(100, 5) is True
    assert pipeline._selected_for_head_scan(104, 5) is True
    assert pipeline._selected_for_head_scan(105, 5) is False
    assert pipeline._selected_for_head_scan(100, 0) is False
    assert pipeline._selected_for_head_scan(199, 100) is True
    assert pipeline._selected_for_head_scan(100, -1) is False
    assert pipeline._selected_for_head_scan(199, 101) is True


def _repository_item(
    repository_id: int, full_name: str, *, fork: bool = False,
    created_at: str | None = None,
) -> dict:
    item = {
        "id": repository_id,
        "full_name": full_name,
        "private": False,
        "fork": fork,
    }
    if created_at is not None:
        item["created_at"] = created_at
    return item

def test_recent_repository_search_sorts_locally_by_created_at_desc() -> None:
    now = datetime.now(timezone.utc)
    oldest = (now - timedelta(hours=3)).isoformat()
    middle = (now - timedelta(hours=2)).isoformat()
    newest = (now - timedelta(hours=1)).isoformat()
    session = _Session(
        [
            _Response(
                200,
                {
                    "total_count": 3,
                    "incomplete_results": False,
                    "items": [
                        _repository_item(401, "acme/oldest", created_at=oldest),
                        _repository_item(403, "acme/newest", created_at=newest),
                        _repository_item(402, "acme/middle", created_at=middle),
                    ],
                },
            )
        ]
    )
    client = GitHubPublicEventsClient(
        Config(discovery_max_event_age_hours=48, discovery_max_pages=1),
        session=session,  # type: ignore[arg-type]
    )

    result = client.search_recent_repositories(last_repository_id="400")

    assert [item.repository for item in result.repositories] == [
        "acme/newest", "acme/middle", "acme/oldest"
    ]
    assert result.newest_repository_id == "403"
    assert session.calls[0]["url"].endswith("/search/repositories")
    params = session.calls[0]["params"]
    assert params["q"].startswith("created:>=")
    assert params["sort"] == "updated"
    assert params["order"] == "desc"



def test_repository_cursor_bootstraps_then_lists_new_repositories() -> None:
    session = _Session(
        [
            _Response(200, [_event("bootstrap")]),
            _Response(
                200,
                [
                    _repository_item(124, "acme/first"),
                    _repository_item(125, "acme/second"),
                ],
            ),
        ]
    )
    client = GitHubPublicEventsClient(
        Config(discovery_repositories_per_poll=2),
        session=session,  # type: ignore[arg-type]
    )

    result = client.poll_repositories()

    assert result.bootstrapped is True
    assert result.newest_repository_id == "125"
    assert [item.repository for item in result.repositories] == [
        "acme/first",
        "acme/second",
    ]
    assert session.calls[1]["url"].endswith("/repositories")
    assert session.calls[1]["params"] == {"since": 123, "per_page": 2}


def test_repository_cursor_advances_past_filtered_forks_without_skipping() -> None:
    session = _Session(
        [
            _Response(200, [_repository_item(201, "acme/fork", fork=True)]),
            _Response(200, [_repository_item(202, "acme/original")]),
        ]
    )
    client = GitHubPublicEventsClient(
        Config(discovery_repositories_per_poll=1, discovery_max_pages=2),
        session=session,  # type: ignore[arg-type]
    )

    result = client.poll_repositories(last_repository_id="200")

    assert result.bootstrapped is False
    assert result.source_items_seen == 2
    assert result.newest_repository_id == "202"
    assert [item.repository for item in result.repositories] == ["acme/original"]
    assert session.calls[1]["params"]["since"] == 201


def test_repository_cursor_enforces_limit_when_api_returns_larger_page() -> None:
    session = _Session(
        [
            _Response(
                200,
                [
                    _repository_item(301, "acme/first"),
                    _repository_item(302, "acme/second"),
                    _repository_item(303, "acme/must-wait"),
                ],
            )
        ]
    )
    client = GitHubPublicEventsClient(
        Config(discovery_repositories_per_poll=2), session=session  # type: ignore[arg-type]
    )
    result = client.poll_repositories(last_repository_id="300")

    assert result.source_items_seen == 2
    assert result.newest_repository_id == "302"
    assert [item.repository for item in result.repositories] == [
        "acme/first", "acme/second"
    ]


def test_discovery_request_retries_transient_network_error(monkeypatch) -> None:
    session = _Session([requests.ReadTimeout(), _Response(200, [])])
    monkeypatch.setattr(pipeline.time, "sleep", lambda _seconds: None)
    client = GitHubPublicEventsClient(Config(), session=session)  # type: ignore[arg-type]

    response = client._request("https://api.github.test/repositories", retries=2)

    assert response.status_code == 200
    assert len(session.calls) == 2


def test_repository_window_paginates_every_result_and_embeds_metadata() -> None:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    older = (now - timedelta(seconds=45)).isoformat()
    newer = (now - timedelta(seconds=15)).isoformat()
    session = _Session(
        [
            _Response(
                200,
                {
                    "total_count": 101,
                    "incomplete_results": False,
                    "items": [
                        _repository_item(501, "acme/older", created_at=older)
                    ],
                },
            ),
            _Response(
                200,
                {
                    "total_count": 101,
                    "incomplete_results": False,
                    "items": [
                        _repository_item(502, "acme/newer", created_at=newer)
                    ],
                },
            ),
        ]
    )
    client = GitHubPublicEventsClient(
        Config(discovery_search_requests_per_minute=30),
        session=session,  # type: ignore[arg-type]
    )

    result = client.search_repository_window(
        window_start=now - timedelta(minutes=1),
        window_end=now,
    )

    assert [item.repository for item in result.repositories] == [
        "acme/newer",
        "acme/older",
    ]
    assert result.request_count == 2
    assert result.source_items_seen == 2
    assert result.repositories[0].metadata is not None
    assert session.calls[1]["params"]["page"] == 2
    assert "is:public" in session.calls[0]["params"]["q"]


def test_repository_window_splits_over_github_result_cap_newest_first() -> None:
    end = datetime.now(timezone.utc).replace(microsecond=0)
    start = end - timedelta(minutes=2)
    midpoint = start + timedelta(minutes=1)
    session = _Session(
        [
            _Response(
                200,
                {
                    "total_count": 1001,
                    "incomplete_results": False,
                    "items": [],
                },
            ),
            _Response(
                200,
                {
                    "total_count": 1,
                    "incomplete_results": False,
                    "items": [
                        _repository_item(
                            602,
                            "acme/newer-half",
                            created_at=(midpoint + timedelta(seconds=30)).isoformat(),
                        )
                    ],
                },
            ),
            _Response(
                200,
                {
                    "total_count": 1,
                    "incomplete_results": False,
                    "items": [
                        _repository_item(
                            601,
                            "acme/older-half",
                            created_at=(start + timedelta(seconds=30)).isoformat(),
                        )
                    ],
                },
            ),
        ]
    )
    client = GitHubPublicEventsClient(
        Config(discovery_search_requests_per_minute=30),
        session=session,  # type: ignore[arg-type]
    )

    result = client.search_repository_window(
        window_start=start,
        window_end=end,
    )

    assert [item.repository for item in result.repositories] == [
        "acme/newer-half",
        "acme/older-half",
    ]
    assert result.request_count == 3
    assert midpoint.strftime("%Y-%m-%dT%H:%M:%SZ") in session.calls[1]["params"]["q"]
    assert start.strftime("%Y-%m-%dT%H:%M:%SZ") in session.calls[2]["params"]["q"]


def test_pushed_repository_window_revisits_only_recent_nonempty_repositories() -> None:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    created_after = now - timedelta(hours=4)
    pushed_at = now - timedelta(seconds=30)
    session = _Session(
        [
            _Response(
                200,
                {
                    "total_count": 3,
                    "incomplete_results": False,
                    "items": [
                        {
                            **_repository_item(
                                701,
                                "acme/filled-after-create",
                                created_at=(now - timedelta(hours=2)).isoformat(),
                            ),
                            "pushed_at": pushed_at.isoformat(),
                            "size": 12,
                            "default_branch": "main",
                        },
                        {
                            **_repository_item(
                                702,
                                "acme/stale-push",
                                created_at=(now - timedelta(hours=1)).isoformat(),
                            ),
                            "pushed_at": (now - timedelta(minutes=2)).isoformat(),
                            "size": 8,
                        },
                        {
                            **_repository_item(
                                703,
                                "acme/old-repository",
                                created_at=(now - timedelta(hours=8)).isoformat(),
                            ),
                            "pushed_at": pushed_at.isoformat(),
                            "size": 9,
                        },
                    ],
                },
            )
        ]
    )
    client = GitHubPublicEventsClient(
        Config(discovery_min_size_kb=1),
        session=session,  # type: ignore[arg-type]
    )

    result = client.search_pushed_repository_window(
        window_start=now - timedelta(minutes=1),
        window_end=now,
        created_after=created_after,
    )

    assert [item.repository for item in result.repositories] == [
        "acme/filled-after-create"
    ]
    event = result.repositories[0]
    assert event.event_id == "repository-pushed:701"
    assert event.recheck_token
    assert event.metadata is not None
    assert event.metadata["pushed_at"] == pushed_at.isoformat()
    query = session.calls[0]["params"]["q"]
    assert "pushed:" in query
    assert f"created:>={created_after.strftime('%Y-%m-%dT%H:%M:%SZ')}" in query
    assert "size:>=1" in query
    assert "is:public" in query


def test_embedded_search_metadata_skips_redundant_repository_request(
    monkeypatch,
) -> None:
    class _MustNotConstruct:
        def __init__(self, _cfg: Config):
            raise AssertionError("não deve consultar /repos/{owner}/{repo}")

    monkeypatch.setattr(pipeline, "GitHubPublicEventsClient", _MustNotConstruct)
    store = _CandidateStore()
    now = datetime.now(timezone.utc)
    metadata = RepositoryMetadata(
        github_repository_id=123,
        full_name="acme/demo",
        is_public=True,
        language="Python",
        size_kb=10,
        is_fork=False,
        is_archived=False,
        is_disabled=False,
        default_branch="main",
        created_at=now.isoformat(),
    )

    pipeline.handle_job(
        store,  # type: ignore[arg-type]
        Config(discovery_auto_queue_scans=False),
        {
            "kind": "enrich_repository_candidate",
            "payload": {
                "candidate_id": 1,
                "metadata": metadata.payload(),
            },
        },
    )

    assert store.completed is True
