from __future__ import annotations

import json
from pathlib import Path

import pytest

from secret_hunter.ingest import (
    IngestError,
    ManifestIngestAdapter,
    TreeIngestAdapter,
    read_verified_text,
)


def test_tree_adapter_maps_owner_repo_and_logical_path(tmp_path: Path) -> None:
    target = tmp_path / "batch" / "acme" / "demo" / "config" / ".env"
    target.parent.mkdir(parents=True)
    target.write_text("TOKEN=synthetic-value", encoding="utf-8")
    binary = tmp_path / "batch" / "acme" / "demo" / "image.bin"
    binary.write_bytes(b"abc\x00def")

    candidates = list(TreeIngestAdapter(tmp_path, source="batch").iter_candidates())

    assert len(candidates) == 1
    assert candidates[0].repository == "acme/demo"
    assert candidates[0].source_path == "batch/acme/demo/config/.env"
    assert candidates[0].logical_path == "config/.env"
    assert candidates[0].size == len(b"TOKEN=synthetic-value")
    assert len(candidates[0].sha256) == 64


def test_manifest_adapter_preserves_provenance_without_content(tmp_path: Path) -> None:
    payload = tmp_path / "payloads" / "42.env"
    payload.parent.mkdir()
    payload.write_text("fixture", encoding="utf-8")
    commit = "a" * 40
    manifest = tmp_path / "batch.jsonl"
    manifest.write_text(
        json.dumps(
            {
                "repository": "acme/demo",
                "file": "payloads/42.env",
                "path": ".env",
                "branch": "main",
                "commit": commit,
            }
        ),
        encoding="utf-8",
    )

    candidate = next(
        ManifestIngestAdapter(tmp_path, source="batch.jsonl").iter_candidates()
    )

    assert candidate.repository == "acme/demo"
    assert candidate.logical_path == ".env"
    assert candidate.branch == "main"
    assert candidate.commit_sha == commit
    assert "fixture" not in repr(candidate.payload())


def test_manifest_rejects_path_traversal(tmp_path: Path) -> None:
    manifest = tmp_path / "batch.jsonl"
    manifest.write_text(
        json.dumps(
            {
                "repository": "acme/demo",
                "file": "../outside.env",
                "path": ".env",
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(IngestError, match="relativo confinado"):
        list(ManifestIngestAdapter(tmp_path, source="batch.jsonl").iter_candidates())


def test_worker_rejects_file_changed_after_enqueue(tmp_path: Path) -> None:
    target = tmp_path / "acme" / "demo" / ".env"
    target.parent.mkdir(parents=True)
    target.write_text("first", encoding="utf-8")
    candidate = next(TreeIngestAdapter(tmp_path).iter_candidates())
    target.write_text("second", encoding="utf-8")

    with pytest.raises(IngestError, match="mudou depois do enqueue"):
        read_verified_text(
            tmp_path,
            candidate.source_path,
            candidate.sha256,
            max_bytes=1_000_000,
        )
