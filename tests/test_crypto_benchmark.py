from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_crypto_corpus_is_an_exact_regression_gate() -> None:
    completed = subprocess.run(
        [sys.executable, "scripts/benchmark_crypto_detectors.py", "--json"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr
    summary = json.loads(completed.stdout)
    assert summary["cases_failed"] == 0
    assert summary["false_positive"] == 0
    assert summary["false_negative"] == 0
    assert summary["precision"] == 1.0
    assert summary["recall"] == 1.0
    assert summary["f1"] == 1.0
