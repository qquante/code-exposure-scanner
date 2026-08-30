"""Interface estreita para usar apenas os detectores de IA em texto autorizado."""

from __future__ import annotations

from ..extract import Finding, dedupe, extract_from_text
from .catalog import AI_SECRET_TYPE_IDS


def extract_ai_tokens(text: str, **location: str) -> list[Finding]:
    findings = extract_from_text(text, **location)
    return dedupe(
        [finding for finding in findings if finding.type_id in AI_SECRET_TYPE_IDS]
    )
