"""Política central do escopo de varredura automática.

O detector genérico continua disponível para uso local/forense, mas o serviço
distribuído em produção persiste somente material de carteira EVM/Solana e
frases BIP39. Dependências vendorizadas são ignoradas antes de consumir API,
CPU ou espaço de evidência.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import TypeVar


CRYPTO_WALLET_TYPE_IDS = frozenset(
    {
        "evm_private_key",
        "evm_keystore_v3",
        "bip39_mnemonic",
        "solana_keypair_json",
        "solana_keypair_base58",
        "solana_keypair_base64",
        "solana_keypair_hex",
        "solana_seed_array",
        "solana_seed_base58",
        "solana_seed_base64",
        "solana_seed_hex",
    }
)


DEPENDENCY_PATH_SEGMENTS = frozenset(
    {
        "node_modules",
        ".pnpm",
        ".yarn",
        ".venv",
        "venv",
        "site-packages",
        "__pypackages__",
    }
)


DEPENDENCY_METADATA_FILES = frozenset(
    {
        "cargo.lock",
    }
)


TRUFFLEHOG_EXCLUDE_GLOBS = (
    *(f"**/{segment}/**" for segment in sorted(DEPENDENCY_PATH_SEGMENTS)),
    "**/Cargo.lock",
)


def is_dependency_path(path: str) -> bool:
    """Retorna True quando qualquer segmento pertence a uma dependência."""
    normalized = path.replace("\\", "/").strip("/")
    if not normalized:
        return False
    parts = tuple(segment.casefold() for segment in normalized.split("/"))
    if parts[-1] in DEPENDENCY_METADATA_FILES:
        return True
    return any(
        segment in DEPENDENCY_PATH_SEGMENTS or segment.endswith(".egg-info")
        for segment in parts
    )


_FindingT = TypeVar("_FindingT")


def filter_crypto_wallet_findings(findings: Iterable[_FindingT]) -> list[_FindingT]:
    """Mantém somente detectores explicitamente aprovados para esta fase."""
    return [
        finding
        for finding in findings
        if getattr(finding, "type_id", "") in CRYPTO_WALLET_TYPE_IDS
        and not is_dependency_path(str(getattr(finding, "path", "")))
    ]
