"""Política central do escopo de varredura automática.

O detector genérico continua disponível para uso local/forense, mas o serviço
distribuído persiste apenas carteiras EVM/Solana, frases BIP39 e credenciais de
provedores de IA explicitamente catalogadas. Dependências vendorizadas são
ignoradas antes de consumir API, CPU ou espaço de evidência.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import TypeVar

from .ai_detection.catalog import AI_SECRET_TYPE_IDS
from .config import Config


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


KNOWN_CRYPTO_TEST_VECTOR_SUFFIXES = (
    "fixtures/randomized_v1.json",
    "fixtures/sealed_box_v1.json",
    "testdata/sealed-box-p256.json",
)


TRUFFLEHOG_EXCLUDE_GLOBS = (
    *(f"**/{segment}/**" for segment in sorted(DEPENDENCY_PATH_SEGMENTS)),
    "**/Cargo.lock",
    "**/fixtures/randomized_v1.json",
    "**/fixtures/sealed_box_v1.json",
    "**/testdata/sealed-box-p256.json",
    "**/forge-std/test/StdCheats.t.sol",
    "**/btcec/**/*_test.go",
    "**/btcutil/**/*_test.go",
    "**/waddrmgr/**/*_test.go",
)


def is_dependency_path(path: str) -> bool:
    """Retorna True quando qualquer segmento pertence a uma dependência."""
    normalized = path.replace("\\", "/").strip("/")
    if not normalized:
        return False
    parts = tuple(segment.casefold() for segment in normalized.split("/"))
    if parts[-1] in DEPENDENCY_METADATA_FILES:
        return True
    folded = "/".join(parts)
    if any(folded.endswith(suffix) for suffix in KNOWN_CRYPTO_TEST_VECTOR_SUFFIXES):
        return True
    if "/forge-std/test/stdcheats.t.sol" in f"/{folded}":
        return True
    basename = parts[-1]
    if basename.endswith("_test.go") and any(
        component in {"btcec", "btcutil", "waddrmgr"}
        for component in parts[:-1]
    ):
        return True
    if basename == "bench_test.go" and any(
        component in {"btcec", "btcutil", "waddrmgr"}
        for component in parts[:-1]
    ):
        return True
    return any(
        segment in DEPENDENCY_PATH_SEGMENTS or segment.endswith(".egg-info")
        for segment in parts
    )


_FindingT = TypeVar("_FindingT")

AUTOMATIC_SECRET_TYPE_IDS = CRYPTO_WALLET_TYPE_IDS | AI_SECRET_TYPE_IDS


def enabled_automatic_secret_type_ids(cfg: Config) -> frozenset[str]:
    """Retorna o escopo efetivamente ligado pelas duas flags operacionais."""
    enabled: set[str] = set()
    if cfg.ai_detection_enabled:
        enabled.update(AI_SECRET_TYPE_IDS)
    if cfg.private_key_detection_enabled:
        enabled.update(CRYPTO_WALLET_TYPE_IDS)
    return frozenset(enabled)


def filter_crypto_wallet_findings(findings: Iterable[_FindingT]) -> list[_FindingT]:
    """Mantém somente os detectores de carteira, para compatibilidade e testes."""
    return [
        finding
        for finding in findings
        if getattr(finding, "type_id", "") in CRYPTO_WALLET_TYPE_IDS
        and not is_dependency_path(str(getattr(finding, "path", "")))
    ]


def filter_automatic_findings(
    findings: Iterable[_FindingT], cfg: Config | None = None
) -> list[_FindingT]:
    """Mantém somente os detectores ligados no perfil operacional atual."""
    enabled = enabled_automatic_secret_type_ids(cfg or Config())
    return [
        finding
        for finding in findings
        if getattr(finding, "type_id", "") in enabled
        and not is_dependency_path(str(getattr(finding, "path", "")))
    ]
