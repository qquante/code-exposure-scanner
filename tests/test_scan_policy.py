from __future__ import annotations

from types import SimpleNamespace

import pytest

from secret_hunter.scan_policy import (
    AUTOMATIC_SECRET_TYPE_IDS,
    CRYPTO_WALLET_TYPE_IDS,
    TRUFFLEHOG_EXCLUDE_GLOBS,
    filter_crypto_wallet_findings,
    is_dependency_path,
)


@pytest.mark.parametrize(
    "path",
    (
        "backend/node_modules/dotenv/README.md",
        "frontend\\node_modules\\pkg\\index.js",
        ".venv/lib/site-packages/pkg/module.py",
        "vendor/pkg.egg-info/PKG-INFO",
        ".pnpm/ethers@6/node_modules/ethers/lib.js",
        "Cargo.lock",
        "workspace/crates/wallet/Cargo.lock",
        "fixtures/randomized_v1.json",
        "fixtures/sealed_box_v1.json",
        "internal/sealedbox/testdata/sealed-box-p256.json",
        "lib/forge-std/test/StdCheats.t.sol",
        "node/btcec/schnorr/signature_test.go",
        "node/btcec/ecdsa/bench_test.go",
        "wallet/waddrmgr/common_test.go",
    ),
)
def test_dependency_paths_are_rejected_case_insensitively(path: str) -> None:
    assert is_dependency_path(path)
    assert is_dependency_path(path.upper())


@pytest.mark.parametrize(
    "path",
    (
        "src/wallet.ts",
        ".env",
        "contracts/vendor/Wallet.sol",
        "dist/config.js",
        "Cargo.toml",
        "tests/wallet_private_key_test.py",
        "fixtures/customer-production-export.json",
    ),
)
def test_authored_paths_remain_scannable(path: str) -> None:
    assert not is_dependency_path(path)


def test_crypto_scope_is_an_explicit_allowlist_not_a_category_match() -> None:
    findings = [
        SimpleNamespace(type_id="evm_private_key", path="src/wallet.ts"),
        SimpleNamespace(type_id="solana_keypair_json", path="keys/id.json"),
        SimpleNamespace(type_id="bip39_mnemonic", path=".env"),
        SimpleNamespace(type_id="bitcoin_wif", path=".env"),
        SimpleNamespace(type_id="private_key_pem", path="id_rsa"),
        SimpleNamespace(type_id="evm_private_key", path="node_modules/pkg/example.js"),
    ]

    filtered = filter_crypto_wallet_findings(findings)

    assert [item.type_id for item in filtered] == [
        "evm_private_key",
        "solana_keypair_json",
        "bip39_mnemonic",
    ]
    assert "bitcoin_wif" not in CRYPTO_WALLET_TYPE_IDS
    assert "private_key_pem" not in CRYPTO_WALLET_TYPE_IDS
    assert "openrouter_api_key" in AUTOMATIC_SECRET_TYPE_IDS


def test_trufflehog_receives_equivalent_dependency_globs() -> None:
    assert "**/node_modules/**" in TRUFFLEHOG_EXCLUDE_GLOBS
    assert "**/site-packages/**" in TRUFFLEHOG_EXCLUDE_GLOBS
    assert "**/Cargo.lock" in TRUFFLEHOG_EXCLUDE_GLOBS
    assert "**/fixtures/randomized_v1.json" in TRUFFLEHOG_EXCLUDE_GLOBS
    assert "**/forge-std/test/StdCheats.t.sol" in TRUFFLEHOG_EXCLUDE_GLOBS
    assert "**/btcec/**/*_test.go" in TRUFFLEHOG_EXCLUDE_GLOBS
    assert "**/waddrmgr/**/*_test.go" in TRUFFLEHOG_EXCLUDE_GLOBS
