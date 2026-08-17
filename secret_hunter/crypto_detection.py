"""Detecção estrutural defensiva de material criptográfico.

Regex localiza candidatos; decodificação e invariantes de tamanho reduzem falsos
positivos. Nenhuma função deste módulo consulta rede, saldo, assina ou transmite
material privado.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from dataclasses import dataclass


_BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_BASE58_RE = re.compile(r"[1-9A-HJ-NP-Za-km-z]+")
_HEX_RE = re.compile(r"[0-9a-fA-F]+")
_QUOTED_TOKEN_RE = re.compile(
    r"(?P<quote>[\"'])(?P<value>[A-Za-z0-9_+/=-]{40,140})(?P=quote)"
)
_BYTE_ARRAY_RE = re.compile(
    r"\[\s*\d{1,3}(?:\s*,\s*\d{1,3}){31,63}\s*\]"
)
_ENV_PK_RE = re.compile(
    r"(?im)^\s*(?:export\s+)?PK\s*[:=]\s*[\"']?((?:0x)?[0-9a-f]{64})\b"
)

_SOLANA_CONTEXT = re.compile(
    r"(?i)(?:solana|@solana/web3\.js|solders|solana[_-]sdk|Keypair\.|"
    r"fromSecretKey|from_secret_key|from_base58_string|solana-keygen|"
    r"payer[_ .-]?(?:key|keypair)|signer[_ .-]?keypair|"
    r"solana[_ .-]?(?:private|secret|wallet|keypair))"
)
_SEED_CONTEXT = re.compile(
    r"(?i)(?:Keypair\.fromSeed|from_seed|seed[_ .-]?(?:bytes|key|secret)|"
    r"solana[_ .-]?seed)"
)
_SECRET_CONTEXT = re.compile(
    r"(?i)(?:private[_ .-]?key|secret[_ .-]?key|wallet[_ .-]?secret|"
    r"keypair|payer[_ .-]?key|signer[_ .-]?key)"
)
_SOLANA_PATH = re.compile(
    r"(?i)(?:^|[/\\])(?:id|wallet|payer|authority|.*-keypair)\.json$|"
    r"(?:solana|keypair|wallet|payer|authority)"
)


@dataclass(frozen=True)
class StructuralSecret:
    type_id: str
    secret: str
    start: int
    end: int


def _plausible_seed(data: bytes) -> bool:
    # Qualquer sequência de 32 bytes é uma seed Ed25519 possível, inclusive uma
    # seed fraca. Entropia baixa é risco adicional, não motivo para ignorá-la.
    return len(data) == 32


def solana_keypair_consistent(data: bytes) -> bool:
    """Confere seed+pubkey quando PyNaCl está disponível; fallback é estrutural."""
    if len(data) != 64:
        return False
    try:
        from nacl.signing import SigningKey  # type: ignore
    except ImportError:
        return True
    try:
        return SigningKey(data[:32]).verify_key.encode() == data[32:]
    except Exception:
        return False


def decode_base58(value: str) -> bytes | None:
    if not value or _BASE58_RE.fullmatch(value) is None:
        return None
    number = 0
    try:
        for char in value:
            number = number * 58 + _BASE58_ALPHABET.index(char)
        decoded = number.to_bytes((number.bit_length() + 7) // 8, "big")
    except (ValueError, OverflowError):
        return None
    return b"\x00" * (len(value) - len(value.lstrip("1"))) + decoded


def decode_base64(value: str) -> bytes | None:
    if not value:
        return None
    padded = value + "=" * (-len(value) % 4)
    try:
        return base64.b64decode(padded, altchars=b"-_", validate=True)
    except (binascii.Error, ValueError):
        return None


def decode_solana_material(type_id: str, value: str) -> bytes | None:
    """Decodifica os formatos aceitos sem derivar contas ou consultar rede."""
    try:
        if type_id in {"solana_keypair_json", "solana_seed_array"}:
            parsed = json.loads(value)
            if not isinstance(parsed, list) or not all(
                isinstance(item, int) and 0 <= item <= 255 for item in parsed
            ):
                return None
            return bytes(parsed)
        if type_id in {"solana_keypair_base58", "solana_seed_base58"}:
            return decode_base58(value)
        if type_id in {"solana_keypair_base64", "solana_seed_base64"}:
            return decode_base64(value)
        if type_id in {"solana_keypair_hex", "solana_seed_hex"}:
            return bytes.fromhex(value)
    except (TypeError, ValueError):
        return None
    return None


def valid_bip39_mnemonic(value: str) -> bool:
    """Valida wordlist e checksum BIP39 usando a implementação de referência."""
    words = value.strip().split()
    if len(words) not in {12, 15, 18, 21, 24}:
        return False
    try:
        from mnemonic import Mnemonic  # type: ignore
    except ImportError:
        return False
    try:
        return bool(Mnemonic("english").check(" ".join(words)))
    except Exception:
        return False


def _context(text: str, start: int, end: int, radius: int = 160) -> str:
    return text[max(0, start - radius): min(len(text), end + 64)]


def _solana_context(text: str, start: int, end: int, path: str) -> bool:
    return bool(_SOLANA_CONTEXT.search(_context(text, start, end)) or _SOLANA_PATH.search(path))


def _seed_context(text: str, start: int, end: int, path: str) -> bool:
    window = _context(text, start, end)
    return bool(
        _SEED_CONTEXT.search(window)
        or (_SOLANA_CONTEXT.search(window) and re.search(r"(?i)seed", window))
        or (re.search(r"(?i)seed", path) and _SOLANA_PATH.search(path))
    )


def _encoded_secret_type(value: str, *, solana_context: bool, seed_context: bool,
                         generic_secret_context: bool) -> tuple[str, bytes] | None:
    if _HEX_RE.fullmatch(value):
        try:
            decoded = bytes.fromhex(value)
        except ValueError:
            decoded = b""
        if len(decoded) == 64 and solana_context and solana_keypair_consistent(decoded):
            return "solana_keypair_hex", decoded
        if len(decoded) == 32 and seed_context and _plausible_seed(decoded):
            return "solana_seed_hex", decoded

    decoded58 = decode_base58(value)
    if decoded58 is not None:
        if (
            len(decoded58) == 64
            and (solana_context or generic_secret_context)
            and solana_keypair_consistent(decoded58)
        ):
            return "solana_keypair_base58", decoded58
        if len(decoded58) == 32 and seed_context and _plausible_seed(decoded58):
            return "solana_seed_base58", decoded58

    decoded64 = decode_base64(value)
    if decoded64 is not None:
        if len(decoded64) == 64 and solana_context and solana_keypair_consistent(decoded64):
            return "solana_keypair_base64", decoded64
        if len(decoded64) == 32 and seed_context and _plausible_seed(decoded64):
            return "solana_seed_base64", decoded64
    return None


def _extract_solana_arrays(text: str, path: str) -> list[StructuralSecret]:
    findings: list[StructuralSecret] = []
    for match in _BYTE_ARRAY_RE.finditer(text):
        try:
            values = json.loads(match.group(0))
        except (TypeError, ValueError):
            continue
        if not isinstance(values, list) or not all(
            isinstance(item, int) and 0 <= item <= 255 for item in values
        ):
            continue
        material = bytes(values)
        if (
            len(material) == 64
            and _solana_context(text, match.start(), match.end(), path)
            and solana_keypair_consistent(material)
        ):
            findings.append(
                StructuralSecret("solana_keypair_json", match.group(0), match.start(), match.end())
            )
        elif (
            len(material) == 32
            and _seed_context(text, match.start(), match.end(), path)
            and _plausible_seed(material)
        ):
            findings.append(
                StructuralSecret("solana_seed_array", match.group(0), match.start(), match.end())
            )
    return findings


def _extract_solana_encoded(text: str, path: str) -> list[StructuralSecret]:
    findings: list[StructuralSecret] = []
    for match in _QUOTED_TOKEN_RE.finditer(text):
        window = _context(text, match.start(), match.end())
        is_solana = bool(_SOLANA_CONTEXT.search(window) or _SOLANA_PATH.search(path))
        is_seed = _seed_context(text, match.start(), match.end(), path)
        is_generic_secret = bool(_SECRET_CONTEXT.search(window))
        classified = _encoded_secret_type(
            match.group("value"),
            solana_context=is_solana,
            seed_context=is_seed,
            generic_secret_context=is_generic_secret,
        )
        if classified is None:
            continue
        type_id, _decoded = classified
        findings.append(
            StructuralSecret(type_id, match.group("value"), match.start("value"), match.end("value"))
        )
    return findings


def _extract_evm_env_pk(text: str, path: str) -> list[StructuralSecret]:
    """Cobre o alias curto PK apenas em arquivos de ambiente não-template."""
    basename = path.replace("\\", "/").rsplit("/", 1)[-1].lower()
    sensitive = basename == ".env" or basename.startswith(".env.")
    if not sensitive or any(term in basename for term in ("example", "sample", "template")):
        return []
    findings: list[StructuralSecret] = []
    curve_order = int(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16
    )
    for match in _ENV_PK_RE.finditer(text):
        secret = match.group(1)
        raw = secret[2:] if secret.lower().startswith("0x") else secret
        scalar = int(raw, 16)
        if 0 < scalar < curve_order:
            findings.append(
                StructuralSecret("evm_private_key", secret, match.start(1), match.end(1))
            )
    return findings


def _extract_evm_keystore(text: str) -> list[StructuralSecret]:
    if '"ciphertext"' not in text or '"version"' not in text:
        return []
    try:
        payload = json.loads(text)
    except (TypeError, ValueError):
        return []
    if not isinstance(payload, dict) or payload.get("version") != 3:
        return []
    crypto = payload.get("crypto") or payload.get("Crypto")
    if not isinstance(crypto, dict):
        return []
    ciphertext = crypto.get("ciphertext")
    if not isinstance(ciphertext, str) or len(ciphertext) < 32:
        return []
    if not all(key in crypto for key in ("cipher", "kdf", "mac")):
        return []
    start = text.find(ciphertext)
    if start < 0:
        return []
    return [StructuralSecret("evm_keystore_v3", ciphertext, start, start + len(ciphertext))]


def extract_structural_crypto(text: str, *, path: str = "") -> list[StructuralSecret]:
    """Extrai formatos que exigem parsing/decodificação além de uma regex."""
    combined = [
        *_extract_solana_arrays(text, path),
        *_extract_solana_encoded(text, path),
        *_extract_evm_env_pk(text, path),
        *_extract_evm_keystore(text),
    ]
    seen: set[tuple[str, str, int]] = set()
    result: list[StructuralSecret] = []
    for item in combined:
        key = (item.type_id, item.secret, item.start)
        if key not in seen:
            seen.add(key)
            result.append(item)
    return result