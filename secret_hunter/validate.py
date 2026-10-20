"""Validação MÍNIMA de segredos (opt-in, defensiva).

Princípios:
  - Só confirma autenticação quando o repositório está explicitamente autorizado.
  - Requisições mínimas e únicas (sem ler dados de negócio).
  - Para CRIPTO: o material NUNCA sai da máquina. Validamos somente formato,
    checksum e consistência criptográfica local; não consultamos saldo ou RPC.

A validação é OPT-IN (config.validate) e deve ser usada apenas em contexto de
divulgação responsável / com autorização.
"""

from __future__ import annotations

import logging
import time

import requests

from .config import Config
from .crypto_detection import decode_solana_material
from .extract import Finding

log = logging.getLogger("secret_hunter.validate")

# Base58 / Base58Check (Bitcoin WIF, Solana)
_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58decode(s: str) -> bytes:
    n = 0
    for ch in s:
        n = n * 58 + _ALPHABET.index(ch)
    out = b""
    while n > 0:
        n, r = divmod(n, 256)
        out = bytes([r]) + out
    # zeros à esquerda
    pad = len(s) - len(s.lstrip("1"))
    return b"\x00" * pad + out


def b58encode(data: bytes) -> str:
    n = int.from_bytes(data, "big")
    out = ""
    while n > 0:
        n, remainder = divmod(n, 58)
        out = _ALPHABET[remainder] + out
    pad = len(data) - len(data.lstrip(b"\x00"))
    return "1" * pad + out


def _b58check(payload: bytes) -> str:
    """Base58Check (com checksum SHA256d)."""
    import hashlib

    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    data = payload + checksum
    n = int.from_bytes(data, "big")
    out = ""
    while n > 0:
        n, r = divmod(n, 58)
        out = _ALPHABET[r] + out
    pad = len(data) - len(data.lstrip(b"\x00"))
    return "1" * pad + out


# Validação de cripto estritamente local
def _evm_address_from_key(priv_hex: str) -> str | None:
    """Deriva o endereço EVM a partir da chave privada. Retorna None se sem lib."""
    raw = priv_hex[2:] if priv_hex.startswith("0x") else priv_hex
    key_bytes = bytes.fromhex(raw)

    try:
        from eth_account import Account  # type: ignore
        acct = Account.from_key(key_bytes)
        return acct.address
    except Exception:
        pass

    try:
        from coincurve import PrivateKey  # type: ignore
        pk = PrivateKey(key_bytes)
        pub = pk.public_key.format(compressed=False)[1:]  # 64 bytes
        return _keccak_address(pub)
    except Exception:
        pass

    try:
        import ecdsa  # type: ignore
        sk = ecdsa.SigningKey.from_string(key_bytes, curve=ecdsa.SECP256k1)
        pub = sk.get_verifying_key().to_string()  # uncompressed 64 bytes
        return _keccak_address(pub)
    except Exception:
        return None


def _keccak_address(pub_64: bytes) -> str:
    """Keccak-256 dos 64 bytes da pubkey -> últimos 20 bytes = endereço."""
    from Crypto.Hash import keccak  # type: ignore  (pycryptodome)

    k = keccak.new(digest_bits=256)
    k.update(pub_64)
    return "0x" + k.hexdigest()[-40:]


def _btc_address_from_wif(wif: str) -> str | None:
    try:
        decoded = b58decode(wif)
        if len(decoded) not in (37, 38):  # version + 32 key (+ comp flag) + 4 checksum
            return None
        body, checksum = decoded[:-4], decoded[-4:]
        import hashlib
        if hashlib.sha256(hashlib.sha256(body).digest()).digest()[:4] != checksum:
            return None
        # corpo = versão(1) + chave(32) [+ flag 0x01]
        if body[0] not in (0x80, 0xEF):
            return None
        compressed = len(body) == 34
        if compressed and body[-1] != 0x01:
            return None
        priv = body[1:33]
        try:
            import ecdsa  # type: ignore
            sk = ecdsa.SigningKey.from_string(priv, curve=ecdsa.SECP256k1)
            point = sk.get_verifying_key().to_string()
            if compressed:
                prefix = b"\x02" if point[-1] % 2 == 0 else b"\x03"
                serialized = prefix + point[:32]
            else:
                serialized = b"\x04" + point
            address_version = b"\x00" if body[0] == 0x80 else b"\x6f"
            return _btc_pubkey_to_address(serialized, address_version)
        except Exception:
            return None
    except Exception:
        return None


def _btc_pubkey_to_address(serialized_pubkey: bytes, address_version: bytes) -> str:
    import hashlib
    h = hashlib.sha256(serialized_pubkey).digest()
    # RIPEMD-160 pode não estar disponível em alguns builds do OpenSSL
    try:
        r = hashlib.new("ripemd160", h).digest()
    except Exception:
        return ""
    return _b58check(address_version + r)


def _solana_pubkey_from_keypair(keypair: bytes) -> str | None:
    """Deriva a pubkey Solana (ed25519) e confere a metade pública do keypair."""
    if len(keypair) != 64:
        return None
    try:
        from nacl.signing import SigningKey  # type: ignore  (PyNaCl)
        derived = SigningKey(keypair[:32]).verify_key.encode()
        if keypair[32:] != derived:
            return None
        return b58encode(derived)
    except Exception:
        return None


def _solana_pubkey_from_seed(seed: bytes) -> str | None:
    """Deriva localmente a pubkey Ed25519 a partir de uma seed de 32 bytes."""
    if len(seed) != 32:
        return None
    try:
        from nacl.signing import SigningKey  # type: ignore  (PyNaCl)
        return b58encode(SigningKey(seed).verify_key.encode())
    except Exception:
        return None


def validate_evm(f: Finding, cfg: Config) -> None:
    """Valida escalar secp256k1 e deriva endereço sem qualquer consulta externa."""
    addr = _evm_address_from_key(f.secret_raw)
    f.validate_status = "format_valid"
    if addr is None:
        f.validate_detail = "escalar secp256k1 válido; derivação indisponível sem biblioteca local"
    else:
        f.validate_detail = f"escalar secp256k1 válido; endereço derivado localmente: {addr}"
    log.info("evm %s: validação local concluída", f.secret_redacted)


def validate_btc(f: Finding, cfg: Config) -> None:
    addr = _btc_address_from_wif(f.secret_raw)
    if addr in (None, ""):
        f.validate_status = "unverified"
        f.validate_detail = "WIF malformado ou sem lib ecdsa (checksum base58check ainda é verificado)"
        return
    f.validate_status = "format_valid"
    f.validate_detail = f"WIF/checksum válidos; endereço público derivado localmente: {addr}"


def validate_solana(f: Finding, cfg: Config) -> None:
    material = decode_solana_material(f.type_id, f.secret_raw)
    if material is None or len(material) not in {32, 64}:
        f.validate_status = "unverified"
        f.validate_detail = "material Solana malformado"
        return
    if len(material) == 64:
        pub = _solana_pubkey_from_keypair(material)
        label = "keypair"
    else:
        pub = _solana_pubkey_from_seed(material)
        label = "seed"
    f.validate_status = "format_valid"
    if pub is None:
        f.validate_detail = f"{label} estruturalmente válido; derivação indisponível sem PyNaCl"
    else:
        f.validate_detail = f"{label} consistente; pubkey derivada localmente: {pub}"


# Validação de chaves de API (uma única requisição mínima)
def _do_http(f: Finding, method: str, url: str, *, headers=None, auth=None,
             ok_codes=(200,), cfg: Config) -> None:
    """Uma requisição mínima com retry/backoff para tolerar falhas transitórias."""
    retries = max(int(getattr(cfg, "http_retries", 3)), 1)
    last_err = ""
    for attempt in range(1, retries + 1):
        try:
            r = requests.request(
                method, url, headers=headers, auth=auth, timeout=cfg.request_timeout,
            )
            # sucesso ou resposta definitiva do provedor -> não retenta
            if r.status_code in ok_codes or r.status_code in (401, 403):
                if r.status_code in ok_codes:
                    f.validate_status = "provider_active"
                    f.validate_detail = f"HTTP {r.status_code}"
                else:
                    f.validate_status = "provider_inactive"
                    f.validate_detail = f"HTTP {r.status_code} (acesso negado)"
                log.info("%s %s: %s", f.type_id, f.secret_redacted, f.validate_status)
                return
            # status ambíguo (5xx, timeout) -> registra e retenta
            last_err = f"HTTP {r.status_code}"
            log.warning("%s %s: HTTP %d (tentativa %d)", f.type_id, f.secret_redacted,
                        r.status_code, attempt)
        except Exception as exc:
            last_err = type(exc).__name__
            log.warning("%s %s: %s (tentativa %d)", f.type_id, f.secret_redacted,
                        last_err, attempt)
        if attempt < retries:
            time.sleep(min(2 ** attempt, 8))
    f.validate_status = "unverified"
    f.validate_detail = f"indeterminado após {retries} tentativas: {last_err}"


def validate_stripe(f: Finding, cfg: Config) -> None:
    _do_http(f, "GET", "https://api.stripe.com/v1/account",
             auth=(f.secret_raw, ""), cfg=cfg)


def validate_mercadopago(f: Finding, cfg: Config) -> None:
    _do_http(f, "GET", "https://api.mercadopago.com/users/me",
             headers={"Authorization": f"Bearer {f.secret_raw}"}, cfg=cfg)


def validate_github(f: Finding, cfg: Config) -> None:
    _do_http(f, "GET", "https://api.github.com/user",
             headers={"Authorization": f"token {f.secret_raw}"}, cfg=cfg)


def validate_gitlab(f: Finding, cfg: Config) -> None:
    _do_http(f, "GET", "https://gitlab.com/api/v4/user",
             headers={"PRIVATE-TOKEN": f.secret_raw}, cfg=cfg)


def validate_openai(f: Finding, cfg: Config) -> None:
    _do_http(f, "GET", "https://api.openai.com/v1/models",
             headers={"Authorization": f"Bearer {f.secret_raw}"}, cfg=cfg)


def validate_huggingface(f: Finding, cfg: Config) -> None:
    _do_http(f, "GET", "https://huggingface.co/api/whoami-v2",
             headers={"Authorization": f"Bearer {f.secret_raw}"}, cfg=cfg)


def validate_slack(f: Finding, cfg: Config) -> None:
    _do_http(f, "GET", "https://slack.com/api/auth.test",
             headers={"Authorization": f"Bearer {f.secret_raw}"}, cfg=cfg)


def validate_telegram(f: Finding, cfg: Config) -> None:
    _do_http(f, "GET", f"https://api.telegram.org/bot{f.secret_raw}/getMe", cfg=cfg)


_VALIDATORS = {
    "stripe_live": validate_stripe,
    "stripe_restricted": validate_stripe,
    "stripe_test": validate_stripe,
    "mercadopago": validate_mercadopago,
    "mercadopago_test": validate_mercadopago,
    "github_pat": validate_github,
    "github_fine_grained": validate_github,
    "github_oauth": validate_github,
    "gitlab_pat": validate_gitlab,
    "openai_proj": validate_openai,
    "openai_legacy": validate_openai,
    "huggingface": validate_huggingface,
    "slack_token": validate_slack,
    "telegram_bot": validate_telegram,
    "evm_private_key": validate_evm,
    "bitcoin_wif": validate_btc,
    "solana_keypair_json": validate_solana,
    "solana_keypair_base58": validate_solana,
    "solana_keypair_base64": validate_solana,
    "solana_keypair_hex": validate_solana,
    "solana_seed_array": validate_solana,
    "solana_seed_base58": validate_solana,
    "solana_seed_base64": validate_solana,
    "solana_seed_hex": validate_solana,
}


def validate(finding: Finding, cfg: Config) -> None:
    """Aplica a validação apropriada (se houver) a um Finding."""
    fn = _VALIDATORS.get(finding.type_id)
    if fn is None:
        finding.validate_status = "unverified"
        finding.validate_detail = "validação não suportada (checagem manual)"
        return
    if finding.type_id.startswith(("evm", "bitcoin", "solana")) and not cfg.validate_crypto:
        # cripto exige opt-in explícito para decodificação e derivação somente locais
        finding.validate_status = "unverified"
        finding.validate_detail = "validação cripto desabilitada (--validate-crypto)"
        return
    try:
        fn(finding, cfg)
    except Exception as exc:  # pragma: no cover
        finding.validate_status = "error"
        finding.validate_detail = str(exc)[:120]
