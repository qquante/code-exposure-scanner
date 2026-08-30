"""Extração e classificação de segredos a partir de texto.

Regras de segurança:
  - O segredo bruto fica apenas em memória (Finding.secret_raw); a referência é
    removida após o HMAC. Strings Python não oferecem garantia de zeroização.
  - O deploy PostgreSQL persiste apenas hint fixo e fingerprint HMAC.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlsplit

from . import patterns as P
from .crypto_detection import extract_structural_crypto, valid_bip39_mnemonic
from .scan_policy import is_dependency_path


@dataclass
class Finding:
    type_id: str
    provider: str
    category: str
    risk: str
    secret_redacted: str
    repo: str = ""          # "owner/name"
    path: str = ""
    branch: str = ""
    commit: str = ""
    blob_sha: str = ""
    line: int = 0
    context: str = ""       # trecho ao redor (já redigido)
    source: str = "code"    # code | history | trufflehog | ingest
    # transiente — NÃO persistir
    secret_raw: str = field(default="", repr=False)
    fingerprint: str = ""
    validate_status: str = ""
    validate_detail: str = ""


def redact(secret: str, head: int = 4, tail: int = 4) -> str:
    """Versão segura para exibição/persistência: prefixo + … + sufixo."""
    s = secret.strip()
    if len(s) <= head + tail + 3:
        return s[:1] + "…" if s else ""
    return f"{s[:head]}…{s[-tail:]}"


def _context_around(text: str, start: int, end: int, secret: str, span: int = 48) -> str:
    ctx = text[max(0, start - span): end + span].replace("\n", " ")
    # redige todas as ocorrências do segredo dentro do contexto
    return ctx.replace(secret, redact(secret))


def _match_secret(st: P.SecretType, m) -> str:
    """Extrai a string do segredo do match, considerando grupos especiais."""
    if st.type_id == "generic_assignment":
        return m.group("val")
    if st.type_id == "bip39_mnemonic":
        return m.group(1)
    if st.type_id == "jwt":
        return m.group(1)
    return next((group for group in m.groups() if group is not None), "")


def _passes_filters(st: P.SecretType, secret: str) -> bool:
    """Filtros de plausibilidade para reduzir falsos positivos."""
    if st.type_id == "evm_private_key":
        return P.plausible_evm_key(secret)
    if st.type_id == "generic_assignment":
        if P.is_placeholder(secret):
            return False
        return P.shannon_entropy(secret) >= 3.5
    if st.category == "ai" and st.type_id.endswith("_context"):
        return not P.is_placeholder(secret) and P.shannon_entropy(secret) >= 3.2
    if st.type_id == "bitcoin_wif":
        return not P.is_placeholder(secret) and P.plausible_bitcoin_wif(secret)
    if st.type_id in {
        "mongodb_uri", "postgres_uri", "mysql_uri", "redis_uri", "generic_uri_creds"
    }:
        try:
            parsed = urlsplit(secret)
        except ValueError:
            return False
        return bool(parsed.hostname and parsed.password is not None)
    if st.type_id == "bip39_mnemonic":
        return valid_bip39_mnemonic(secret)
    if st.type_id == "private_key_pem":
        return True
    if st.type_id == "jwt":
        return not P.is_placeholder(secret)
    if P.is_placeholder(secret):
        return False
    return True


def extract_from_text(
    text: str,
    *,
    repo: str = "",
    path: str = "",
    branch: str = "",
    commit: str = "",
    source: str = "code",
) -> list[Finding]:
    """Varre um texto com todos os padrões e devolve Findings classificados."""
    findings: list[Finding] = []
    if not text or is_dependency_path(path):
        return findings

    for st in P.SECRET_TYPES:
        if st.regex is None:
            continue
        try:
            matches = list(st.regex.finditer(text))
        except Exception:
            continue
        for m in matches:
            secret = _match_secret(st, m)
            if not secret or not _passes_filters(st, secret):
                continue
            if st.type_id == "private_key_pem":
                # elimina false positive de código PHP de criptografia
                # (openssl_private_encrypt, openssl_pkey_get_private, phpseclib...)
                window = text[max(0, m.start() - 160): m.end() + 160]
                if P.is_php_encryption_context(window):
                    continue

            # linha do match (1-based)
            line = text.count("\n", 0, m.start()) + 1
            findings.append(
                Finding(
                    type_id=st.type_id,
                    provider=st.provider,
                    category=st.category,
                    risk=st.risk,
                    secret_redacted=redact(secret),
                    secret_raw=secret,
                    repo=repo,
                    path=path,
                    branch=branch,
                    commit=commit,
                    line=line,
                    context=_context_around(text, m.start(), m.end(), secret),
                    source=source,
                )
            )

    structural = extract_structural_crypto(text, path=path)
    solana_hex = {
        (candidate.secret, text.count("\n", 0, candidate.start) + 1)
        for candidate in structural
        if candidate.type_id == "solana_seed_hex"
    }
    if solana_hex:
        findings = [
            finding for finding in findings
            if not (
                finding.type_id == "evm_private_key"
                and (finding.secret_raw, finding.line) in solana_hex
            )
        ]

    for candidate in structural:
        st = P.TYPES_BY_ID[candidate.type_id]
        line = text.count("\n", 0, candidate.start) + 1
        if any(
            finding.type_id == candidate.type_id
            and finding.secret_raw == candidate.secret
            and finding.line == line
            for finding in findings
        ):
            continue
        findings.append(
            Finding(
                type_id=st.type_id,
                provider=st.provider,
                category=st.category,
                risk=st.risk,
                secret_redacted=redact(candidate.secret),
                secret_raw=candidate.secret,
                repo=repo,
                path=path,
                branch=branch,
                commit=commit,
                line=line,
                context=_context_around(
                    text, candidate.start, candidate.end, candidate.secret
                ),
                source=source,
            )
        )
    return findings


def dedupe(findings: list[Finding]) -> list[Finding]:
    """Remove o detector duplicado, preservando localizações distintas."""
    seen: set[tuple[str, str, str, str, str, int]] = set()
    out: list[Finding] = []
    for f in findings:
        identity = f.secret_raw or f.fingerprint or f.secret_redacted
        key = (identity, f.repo, f.path, f.commit, f.blob_sha, f.line)
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out
