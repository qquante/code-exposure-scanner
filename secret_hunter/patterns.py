"""Padrões de detecção de segredos.

Cada SecretType associa uma regex a metadados de classificação:
  - type_id   : identificador estável (usado na validação e no storage)
  - category  : cloud | payment | database | crypto | vcs | messaging | ai | generic
  - risk      : critical | high | medium | low
  - verify_note : como validar de forma MÍNIMA (referência, sem enviar a chave inteira)

IMPORTANTE (ética white-hat): o objetivo é DETECTAR e NOTIFICAR. As regex
capturam o segredo em `group(1)` para permitir redação imediata.
"""

from __future__ import annotations

import hashlib
import math
import re
from collections import Counter
from dataclasses import dataclass


# --------------------------------------------------------------------------- #
# Utilidades
# --------------------------------------------------------------------------- #
def shannon_entropy(data: str) -> float:
    """Entropia de Shannon (bits/caractere) — usada para filtrar falsos positivos."""
    if not data:
        return 0.0
    total = len(data)
    counts = Counter(data)
    return -sum((v / total) * math.log2(v / total) for v in counts.values())


# Palavras que aparecem com frequência em "secrets" fake de exemplo/teste.
_PLACEHOLDER_TERMS = (
    "example", "your_", "your-", "xxx", "xxxx", "changeme", "change_me",
    "replace", "todo", "fake", "dummy", "sample", "test", "password",
    "secret", "api_key", "apikey", "<", ">", "...", "null", "none",
)

# Marcadores de código PHP de criptografia (exemplos/tutoriais) que NÃO são
# vazamentos — servem para eliminar false positives do padrão private_key_pem.
_PHP_ENCRYPTION_MARKERS = (
    "openssl_private_encrypt",
    "openssl_private_decrypt",
    "openssl_pkey_get_private",
    "openssl_get_privatekey",
    "openssl_pkey_export",
    "openssl_pkcs7_",
    "openssl_encrypt",
    "openssl_decrypt",
    "phpseclib",
    "mcrypt_",
    "sodium_crypto_",
    "crypt\\rsa",
    "rsa\\crypt",
    "loadprivatekey",
)


def is_php_encryption_context(text: str) -> bool:
    """True se o trecho parece código PHP de criptografia (não um vazamento)."""
    low = text.lower()
    return any(marker in low for marker in _PHP_ENCRYPTION_MARKERS)


_BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


@dataclass(frozen=True)
class SecretType:
    type_id: str
    name: str
    provider: str
    category: str
    risk: str
    regex: re.Pattern | None
    description: str
    verify_note: str = ""
    revision: str = "1"


_EVM_CHAIN_HINT = (
    r"(?:evm|eth(?:ereum)?|base|bsc|bnb|robinhood|polygon|matic|arbitrum|arb|"
    r"optimism|avalanche|avax|celo|linea|scroll|blast|zksync)"
)
_EVM_ROLE_HINT = (
    r"(?:private[_ .-]?key|priv[_ .-]?key|wallet[_ .-]?(?:key|pk)|deployer[_ .-]?(?:key|pk)|"
    r"signer[_ .-]?(?:key|pk)|account[_ .-]?(?:key|pk)|owner[_ .-]?(?:key|pk)|"
    r"operator[_ .-]?(?:key|pk)|relayer[_ .-]?(?:key|pk)|treasury[_ .-]?(?:key|pk))"
)
_EVM_LIBRARY_HINT = (
    r"(?:(?:new\s+)?(?:ethers(?:\.js)?\.)?Wallet|Account\.from[_ .-]?key|"
    r"privateKeyToAccount|private_key_to_account|--private-key)"
)


# --------------------------------------------------------------------------- #
# Catálogo de padrões
# --------------------------------------------------------------------------- #
SECRET_TYPES: list[SecretType] = [
    # ----------------------------- Pagamentos ----------------------------- #
    SecretType(
        "stripe_live", "Stripe secret key (live)", "Stripe", "payment", "critical",
        re.compile(r"\b(sk_live_[0-9a-zA-Z]{16,})\b"),
        "Chave secreta de produção da Stripe. Permite cobrar/refundar e acessar dados de clientes.",
        "GET https://api.stripe.com/v1/account com -u <chave>: (200 = válida)",
    ),
    SecretType(
        "stripe_restricted", "Stripe restricted key (live)", "Stripe", "payment", "critical",
        re.compile(r"\b(rk_live_[0-9a-zA-Z]{16,})\b"),
        "Chave restrita (escopo limitado) de produção da Stripe.",
        "Mesma checagem da Stripe, com escopo reduzido.",
    ),
    SecretType(
        "stripe_test", "Stripe secret key (test)", "Stripe", "payment", "low",
        re.compile(r"\b(sk_test_[0-9a-zA-Z]{16,})\b"),
        "Chave de TESTE da Stripe — risco baixo, mas revela práticas do dev.",
        "GET https://api.stripe.com/v1/account",
    ),
    SecretType(
        "mercadopago", "Mercado Pago access token", "Mercado Pago", "payment", "critical",
        re.compile(r"\b(APP_USR-[0-9a-zA-Z\-]{15,})\b"),
        "Token de produção do Mercado Pago. Acesso a transações, CPFs e dados financeiros.",
        "GET https://api.mercadopago.com/users/me com Authorization: Bearer <token>",
    ),
    SecretType(
        "mercadopago_test", "Mercado Pago token (test)", "Mercado Pago", "payment", "low",
        re.compile(r"\b(TEST-[0-9a-zA-Z\-]{15,})\b"),
        "Token de sandbox do Mercado Pago.",
        "GET https://api.mercadopago.com/users/me",
    ),

    # ------------------------------ Nuvem ------------------------------- #
    SecretType(
        "aws_akia", "AWS Access Key ID (AKIA)", "Amazon AWS", "cloud", "high",
        re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
        "Access Key ID AWS. Sozinho não basta (precisa do Secret Access Key), mas é o 1º fator.",
        "Requer o par (secret key). ID isolado = 'não verificável sozinho'.",
    ),
    SecretType(
        "aws_asia", "AWS temporary key (ASIA)", "Amazon AWS", "cloud", "high",
        re.compile(r"\b(ASIA[0-9A-Z]{16})\b"),
        "Credencial temporária AWS (associada a STS/sessão).",
        "Requer o par + token de sessão.",
    ),
    SecretType(
        "google_api_key", "Google/Gemini API key", "Google", "cloud", "high",
        re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b"),
        "Chave de API Google (Maps, Gemini, etc.). Pode gerar custo e expor dados.",
        "Validação depende do serviço alvo; em geral 'não verificável' sem escolher a API.",
    ),

    # ----------------------------- Bancos de dados ----------------------- #
    SecretType(
        "mongodb_uri", "MongoDB connection string", "MongoDB", "database", "critical",
        re.compile(r"(mongodb(?:\+srv)?://[^\s\"'<>]+)"),
        "URI de conexão do MongoDB. Acesso total ao banco (dados de usuários, CPFs, receitas).",
        "Tentativa de conexão (opcional, pesada).",
    ),
    SecretType(
        "postgres_uri", "PostgreSQL connection string", "PostgreSQL", "database", "critical",
        re.compile(r"(postgres(?:ql)?://[^\s\"'<>]+)"),
        "URI de conexão PostgreSQL com credenciais embutidas.",
        "Tentativa de conexão (opcional, pesada).",
    ),
    SecretType(
        "mysql_uri", "MySQL connection string", "MySQL", "database", "critical",
        re.compile(r"(mysql://[^\s\"'<>]+)"),
        "URI de conexão MySQL com credenciais embutidas.",
        "Tentativa de conexão (opcional, pesada).",
    ),
    SecretType(
        "redis_uri", "Redis connection string", "Redis", "database", "high",
        re.compile(r"(redis://[^\s\"'<>]+)"),
        "URI de conexão Redis (pode conter senha).",
        "Tentativa de conexão (opcional).",
    ),
    SecretType(
        "generic_uri_creds", "URL com user:pass embutido", "—", "database", "high",
        re.compile(r"([a-zA-Z][a-zA-Z0-9+.-]*://[^/\s:@\"']+:[^/\s:@\"']+@[^\s\"'<>]+)"),
        "Qualquer URI com usuário:senha embutidos na string.",
        "Depende do esquema.",
    ),

    # ------------------------------- VCS -------------------------------- #
    SecretType(
        "github_pat", "GitHub PAT (ghp_)", "GitHub", "vcs", "critical",
        re.compile(r"\b(ghp_[0-9a-zA-Z]{36})\b"),
        "Personal Access Token do GitHub — acesso total aos repositórios do usuário.",
        "GET https://api.github.com/user com Authorization: token <token>",
    ),
    SecretType(
        "github_fine_grained", "GitHub fine-grained PAT", "GitHub", "vcs", "critical",
        re.compile(r"\b(github_pat_[0-9a-zA-Z_]{22,})\b"),
        "Fine-grained PAT do GitHub.",
        "GET https://api.github.com/user",
    ),
    SecretType(
        "github_oauth", "GitHub OAuth token (gho_)", "GitHub", "vcs", "high",
        re.compile(r"\b(gh[osru]_[0-9a-zA-Z]{36})\b"),
        "Token OAuth/app do GitHub.",
        "GET https://api.github.com/user",
    ),
    SecretType(
        "gitlab_pat", "GitLab PAT (glpat-)", "GitLab", "vcs", "critical",
        re.compile(r"\b(glpat-[0-9a-zA-Z_\-]{20,})\b"),
        "Personal Access Token do GitLab.",
        "GET https://gitlab.com/api/v4/user com PRIVATE-TOKEN: <token>",
    ),

    # -------------------------------- IA --------------------------------- #
    SecretType(
        "openai_proj", "OpenAI API key (sk-proj-)", "OpenAI", "ai", "high",
        re.compile(r"\b(sk-proj-[A-Za-z0-9_\-]{20,})\b"),
        "Chave de API OpenAI (projetos). Gera custo e expõe uso.",
        "GET https://api.openai.com/v1/models com Authorization: Bearer <chave>",
    ),
    SecretType(
        "openai_legacy", "OpenAI API key (sk-)", "OpenAI", "ai", "high",
        re.compile(r"\b(sk-[A-Za-z0-9]{48})\b"),
        "Chave de API OpenAI (formato legado).",
        "GET https://api.openai.com/v1/models",
    ),
    SecretType(
        "huggingface", "Hugging Face token (hf_)", "Hugging Face", "ai", "high",
        re.compile(r"\b(hf_[A-Za-z0-9]{20,})\b"),
        "Token de escrita/leitura do Hugging Face Hub.",
        "GET https://huggingface.co/api/whoami-v2 com Authorization: Bearer <token>",
    ),

    # ---------------------------- Mensageria ------------------------------ #
    SecretType(
        "slack_token", "Slack token (xox*)", "Slack", "messaging", "high",
        re.compile(r"\b(xox[baprs]-[0-9A-Za-z\-]{10,})\b"),
        "Token do Slack (bot/user/app).",
        "GET https://slack.com/api/auth.test com Authorization: Bearer <token>",
    ),
    SecretType(
        "telegram_bot", "Telegram bot token", "Telegram", "messaging", "high",
        re.compile(r"\b([0-9]{8,10}:[A-Za-z0-9_\-]{35})\b"),
        "Token de bot do Telegram.",
        "GET https://api.telegram.org/bot<token>/getMe",
    ),

    # ------------------------------ Cripto ------------------------------- #
    SecretType(
        "evm_private_key", "EVM private key (0x...)", "EVM (ETH/BSC/Polygon...)", "crypto", "critical",
        re.compile(
            rf"(?i)(?:{_EVM_ROLE_HINT}|{_EVM_CHAIN_HINT}[_ .-]*(?:key|pk)|"
            rf"{_EVM_LIBRARY_HINT}|secret[_ .-]?key)"
            r"[^\r\n]{0,64}?\b((?:0x)?[0-9a-f]{64})\b"
        ),
        "Chave privada secp256k1 de 32 bytes usada por qualquer rede EVM.",
        "Valida o escalar e deriva o endereço público somente em memória local.",
        revision="evm-context-v2",
    ),
    SecretType(
        "bitcoin_wif", "Bitcoin private key (WIF)", "Bitcoin", "crypto", "critical",
        re.compile(r"\b([5KL][1-9A-HJ-NP-Za-km-z]{50,51})\b"),
        "Chave privada Bitcoin em formato WIF.",
        "Valida Base58Check e deriva o endereço público localmente.",
    ),
    SecretType(
        "solana_keypair_json", "Solana keypair (array de 64 bytes)", "Solana", "crypto", "critical",
        None,
        "Keypair Ed25519 exportado pelo Solana CLI ou SDK como 64 bytes.",
        "Valida tamanho e consistência seed+pubkey somente em memória local.",
        revision="solana-structural-v2",
    ),
    SecretType(
        "solana_keypair_base58", "Solana keypair (Base58)", "Solana", "crypto", "critical",
        None,
        "Keypair Ed25519 de 64 bytes serializado em Base58.",
        "Decodifica Base58 e valida a consistência local do keypair.",
        revision="solana-structural-v2",
    ),
    SecretType(
        "solana_keypair_base64", "Solana keypair (Base64)", "Solana", "crypto", "critical",
        None,
        "Keypair Ed25519 de 64 bytes serializado em Base64/Base64URL.",
        "Decodifica Base64 e valida a consistência local do keypair.",
        revision="solana-structural-v2",
    ),
    SecretType(
        "solana_keypair_hex", "Solana keypair (hex)", "Solana", "crypto", "critical",
        None,
        "Keypair Ed25519 de 64 bytes serializado em 128 caracteres hexadecimais.",
        "Decodifica hexadecimal e valida a consistência local do keypair.",
        revision="solana-structural-v2",
    ),
    SecretType(
        "solana_seed_array", "Solana seed (array de 32 bytes)", "Solana", "crypto", "critical",
        None,
        "Seed Ed25519 de 32 bytes passada a Keypair.fromSeed ou equivalente.",
        "Valida tamanho e deriva a pubkey somente em memória local.",
        revision="solana-structural-v2",
    ),
    SecretType(
        "solana_seed_base58", "Solana seed (Base58)", "Solana", "crypto", "critical",
        None,
        "Seed Ed25519 de 32 bytes serializada em Base58 com contexto explícito de seed.",
        "Decodifica e deriva a pubkey somente em memória local.",
        revision="solana-structural-v2",
    ),
    SecretType(
        "solana_seed_base64", "Solana seed (Base64)", "Solana", "crypto", "critical",
        None,
        "Seed Ed25519 de 32 bytes serializada em Base64 com contexto explícito de seed.",
        "Decodifica e deriva a pubkey somente em memória local.",
        revision="solana-structural-v2",
    ),
    SecretType(
        "solana_seed_hex", "Solana seed (hex)", "Solana", "crypto", "critical",
        None,
        "Seed Ed25519 de 32 bytes serializada em hexadecimal com contexto explícito de Solana.",
        "Decodifica e deriva a pubkey somente em memória local.",
        revision="solana-structural-v2",
    ),
    SecretType(
        "evm_keystore_v3", "EVM keystore JSON v3 (criptografado)", "EVM", "crypto", "high",
        None,
        "Artefato de wallet EVM criptografado; não é uma chave privada em texto puro.",
        "Confirma somente a estrutura JSON v3 e nunca tenta descriptografar.",
        revision="evm-keystore-structural-v1",
    ),
    SecretType(
        "bip39_mnemonic",
        "BIP39 mnemonic (12/15/18/21/24 palavras)",
        "Cripto (seed phrase)",
        "crypto",
        "critical",
        re.compile(
            r"(?i)(?:mnemonic|seed[_ -]?phrase|recovery[_ -]?phrase)"
            r"[^\r\n]{0,32}?[\"']?"
            r"((?:[a-z]{3,}\s+){23}[a-z]{3,}|(?:[a-z]{3,}\s+){20}[a-z]{3,}|"
            r"(?:[a-z]{3,}\s+){17}[a-z]{3,}|(?:[a-z]{3,}\s+){14}[a-z]{3,}|"
            r"(?:[a-z]{3,}\s+){11}[a-z]{3,})\b"
        ),
        "Frase-semente BIP39 com wordlist e checksum válidos.",
        "Valida wordlist/checksum localmente; nunca deriva contas nem transmite a frase.",
        revision="bip39-checksum-v2",
    ),
    SecretType(
        "private_key_pem", "Private key (PEM)", "—", "crypto", "critical",
        re.compile(
            r"(-----BEGIN (?P<pem_label>[A-Z0-9 ]*PRIVATE KEY)-----"
            r"[\s\S]{1,100000}?-----END (?P=pem_label)-----)"
        ),
        "Bloco de chave privada PEM (RSA/EC/OpenSSH).",
        "Inspeção estrutural (tipo de chave), sem uso da chave.",
    ),

    # ------------------------------ Genérico ------------------------------ #
    SecretType(
        "generic_assignment", "Atribuição de segredo (alta entropia)", "—", "generic", "medium",
        re.compile(
            r"(?i)(?P<pre>(?:api[_-]?key|secret|token|password|passwd|pwd|auth[_-]?token"
            r"|access[_-]?key|client[_-]?secret)['\"]?\s*[:=]\s*['\"]?)"
            r"(?P<val>[A-Za-z0-9_\-+/=]{16,})"
        ),
        "Valor de alta entropia atribuído a variável de segredo (api_key=, password=...).",
        "Filtrado por entropia >= 3.5 e termos placeholder.",
    ),
    SecretType(
        "jwt", "JSON Web Token (JWT)", "—", "generic", "medium",
        re.compile(r"\b(eyJ[A-Za-z0-9_\-]{6,}\.eyJ[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,})\b"),
        "JWT assinado — pode expor claims e permitir replay se a assinatura for fraca.",
        "Decodificar payload (base64) para inspeção; não é 'chave' em si.",
    ),
]


# --------------------------------------------------------------------------- #
# Índices auxiliares
# --------------------------------------------------------------------------- #
TYPES_BY_ID: dict[str, SecretType] = {t.type_id: t for t in SECRET_TYPES}

# Identifica a versão efetiva dos detectores. Entra nas chaves idempotentes para
# que uma alteração de regex permita reprocessar blobs/histórico antigos.
PATTERN_SET_ID = hashlib.sha256(
    "\n".join(
        f"{item.type_id}:{item.regex.pattern if item.regex is not None else 'structural'}:{item.revision}"
        for item in SECRET_TYPES
    ).encode("utf-8")
).hexdigest()[:12]

RISK_WEIGHT = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def is_placeholder(value: str) -> bool:
    """Heurística para descartar valores obviamente fake/placeholder."""
    low = value.lower()
    if low in ("true", "false", "null", "none", "undefined"):
        return True
    return any(term in low for term in _PLACEHOLDER_TERMS)


def plausible_evm_key(hexkey: str) -> bool:
    """Checa se um 0x+64hex é plausível como chave privada secp256k1.

    Descarta hashes/txids óbvios: todos iguais, entropia baixa, ou fora do
    intervalo válido (0 < k < n, ordem da curva secp256k1).
    """
    raw = hexkey[2:] if hexkey.lower().startswith("0x") else hexkey
    if len(raw) != 64:
        return False
    if len(set(raw)) <= 4:  # "aaaa...", "0000..." etc.
        return False
    try:
        k = int(raw, 16)
    except ValueError:
        return False
    n = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
    return 0 < k < n and shannon_entropy(raw) >= 2.5


def plausible_bitcoin_wif(value: str) -> bool:
    """Valida versão, tamanho e checksum Base58Check sem derivar a pubkey."""
    try:
        number = 0
        for char in value:
            number = number * 58 + _BASE58_ALPHABET.index(char)
        decoded = number.to_bytes((number.bit_length() + 7) // 8, "big")
        decoded = b"\x00" * (len(value) - len(value.lstrip("1"))) + decoded
    except (ValueError, OverflowError):
        return False
    if len(decoded) not in (37, 38):
        return False
    body, checksum = decoded[:-4], decoded[-4:]
    if body[0] not in (0x80, 0xEF):
        return False
    if len(body) == 34 and body[-1] != 0x01:
        return False
    expected = hashlib.sha256(hashlib.sha256(body).digest()).digest()[:4]
    difference = 0
    for left, right in zip(checksum, expected):
        difference |= left ^ right
    return difference == 0
