"""secret_hunter — descoberta defensiva de segredos vazados no GitHub.

Objetivo: localizar segredos expostos e NOTIFICAR os donos dos repositórios,
nunca explorá-los. Nenhum segredo bruto é armazenado — apenas fingerprints
hash (HMAC-SHA256) e versões redigidas (ex.: sk_live_...a1b2).
"""

__version__ = "0.4.0"
__all__ = ["__version__"]
