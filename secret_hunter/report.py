"""Geração do template de alerta (Issue) para divulgação responsável.

O texto é educado e claro sobre: o que vazou, o risco real, a persistência
no histórico e a remediação. NUNCA inclui o segredo bruto — apenas a versão
redigida e o contexto (que já vem redigido da extração).
"""

from __future__ import annotations

_RISK_TEXT = {
    "critical": "🔴 **Crítico** — a credencial ainda pode estar ativa e dá acesso direto.",
    "high": "🟠 **Alto** — exposição significativa; requer ação imediata.",
    "medium": "🟡 **Médio** — risco moderado; vale revisar.",
    "low": "⚪ **Baixo** — provavelmente inofensivo (ex.: chave de teste), mas convém limpar.",
}

_CATEGORY_RISK = {
    "payment": "possibilita a **terceiros acessarem transações, valores e dados pessoais "
               "(como nome, e-mail e CPF) de clientes**, além de realizar/estornar cobranças.",
    "database": "permite que **estranhos acessem o banco de dados**, visualizem receitas e "
                "dados de usuários (nomes, e-mails, CPFs) e **assumam controle administrativo** do sistema.",
    "crypto": "dá **controle total sobre os fundos on-chain** da carteira — qualquer um com a chave "
              "pode transferir todos os ativos de forma irreversível.",
    "cloud": "pode gerar **custos financeiros** e dar acesso a serviços/recursos da sua conta na nuvem.",
    "vcs": "dá **acesso aos seus repositórios e código-fonte**, permitindo alteração, vazamento e "
           "injeção de código malicioso.",
    "ai": "pode ser usada para **gerar custos na sua conta** e acessar recursos pagos.",
    "messaging": "permite **atuar em nome do bot/usuário** no workspace (ler e enviar mensagens).",
    "generic": "pode permitir acesso indevido a sistemas que usam essa credencial.",
}

_INTRO = (
    "Olá! 👋\n\n"
    "Durante uma **varredura de segurança defensiva** (não intrusiva) em repositórios públicos, "
    "identifiquei o que parece ser uma **credencial/senha exposta** no seu repositório. "
    "Estou abrindo esta issue apenas para **avisar você** — não utilizei nem vou utilizar o valor "
    "encontrado.\n\n"
)

_REMEDIATION = (
    "## ✅ O que recomendamos\n\n"
    "1. **Revogue (rotacione) a credencial imediatamente** no painel do provedor — apenas apagar "
    "   do código **não resolve**, porque o valor continua visível no histórico de commits.\n"
    "2. **Gere uma nova chave** e armazene-a fora do código (variáveis de ambiente, cofre de "
    "   segredos, `.env` local).\n"
    "3. **Adicione o arquivo ao `.gitignore`** (ex.: `.env`, `*.json` com segredos, `secrets.*`).\n"
    "4. Se o segredo já foi usado indevidamente, **audite os logs** do provedor.\n"
    "5. Para limpar o histórico, considere ferramentas como **`git filter-repo`** ou **BFG** "
    "   (lembrando que isso reescreve o histórico e força novos clones).\n\n"
    "> Ferramentas usadas na detecção: GitHub Code Search, expressões regulares e lógica similar "
    "ao TruffleHog (varredura de histórico).\n"
)

_OUTRO = (
    "Fico à disposição para ajudar com os passos de revogação ou para indicar ferramentas de "
    "prevenção (pre-commit hooks, gitleaks em CI, GitHub Secret Scanning). "
    "Se preferir, posso fornecer detalhes adicionais por e-mail.\n\n"
    "Obrigado por manter a comunidade segura! 🔐\n"
)


def _fmt_finding(f: dict) -> str:
    lines = [
        f"- **Tipo:** {f.get('provider', '?')} ({f.get('type_id', '?')}) — {_RISK_TEXT.get(f.get('risk'), '')}",
        f"  - Arquivo: `{f.get('path') or '(histórico)'}`",
    ]
    commit_sha = f.get("commit_sha") or f.get("commit")
    if commit_sha:
        lines.append(f"  - Commit: `{commit_sha[:10]}`")
    validation_status = f.get("validation_status") or f.get("validate_status")
    if validation_status in ("provider_active", "provider_inactive"):
        lines.append(f"  - Status verificado: **{validation_status}**")
    if f.get("context"):
        lines.append(f"  - Contexto: `{f['context']}`")
    return "\n".join(lines)


def build_issue_title() -> str:
    return "[Segurança] Possível credencial exposta no repositório"


def build_issue_body(findings: list[dict], *, visibility: str = "private") -> str:
    """Monta o corpo da Issue para um conjunto de findings do mesmo repositório."""
    if not findings:
        return ""
    if visibility == "public":
        return (
            "Olá! Durante uma varredura defensiva em código público, identifiquei "
            "uma possível credencial exposta relacionada a este repositório.\n\n"
            "Para não ampliar a exposição, não publicarei tipo, arquivo, commit nem "
            "qualquer fragmento aqui. Poderiam indicar um **canal privado** em "
            "`SECURITY.md` ou habilitar o *Private vulnerability reporting* do GitHub?\n\n"
            "A recomendação imediata é revisar alertas de secret scanning e rotacionar "
            "qualquer credencial confirmada. Obrigado."
        )
    if visibility != "private":
        raise ValueError("visibility deve ser 'private' ou 'public'")
    repo = findings[0].get("repo", "")
    cats = sorted({f.get("category", "generic") for f in findings})
    risks = sorted({f.get("risk", "low") for f in findings}, key=lambda r: ["critical", "high", "medium", "low"].index(r))
    top_risk = risks[0]

    parts = [_INTRO]
    parts.append(f"## 🔍 O que encontrei\n\n**Repositório:** `{repo}`\n\n")
    parts.append("\n".join(_fmt_finding(f) for f in findings))
    parts.append("\n\n## ⚠️ Por que isso importa\n\n")
    for cat in cats:
        parts.append(f"- {_CATEGORY_RISK.get(cat, _CATEGORY_RISK['generic'])}\n")
    parts.append(f"\n{_RISK_TEXT.get(top_risk, '')}\n\n")
    parts.append("## 🧭 Sobre a persistência no histórico\n\n"
                 "Mesmo que a linha seja removida do código atual, o valor continua visível no "
                 "**histórico de commits** (qualquer pessoa pode consultar commits antigos). "
                 "Por isso a **rotação da chave no provedor** é o passo essencial — ela invalida "
                 "a cópia vazada independentemente do histórico.\n\n")
    parts.append(_REMEDIATION)
    parts.append(_OUTRO)
    return "".join(parts)
