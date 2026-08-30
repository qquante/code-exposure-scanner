"""Padrões de tokens de IA baseados em prefixos e variáveis oficiais.

Prefixos documentados podem ser reconhecidos em qualquer contexto. Provedores
sem formato público estável são detectados somente junto da variável oficial,
com filtro de placeholder e entropia aplicado pelo extrator principal.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class AISecretSpec:
    type_id: str
    name: str
    provider: str
    risk: str
    pattern: str
    description: str
    detection_mode: str
    search_literal: str
    docs_url: str
    revision: str = "ai-v1"


def _assignment(*names: str, minimum: int = 20, maximum: int = 512) -> str:
    variables = "|".join(re.escape(name) for name in names)
    return (
        rf"(?im)(?:[\"']?(?:{variables})[\"']?)\s*[:=]\s*[\"']?"
        rf"([A-Za-z0-9_./+=-]{{{minimum},{maximum}}})[\"']?"
    )


_NO_ACTIVE_VALIDATION = (
    "Detecção passiva; não testar a chave. Confirmar propriedade e rotacionar no console."
)


AI_SECRET_SPECS: tuple[AISecretSpec, ...] = (
    # Formatos opacos ou compatíveis com OpenAI: contexto obrigatório.
    AISecretSpec(
        "deepseek_api_key_context", "DeepSeek API key", "DeepSeek", "high",
        _assignment("DEEPSEEK_API_KEY"),
        _NO_ACTIVE_VALIDATION, "context", '"DEEPSEEK_API_KEY"',
        "https://api-docs.deepseek.com/",
    ),
    AISecretSpec(
        "mistral_api_key_context", "Mistral API key", "Mistral AI", "high",
        _assignment("MISTRAL_API_KEY"),
        _NO_ACTIVE_VALIDATION, "context", '"MISTRAL_API_KEY"',
        "https://docs.mistral.ai/getting-started/quickstarts/developer/first-api-request",
    ),
    AISecretSpec(
        "cohere_api_key_context", "Cohere API key", "Cohere", "high",
        _assignment("COHERE_API_KEY"),
        _NO_ACTIVE_VALIDATION, "context", '"COHERE_API_KEY"',
        "https://docs.cohere.com/v2/docs/building-a-chatbot-with-cohere",
    ),
    AISecretSpec(
        "together_api_key_context", "Together AI API key", "Together AI", "high",
        _assignment("TOGETHER_API_KEY"),
        _NO_ACTIVE_VALIDATION, "context", '"TOGETHER_API_KEY"',
        "https://docs.together.ai/docs/api-keys-authentication",
    ),
    AISecretSpec(
        "cerebras_api_key_context", "Cerebras API key", "Cerebras", "high",
        _assignment("CEREBRAS_API_KEY"),
        _NO_ACTIVE_VALIDATION, "context", '"CEREBRAS_API_KEY"',
        "https://inference-docs.cerebras.ai/api-reference/authentication",
    ),
    AISecretSpec(
        "azure_openai_api_key_context", "Azure OpenAI API key", "Microsoft Azure OpenAI", "high",
        _assignment("AZURE_OPENAI_API_KEY", minimum=24, maximum=128),
        _NO_ACTIVE_VALIDATION, "context", '"AZURE_OPENAI_API_KEY"',
        "https://learn.microsoft.com/azure/ai-foundry/openai/how-to/switching-endpoints",
    ),
    AISecretSpec(
        "ai21_api_key_context", "AI21 API key", "AI21 Labs", "high",
        _assignment("AI21_API_KEY"),
        _NO_ACTIVE_VALIDATION, "context", '"AI21_API_KEY"',
        "https://docs.ai21.com/docs/quickstart",
    ),
    AISecretSpec(
        "voyage_api_key_context", "Voyage AI API key", "Voyage AI", "high",
        _assignment("VOYAGE_API_KEY"),
        _NO_ACTIVE_VALIDATION, "context", '"VOYAGE_API_KEY"',
        "https://docs.voyageai.com/docs/api-key-and-installation",
    ),
    AISecretSpec(
        "stability_api_key_context", "Stability AI API key", "Stability AI", "high",
        _assignment("STABILITY_API_KEY"),
        _NO_ACTIVE_VALIDATION, "context", '"STABILITY_API_KEY"',
        "https://platform.stability.ai/docs/getting-started/authentication",
    ),
    AISecretSpec(
        "elevenlabs_api_key_context", "ElevenLabs API key", "ElevenLabs", "high",
        _assignment("ELEVENLABS_API_KEY", "XI_API_KEY"),
        _NO_ACTIVE_VALIDATION, "context", '"ELEVENLABS_API_KEY"',
        "https://elevenlabs.io/docs/api-reference/authentication",
    ),
    AISecretSpec(
        "assemblyai_api_key_context", "AssemblyAI API key", "AssemblyAI", "high",
        _assignment("ASSEMBLYAI_API_KEY"),
        _NO_ACTIVE_VALIDATION, "context", '"ASSEMBLYAI_API_KEY"',
        "https://www.assemblyai.com/docs/getting-started/transcribe-an-audio-file",
    ),
    AISecretSpec(
        "pinecone_api_key_context", "Pinecone API key", "Pinecone", "high",
        _assignment("PINECONE_API_KEY"),
        _NO_ACTIVE_VALIDATION, "context", '"PINECONE_API_KEY"',
        "https://docs.pinecone.io/guides/get-started/quickstart",
    ),
    # Prefixos publicados ou demonstrados pelo próprio provedor.
    AISecretSpec(
        "openai_proj", "OpenAI project API key", "OpenAI", "high",
        r"\b(sk-proj-[A-Za-z0-9_-]{20,})\b",
        _NO_ACTIVE_VALIDATION, "prefix", '"sk-proj-"',
        "https://platform.openai.com/docs/api-reference/authentication",
    ),
    AISecretSpec(
        "openai_service", "OpenAI service-account key", "OpenAI", "high",
        r"\b(sk-svcacct-[A-Za-z0-9_-]{20,})\b",
        _NO_ACTIVE_VALIDATION, "prefix", '"sk-svcacct-"',
        "https://platform.openai.com/docs/api-reference/authentication",
    ),
    AISecretSpec(
        "openai_legacy", "OpenAI-compatible legacy key", "OpenAI-compatible", "high",
        r"\b(sk-[A-Za-z0-9]{48})\b",
        "Formato legado ambíguo; atribuir ao provedor somente com contexto. " + _NO_ACTIVE_VALIDATION,
        "prefix", '"OPENAI_API_KEY"',
        "https://platform.openai.com/docs/api-reference/authentication",
    ),
    AISecretSpec(
        "anthropic_api_key", "Anthropic API/auth token", "Anthropic Claude", "high",
        r"\b(sk-ant-[A-Za-z0-9_-]{20,})\b",
        _NO_ACTIVE_VALIDATION, "prefix", '"sk-ant-"',
        "https://platform.claude.com/docs/en/api/overview",
    ),
    AISecretSpec(
        "google_api_key", "Google/Gemini API key", "Google Gemini", "high",
        r"\b(AIza[0-9A-Za-z_-]{35})\b",
        "Pode pertencer ao Gemini ou a outra API Google. " + _NO_ACTIVE_VALIDATION,
        "prefix", '"AIza"',
        "https://ai.google.dev/gemini-api/docs/api-key",
    ),
    AISecretSpec(
        "openrouter_api_key", "OpenRouter API key", "OpenRouter", "high",
        r"\b(sk-or-v1-[0-9A-Fa-f]{64})\b",
        _NO_ACTIVE_VALIDATION, "prefix", '"sk-or-v1-"',
        "https://openrouter.ai/docs/api/api-reference/api-keys/create-keys",
    ),
    AISecretSpec(
        "groq_api_key", "Groq API key", "Groq", "high",
        r"\b(gsk_[A-Za-z0-9]{20,128})\b",
        _NO_ACTIVE_VALIDATION, "prefix", '"gsk_"',
        "https://console.groq.com/docs/production-readiness/security-onboarding",
    ),
    AISecretSpec(
        "huggingface", "Hugging Face access token", "Hugging Face", "high",
        r"\b(hf_[A-Za-z0-9]{20,})\b",
        _NO_ACTIVE_VALIDATION, "prefix", '"hf_"',
        "https://huggingface.co/docs/hub/en/security-tokens",
    ),
    AISecretSpec(
        "replicate_api_token", "Replicate API token", "Replicate", "high",
        r"\b(r8_[A-Za-z0-9]{37})\b",
        _NO_ACTIVE_VALIDATION, "prefix", '"r8_"',
        "https://replicate.com/docs/topics/security/api-tokens/",
    ),
    AISecretSpec(
        "perplexity_api_key", "Perplexity API key", "Perplexity", "high",
        r"\b(pplx-[A-Za-z0-9_-]{20,128})\b",
        _NO_ACTIVE_VALIDATION, "prefix", '"pplx-"',
        "https://docs.perplexity.ai/docs/getting-started/quickstart",
    ),
    AISecretSpec(
        "xai_api_key", "xAI API key", "xAI", "high",
        r"\b(xai-[A-Za-z0-9]{20,128})\b",
        _NO_ACTIVE_VALIDATION, "prefix", '"xai-"',
        "https://docs.x.ai/developers/rest-api-reference/management/auth",
    ),
    AISecretSpec(
        "fireworks_api_key", "Fireworks AI API key", "Fireworks AI", "high",
        r"\b(fw_[A-Za-z0-9]{20,128})\b",
        _NO_ACTIVE_VALIDATION, "prefix", '"fw_"',
        "https://docs.fireworks.ai/getting-started/quickstart",
    ),
    AISecretSpec(
        "nvidia_api_key", "NVIDIA hosted NIM API key", "NVIDIA NIM", "high",
        r"\b(nvapi-[A-Za-z0-9_-]{20,128})\b",
        _NO_ACTIVE_VALIDATION, "prefix", '"nvapi-"',
        "https://docs.nvidia.com/nemo/retriever/latest/extraction/api-keys/",
    ),
    AISecretSpec(
        "tavily_api_key", "Tavily API key", "Tavily", "high",
        r"\b(tvly-[A-Za-z0-9_-]{20,128})\b",
        _NO_ACTIVE_VALIDATION, "prefix", '"tvly-"',
        "https://docs.tavily.com/documentation/quickstart",
    ),
    AISecretSpec(
        "langsmith_api_key", "LangSmith API key", "LangSmith", "high",
        r"\b(lsv2_(?:pt|sk)_[A-Za-z0-9_-]{20,})\b",
        _NO_ACTIVE_VALIDATION, "prefix", '"lsv2_"',
        "https://docs.langchain.com/langsmith/create-account-api-key",
    ),
)


AI_SECRET_TYPE_IDS = frozenset(spec.type_id for spec in AI_SECRET_SPECS)
AI_CONTEXT_TYPE_IDS = frozenset(
    spec.type_id for spec in AI_SECRET_SPECS if spec.detection_mode == "context"
)
AI_SEARCH_QUERIES = {
    spec.type_id: spec.search_literal for spec in AI_SECRET_SPECS if spec.search_literal
}
