from __future__ import annotations

from types import SimpleNamespace

import pytest

from secret_hunter.ai_detection.catalog import AI_SECRET_SPECS, AI_SECRET_TYPE_IDS
from secret_hunter.ai_detection.scanner import extract_ai_tokens
from secret_hunter.github_search import SEARCH_QUERIES
from secret_hunter.scan_policy import filter_automatic_findings


def _material(length: int) -> str:
    return ("A7b9C2d4E6f8G1h3J5k7L9m2N4p6Q8r1S3t5U7v9W2x4Y6z8")[:length]


@pytest.mark.parametrize(
    ("type_id", "variable", "token"),
    (
        ("openai_proj", "OPENAI_API_KEY", "sk-proj-" + _material(48)),
        ("openai_service", "OPENAI_API_KEY", "sk-svcacct-" + _material(48)),
        ("openai_legacy", "OPENAI_API_KEY", "sk-" + _material(48)),
        ("anthropic_api_key", "ANTHROPIC_API_KEY", "sk-ant-api03-" + _material(64)),
        ("google_api_key", "GEMINI_API_KEY", "AIza" + _material(35)),
        ("openrouter_api_key", "OPENROUTER_API_KEY", "sk-or-v1-" + "a1" * 32),
        ("groq_api_key", "GROQ_API_KEY", "gsk_" + _material(48)),
        ("huggingface", "HF_TOKEN", "hf_" + _material(40)),
        ("replicate_api_token", "REPLICATE_API_TOKEN", "r8_" + _material(37)),
        ("perplexity_api_key", "PERPLEXITY_API_KEY", "pplx-" + _material(40)),
        ("xai_api_key", "XAI_API_KEY", "xai-" + _material(64)),
        ("fireworks_api_key", "FIREWORKS_API_KEY", "fw_" + _material(40)),
        ("nvidia_api_key", "NVIDIA_API_KEY", "nvapi-" + _material(40)),
        ("tavily_api_key", "TAVILY_API_KEY", "tvly-" + _material(40)),
        ("langsmith_api_key", "LANGSMITH_API_KEY", "lsv2_pt_" + _material(40)),
    ),
)
def test_documented_prefixes_are_detected(type_id: str, variable: str, token: str) -> None:
    findings = extract_ai_tokens(f'{variable}="{token}"', path=".env")

    assert type_id in {finding.type_id for finding in findings}
    assert all(finding.category == "ai" for finding in findings)
    assert all(finding.secret_raw == token for finding in findings)
    assert all(token not in finding.context for finding in findings)


@pytest.mark.parametrize(
    ("type_id", "variable"),
    (
        ("deepseek_api_key_context", "DEEPSEEK_API_KEY"),
        ("mistral_api_key_context", "MISTRAL_API_KEY"),
        ("cohere_api_key_context", "COHERE_API_KEY"),
        ("together_api_key_context", "TOGETHER_API_KEY"),
        ("cerebras_api_key_context", "CEREBRAS_API_KEY"),
        ("azure_openai_api_key_context", "AZURE_OPENAI_API_KEY"),
        ("ai21_api_key_context", "AI21_API_KEY"),
        ("voyage_api_key_context", "VOYAGE_API_KEY"),
        ("stability_api_key_context", "STABILITY_API_KEY"),
        ("elevenlabs_api_key_context", "ELEVENLABS_API_KEY"),
        ("assemblyai_api_key_context", "ASSEMBLYAI_API_KEY"),
        ("pinecone_api_key_context", "PINECONE_API_KEY"),
    ),
)
def test_opaque_provider_keys_require_official_variable_context(
    type_id: str, variable: str
) -> None:
    token = _material(48)

    without_context = extract_ai_tokens(f'checksum="{token}"', path="config.yml")
    with_context = extract_ai_tokens(f'{variable}: "{token}"', path="config.yml")

    assert type_id not in {finding.type_id for finding in without_context}
    assert type_id in {finding.type_id for finding in with_context}


def test_contextual_placeholders_and_dependency_paths_are_rejected() -> None:
    placeholder = "your_api_key_here_replace_me_now"
    assert extract_ai_tokens(f"MISTRAL_API_KEY={placeholder}", path=".env") == []

    token = "sk-or-v1-" + "a1" * 32
    assert extract_ai_tokens(
        f"OPENROUTER_API_KEY={token}", path="node_modules/sdk/README.md"
    ) == []


def test_catalog_covers_major_llm_and_ai_operators() -> None:
    providers = {spec.provider for spec in AI_SECRET_SPECS}
    assert {
        "OpenAI",
        "Anthropic Claude",
        "Google Gemini",
        "OpenRouter",
        "Groq",
        "Cerebras",
        "Mistral AI",
        "Cohere",
        "Together AI",
        "Hugging Face",
        "Replicate",
        "Perplexity",
        "xAI",
        "Fireworks AI",
        "NVIDIA NIM",
        "DeepSeek",
    } <= providers
    assert len(providers) >= 20


def test_all_ai_detectors_have_a_complementary_code_search_query() -> None:
    assert AI_SECRET_TYPE_IDS <= SEARCH_QUERIES.keys()


def test_automatic_pipeline_accepts_crypto_and_ai_but_not_unrelated_secrets() -> None:
    findings = [
        SimpleNamespace(type_id="evm_private_key", path="src/wallet.ts"),
        SimpleNamespace(type_id="openrouter_api_key", path=".env"),
        SimpleNamespace(type_id="mistral_api_key_context", path="config.yml"),
        SimpleNamespace(type_id="aws_akia", path=".env"),
    ]

    filtered = filter_automatic_findings(findings)

    assert [finding.type_id for finding in filtered] == [
        "evm_private_key",
        "openrouter_api_key",
        "mistral_api_key_context",
    ]
    assert "openrouter_api_key" in AI_SECRET_TYPE_IDS
