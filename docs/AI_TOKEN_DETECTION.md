# Detecção defensiva de tokens de IA

O pipeline reconhece credenciais de operadores de IA em código autorizado sem
chamar a API do provedor. O objetivo é apontar exposição e preservar evidência
redigida; validade, saldo, conta, modelos e permissões não são inferidos.

As chaves são emitidas pelo operador/projeto, não por cada modelo. Uma mesma
`OPENAI_API_KEY`, por exemplo, pode autorizar vários modelos conforme as permissões
da conta; portanto, enumerar nomes de modelos não cria novos formatos de chave.

## Cobertura

| Operador | Modo | Sinal principal |
|---|---|---|
| OpenAI | prefixo | `sk-proj-`, `sk-svcacct-` e formato legado compatível |
| Anthropic Claude | prefixo | `sk-ant-` |
| Google Gemini | prefixo | `AIza` (também pode pertencer a outra API Google) |
| OpenRouter | prefixo | `sk-or-v1-` |
| Groq | prefixo | `gsk_` |
| Hugging Face | prefixo | `hf_` |
| Replicate | prefixo | `r8_` com comprimento documentado |
| Perplexity | prefixo | `pplx-` |
| xAI | prefixo | `xai-` |
| Fireworks AI | prefixo | `fw_` |
| NVIDIA NIM | prefixo | `nvapi-` |
| Tavily | prefixo | `tvly-` |
| LangSmith | prefixo | `lsv2_pt_` ou `lsv2_sk_` |
| DeepSeek | contexto | `DEEPSEEK_API_KEY` |
| Mistral AI | contexto | `MISTRAL_API_KEY` |
| Cohere | contexto | `COHERE_API_KEY` |
| Together AI | contexto | `TOGETHER_API_KEY` |
| Cerebras | contexto | `CEREBRAS_API_KEY` |
| Azure OpenAI | contexto | `AZURE_OPENAI_API_KEY` |
| AI21 Labs | contexto | `AI21_API_KEY` |
| Voyage AI | contexto | `VOYAGE_API_KEY` |
| Stability AI | contexto | `STABILITY_API_KEY` |
| ElevenLabs | contexto | `ELEVENLABS_API_KEY` ou `XI_API_KEY` |
| AssemblyAI | contexto | `ASSEMBLYAI_API_KEY` |
| Pinecone | contexto | `PINECONE_API_KEY` |

`prefixo` significa que o formato é suficientemente característico para ser
detectado em qualquer arquivo. `contexto` significa que o provedor publica uma
variável de ambiente, mas não promete formato estável; o valor só é aceito ao
lado desse nome, com filtro de placeholder e entropia.

## Fluxo automático

```text
Repository Search (janelas recentes, novo primeiro)
  -> candidato PostgreSQL
  -> Redis metadata-live/backfill
  -> filtros de metadados
  -> Redis head-live/backfill
  -> clone raso e priorização de .env/key/token/auth/provider
  -> extrator IA (private keys somente quando a flag estiver ligada)
  -> exclusão de node_modules, lockfiles e dependências vendorizadas
  -> filtro de placeholder/entropia e deduplicação
  -> HMAC/fingerprint + hint redigido no PostgreSQL
  -> evidência bruta opcional no Redis autenticado
  -> dashboard em até o próximo pulso
  -> draft privado sujeito a aprovação humana
```

O perfil operacional atual usa:

```dotenv
AI_DETECTION_ENABLED=true
PRIVATE_KEY_DETECTION_ENABLED=false
SCAN_HISTORY=false
```

Trocar `PRIVATE_KEY_DETECTION_ENABLED` para `true` religa EVM, Solana e BIP39.
Não há terceira configuração nem alteração de código. Jobs fora de
`DISCOVERY_MAX_EVENT_AGE_HOURS` recebem estado `expired`; achados já persistidos
continuam no `Arquivo` para preservar a prova acadêmica. A janela usa
`created_at` do próprio repositório no GitHub, não o horário em que o achado foi
gravado localmente.

O GitHub Code Search é um caminho complementar e limitado por quota. Ele só usa
os IDs de `SEARCH_TYPES` dentro de `SEARCH_SCOPE`; busca global não é necessária
para o fluxo de descoberta recente.

O dashboard expõe `/#ai-providers`, uma visão agrupada por operador com os modos
de detecção, sinais pesquisados, documentação oficial e acesso aos achados.
“Recente” nessa tela significa publicação em repositório criado dentro do teto
configurado; não é possível inferir a data em que o provedor emitiu a chave.

## Limites

- Não existe regex que cubra literalmente todas as chaves: formatos podem mudar.
- Prefixos curtos e formatos opacos exigem contexto para evitar falsos positivos.
- Valores em exemplos, placeholders, dependências e lockfiles são descartados.
- O detector não testa credenciais, não consulta saldo e não executa modelos.
- Um match indica exposição provável, não prova que a chave ainda está ativa.
- O catálogo deve ser revisado quando a documentação oficial dos provedores mudar.
