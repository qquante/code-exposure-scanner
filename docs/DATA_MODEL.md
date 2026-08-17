# Modelo de dados e linhagem dos campos

O PostgreSQL é a fonte de verdade. Nenhuma tabela possui coluna para segredo bruto.

## `repositories`

| Campo | Origem/normalização | Consumidor |
|---|---|---|
| `host` | fixo `github.com` | auditoria e futura expansão |
| `owner`, `name`, `full_name` | URL/resultado GitHub, validado como `owner/repo` | joins, API e notificação |
| `html_url` | reconstruída de `full_name` | painel/admin |
| `is_public` | default atual `true` | política futura |
| `first_seen`, `last_seen` | PostgreSQL | recência |

## `findings`

| Campo | Origem/normalização | Consumidor |
|---|---|---|
| `fingerprint` | HMAC-SHA256 de `type_id + segredo`, em memória | deduplicação sem raw |
| `fingerprint_key_id` | hash curto da chave HMAC, nunca da credencial | detectar troca de chave |
| `type_id` | catálogo em `patterns.py` | validação, filtros e draft |
| `platform` | detector: Stripe, AWS, MongoDB, EVM, Solana etc. | filtros/API |
| `category` | `payment`, `cloud`, `database`, `crypto`, `vcs`, `ai`, `messaging`, `generic` | risco e mensagem |
| `environment` | derivado do tipo: `live`, `test`, `temporary`, `unknown` | priorização |
| `risk` | detector: `critical`, `high`, `medium`, `low` | ordenação |
| `confidence` | tipo específico=`high`; heurístico/cripto ambíguo=`medium` | revisão humana |
| `secret_hint` | texto fixo por tipo, sem sufixo do segredo | identificação segura |
| `validation_status` | `not_checked`, `format_valid`, `provider_active`, `provider_inactive`, `unknown` | revisão/draft |
| `status` | `open`, `notified`, `resolved`, `false_positive`, `accepted_risk` | workflow |
| `first_seen`, `last_seen` | PostgreSQL/upsert | recência |

`fingerprint` é correlacionável dentro desta instalação; por isso a chave HMAC é um Docker Secret. Trocar essa chave altera a identidade dos achados.

## `finding_locations`

| Campo | Origem | Observação |
|---|---|---|
| `source_kind` | `code`, `history` ou `trufflehog` | separa código atual/histórico |
| `path` | Code Search, diff Git ou metadata TruffleHog | só aparece no admin/relatório privado |
| `branch` | scanner, quando conhecido | pode ser vazio |
| `commit_sha` | histórico/TruffleHog | prova de persistência |
| `blob_sha` | item imutável do Code Search | evita corrida com branch mutável |
| `line_start`, `line_end` | regex/metadata | zero quando desconhecida |
| `first_seen`, `last_seen` | PostgreSQL | recência da localização |

Um mesmo segredo pode ter várias localizações sem duplicar o achado.

## `scan_runs` e `scan_jobs`

`scan_runs` registra modo, escopo, estado, quantidade de jobs/achados/erros e tempos. `scan_jobs` contém `kind`, chave natural idempotente, payload sem raw secret, prioridade, estado, tentativas, lease, owner, erro e timestamps.

A chave natural contém o hash da versão dos detectores. Assim, workers duplicados não repetem o mesmo trabalho, mas uma mudança de regex permite reprocessamento.

## `notification_outbox` e `notification_findings`

A outbox guarda título, draft privado, texto público genérico, status, aprovação, URL externa e erros. `notification_findings` relaciona todos os achados agregados. Há no máximo um draft ativo por repositório/canal; após envio, um achado novo cria outro lote.

Estados: `pending_review → approved → sending → sent`. Falhas terminam em `failed` ou `needs_contact`; `rejected` permanece estável até `requeue`, que o devolve à revisão. A recuperação é manual porque a API externa não oferece garantia transacional exatamente-uma-vez.

## `rate_limit_buckets` e `audit_events`

Buckets separados serializam Code Search e Repository Search entre todos os
containers. A auditoria registra ator, ação, entidade e metadata sem segredo.

## `discovery_checkpoints`, `discovery_windows` e `discovery_candidates`

`discovery_checkpoints` guarda o maior repository ID observado como head informativo,
próxima consulta, lease e erro; os campos de ETag/lacuna são preservados para
compatibilidade com o coletor legado. A deduplicação efetiva usa o repository ID
único em `discovery_candidates`, que guarda somente metadados do repositório,

`discovery_windows` é o ledger UTC das janelas de criação. Guarda início/fim,
passagem inicial, reconciliação, próxima tentativa, erro e contadores de requests.
O índice de janelas pendentes ordena por `window_end DESC`, fazendo o head
ultrapassar qualquer backlog. Janelas além do teto de 48h são removidas sem tocar
nos candidatos já persistidos.
resultado dos filtros e a trilha auditável.

O estado percorre `pending_metadata → pending_review → scan_queued`; alternativas
terminais são `filtered`, `unavailable` e `rejected`. A transição para
`scan_queued` cria run/job na mesma transação. No modo manual exige
`authorization_reference`; no automático registra `candidate.scan_auto_queued`.
