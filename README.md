# Secret Hunter

Pipeline defensivo para localizar segredos em código público do GitHub e preparar divulgação responsável. O deploy distribuído usa PostgreSQL como banco, fila, controle de concorrência e outbox; um Redis separado preserva as respostas brutas usadas como evidência acadêmica.

> Use somente em repositórios próprios, escopos autorizados ou divulgação responsável. Validação ativa de credenciais de terceiros fica desabilitada. O PostgreSQL nunca recebe o segredo bruto e o serviço nunca publica detalhes sensíveis em Issue pública. Quando habilitado, o Redis de evidências guarda a resposta bruta e deve ser tratado como material altamente sensível.

## O que está implementado

- GitHub `search/code` com escopo obrigatório `org:`, `user:` ou `repo:`; busca global exige opt-in explícito.
- Extração em camadas: regex, contexto e validação estrutural para pagamentos, cloud, bancos, VCS, IA e mensageria; EVM/Solana incluem hex, arrays, Base58, Base64, BIP39 e keystore criptografado.
- Fetch por SHA de blob imutável para evitar corrida entre busca e alteração do arquivo.
- Histórico completo por Git nativo e TruffleHog 3.96.0 com verificação externa desabilitada.
- PostgreSQL com jobs idempotentes, leases, heartbeat, `FOR UPDATE SKIP LOCKED`, retry com backoff e limitador de Code Search compartilhado entre containers.
- Redis Streams autenticado e persistente para respostas REST brutas do GitHub, sem porta publicada, TTL ou trimming automático.
- Um draft ativo por repositório, agregando achados sem duplicar alertas.
- Aprovação humana obrigatória. O worker prefere Private Vulnerability Reporting; Issue pública genérica é desabilitada por padrão.
- API administrativa autenticada que lista catálogo, achados, localizações, runs, jobs e drafts. Nenhuma resposta contém segredo bruto.
- Drop-zone modular read-only com adapters `tree` e `manifest`, SHA-256 contra
  corrida de arquivo e workers exclusivos de ingestão.

- Descoberta global head-first via Repository Search: janelas fechadas de 60s,
  divisão adaptativa sob o teto de 1.000, reconciliação, deduplicação, lease e
  fila auditada; 48h é somente o limite de recuperação.

O SQLite permanece apenas como modo local/legado de processo único. Não o use com vários workers.

## PostgreSQL e Redis têm papéis separados

PostgreSQL permanece como fonte de verdade transacional para deduplicação, jobs, achados, drafts e auditoria. O Redis não participa da fila nem decide estado operacional: ele apenas anexa as respostas brutas do GitHub para o corpus probatório do TCC.

## Subir localmente com Docker

Pré-requisitos: Docker Desktop com Compose e PowerShell.

1. Crie dois PATs independentes: um somente de leitura para busca e outro para
notificação privada. O passo a passo e as permissões mínimas estão em
[docs/TOKENS_AND_ENV.md](docs/TOKENS_AND_ENV.md). Gere os arquivos locais; sem
parâmetros, o script pede os dois tokens de forma oculta:

```powershell
.\scripts\init-secrets.ps1
```

Também é possível ler os tokens de arquivos temporários sem colocá-los no
histórico do shell:

```powershell
.\scripts\init-secrets.ps1 `
  -GitHubSearchTokenFile C:\caminho\github-search-token.txt `
  -GitHubNotifyTokenFile C:\caminho\github-notify-token.txt
```

2. Suba somente PostgreSQL, migração e API. Isso não inicia busca nem notificação:

```powershell
docker compose up -d --build api
docker compose ps
```

A API fica somente em `127.0.0.1:8000`. Teste:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/health
$adminToken = (Get-Content .\.secrets\admin_api_token.txt -Raw).Trim()
$headers = @{ Authorization = "Bearer $adminToken" }
Invoke-RestMethod http://127.0.0.1:8000/stats -Headers $headers
Invoke-RestMethod http://127.0.0.1:8000/detectors -Headers $headers
```

Abra o dashboard operacional no navegador:

```text
http://127.0.0.1:8000/
```

Ele solicita o conteúdo de `.secrets/admin_api_token.txt`. O token fica somente
na sessão da aba (`sessionStorage`), nunca em URL, cookie ou `localStorage`. O
dashboard cobre visão geral, candidatos, achados, notificações, jobs, execuções
e catálogo de detectores, além de ações auditadas de revisão e agendamento.

3. Para um repositório específico, enfileire o histórico e suba workers, sem scheduler global:

```powershell
$body = @{ repository = "owner/repo"; trufflehog = $true } | ConvertTo-Json
Invoke-RestMethod http://127.0.0.1:8000/jobs/repository -Method Post -Headers $headers -ContentType application/json -Body $body
docker compose --profile scanner up -d --scale worker=2 worker
```

4. Para busca recorrente, edite `SEARCH_SCOPE` no `.env` com um escopo estrito e
suba o perfil completo:

```powershell
docker compose --profile scanner up -d --scale worker=4 worker scheduler
```

Escopos aceitos: `org:nome`, `user:nome` ou `repo:owner/repo`. `ALLOW_GLOBAL_SEARCH=true` existe, mas não é recomendado.

Para descobrir e escanear automaticamente repositórios públicos recém-criados:

```powershell
docker compose --profile scanner --profile discovery up -d --build `
  --scale worker=2 --scale discovery-worker=2 `
  scheduler worker discovery-watcher discovery-worker
```

Com `DISCOVERY_AUTO_QUEUE_SCANS=true`, uma amostra determinística de 5% passa por
clone raso e limitado da árvore atual. Em paralelo, a Code Search roda a cada
hora somente para sete contextos cripto. Antes de baixar um blob, confirma via
metadados que o repositório foi criado nas últimas 48h. O histórico completo só é enfileirado
quando esse pré-scan encontra a categoria `crypto`; somente essa categoria é persistida no automático. Validação ativa permanece
desabilitada e sem wildcard em `AUTHORIZED_VALIDATION_REPOS`.

Use `DISCOVERY_AUTO_QUEUE_SCANS=false` para manter o modo manual via
`POST /candidates/{id}/authorize-scan`. Veja
[docs/GLOBAL_DISCOVERY.md](docs/GLOBAL_DISCOVERY.md).

5. Revise o detalhe privado e aprove manualmente:

```powershell
$drafts = Invoke-RestMethod http://127.0.0.1:8000/notifications -Headers $headers
$draftId = $drafts[0].id
Invoke-RestMethod "http://127.0.0.1:8000/notifications/$draftId" -Headers $headers
Invoke-RestMethod "http://127.0.0.1:8000/notifications/$draftId/approve" -Method Post -Headers $headers
```

6. Só depois da revisão, inicie o envio:

```powershell
docker compose --profile notifications up -d notification-worker
```

O envio tenta um relatório privado. Se o repositório não habilitou esse canal, o draft fica `needs_contact`; não abre Issue pública. Uma tentativa ambígua não é repetida automaticamente. Após conferir no GitHub que nada foi criado, o administrador pode usar `POST /notifications/{id}/requeue`.

## API administrativa

Todos, exceto `/health`, exigem `Authorization: Bearer <admin_api_token>`.

| Endpoint | Finalidade |
|---|---|
| `GET /detectors` | Todos os tipos, plataformas, categorias, riscos e modo de validação |
| `GET /findings` | Lista sanitizada e paginada |
| `GET /findings/{id}` | Todos os campos seguros e todas as localizações |
| `GET /runs` | Rodadas e contadores |
| `GET /jobs` | Fila, tentativas, leases e erros |
| `GET /candidates` | Candidatos globais e estado de revisão/filtro |
| `GET /candidates/{id}` | Metadados e trilha de autorização do candidato |
| `GET /notifications` | Fila de revisão sem corpos |
| `GET /notifications/{id}` | Draft privado/público e achados agregados |
| `POST /jobs/search` | Agenda uma rodada no escopo configurado |
| `POST /jobs/repository` | Agenda histórico de um repo GitHub |
| `POST /jobs/ingest` | Enumera arquivos entregues no drop-zone read-only |
| `POST /candidates/{id}/authorize-scan` | Registra autorização e agenda scan atomicamente |
| `POST /candidates/{id}/reject` | Rejeita candidato sem scan |
| `POST /notifications/{id}/approve` | Aprovação humana auditada |
| `POST /notifications/{id}/reject` | Rejeição humana auditada |
| `POST /notifications/{id}/requeue` | Recuperação manual após reconciliação externa |
| `GET /` | Dashboard administrativo local e responsivo |

Veja [docs/DATA_MODEL.md](docs/DATA_MODEL.md) para a origem e o consumo de cada
campo, [docs/FILE_INGESTION.md](docs/FILE_INGESTION.md) para conectar arquivos,
[docs/GLOBAL_DISCOVERY.md](docs/GLOBAL_DISCOVERY.md) para repositórios novos,
[docs/RAW_EVIDENCE_REDIS.md](docs/RAW_EVIDENCE_REDIS.md) para a preservação bruta no Redis,
[docs/TCC_CRYPTO_METHODOLOGY.md](docs/TCC_CRYPTO_METHODOLOGY.md) para o recorte
acadêmico EVM/Solana, [docs/TCC_CRYPTO_BENCHMARK.md](docs/TCC_CRYPTO_BENCHMARK.md)
para o corpus e métricas dos detectores, [docs/TOKENS_AND_ENV.md](docs/TOKENS_AND_ENV.md) para
credenciais/configuração e [docs/OPERATIONS.md](docs/OPERATIONS.md) para
operação/produção.

## Segurança e validação

- O segredo existe temporariamente em uma string Python, é usado para HMAC-SHA256 e a referência é removida. Python não garante zeroização física dessa memória.
- O PostgreSQL recebe apenas fingerprint HMAC, hint fixo do tipo e metadados. Não há prefixo+sufixo do segredo no deploy distribuído.
- A chave HMAC deve ser igual em todos os workers e não deve ser rotacionada sem uma migração planejada.
- Validação de API é opt-in e só funciona quando o repositório está em `SH_AUTHORIZED_VALIDATION_REPOS`. Ela faz uma chamada mínima de autenticação, não lê dados de negócio.
- No Compose, use `VALIDATE_SECRETS=true` e `AUTHORIZED_VALIDATION_REPOS=owner/repo[,owner/repo]`. Mantenha desabilitado fora de escopo formalmente autorizado.
- Validação cripto é apenas local: formato/checksum e derivação do endereço público. Não consulta saldo, não usa RPC, não assina e não transmite chave.
- Saldo zero nunca significa chave inválida.
- Apagar a linha ou reescrever o Git não revoga uma credencial. A correção essencial é rotacioná-la no provedor.

## Testes

```powershell
python scripts/benchmark_crypto_detectors.py
python -m pytest -q
docker compose --profile test run --rm --build test
```

Os testes PostgreSQL cobrem enqueue concorrente, `SKIP LOCKED`, checkpoint/lease
do coletor, candidato/autorização atômicos, upsert idempotente, agregação de
drafts, ausência de raw secret, ledger temporal e runs vazias. Os testes unitários
cobrem paginação completa, divisão temporal, ordenação local, cursor legado, retry,
reuso de metadados, filtros, histórico e detectores. O benchmark cripto é um gate
exato sobre corpus sintético rotulado; seus números não representam acurácia em
repositórios reais.

## Publicação em VPS

Mantenha PostgreSQL sem porta pública e a API em loopback. Exponha somente HTTPS por um reverse proxy com autenticação adicional, firewall e backup diário (`pg_dump`). Os workers precisam apenas de saída HTTPS para GitHub; não precisam de porta de entrada. Não monte o Docker socket nos containers.

Para uma instalação real ainda faltam dados externos que não devem ser inventados: host/VPS, domínio, certificado, política de retenção, backup e um token GitHub com o menor escopo possível. O Compose deste repositório é um deploy local funcional, não prova produção pública.
