# Pipeline distribuído com Redis Streams

O deploy automático usa dois componentes persistentes com responsabilidades
separadas:

- PostgreSQL é a fonte de verdade para jobs, idempotência, candidatos, achados,
  runs, drafts e auditoria.
- Redis Streams transporta jobs entre workers independentes, registra eventos
  sanitizados e preserva a evidência HTTP bruta do TCC sob senha única.

```text
GitHub Repository Search (API limitada)       Code Search (API limitada)
                   |                                      |
                   v                                      v
       PostgreSQL scan_jobs + queue_lane            search -> blob
                   |
             redis-dispatcher
                   |
       +-----------+-------------+------------------+
       |                         |                   |
 metadata-live (4)      metadata-backfill (2)   metadata legado (2)
       |                         |                   |
 head-live (8)           head-backfill (4)      head legado (2)
       |                         |                   |
       +-------------------------+-------------------+
                                 |
                    todo repositório elegível
                                 |
                           history (4)
                                 |
                 eventos Redis sanitizados
                                 |
                    event-indexer -> PostgreSQL
```

## Contrato e idempotência

O dispatcher procura jobs ativos ainda sem confirmação de publicação, inclusive
IDs abaixo do cursor legado. Depois do `XADD`, grava a confirmação e o ID gerado
pelo Redis no job PostgreSQL. Mensagens repetidas continuam seguras porque o claim
do job no PostgreSQL é idempotente.

Cada estágio possui stream e consumer group próprios. Um worker lê com
`XREADGROUP`, reclama mensagens abandonadas com `XAUTOCLAIM` e confirma com
`XACK` somente depois que o estado transacional do job foi concluído no
PostgreSQL. `claim_job_by_id` garante que a mensagem só possa executar o job
exato que ela referencia. Retry continua no mesmo registro e mantém a mensagem
pendente; falha terminal é registrada e confirmada.

Esse desenho é entrega pelo menos uma vez no transporte e efeito idempotente no
banco. Redis não decide se um job está concluído.

## Streams

| Stream | Consumer group | Conteúdo |
|---|---|---|
| `<prefix>:jobs:metadata-live` | `<prefix>:workers:metadata-live` | enriquecimento de repositórios com até 20 minutos |
| `<prefix>:jobs:metadata-backfill` | `<prefix>:workers:metadata-backfill` | recuperação entre 20 minutos e 4 horas |
| `<prefix>:jobs:metadata` | `<prefix>:workers:metadata` | compatibilidade: drena jobs anteriores às lanes |
| `<prefix>:jobs:search` | `<prefix>:workers:search` | Code Search do perfil ativo (IA por padrão) |
| `<prefix>:jobs:blob` | `<prefix>:workers:blob` | fetch imutável por SHA |
| `<prefix>:jobs:head-live` | `<prefix>:workers:head-live` | pré-scan raso prioritário do HEAD |
| `<prefix>:jobs:head-backfill` | `<prefix>:workers:head-backfill` | pré-scan raso de recuperação |
| `<prefix>:jobs:head` | `<prefix>:workers:head` | compatibilidade: drena jobs anteriores às lanes |
| `<prefix>:jobs:history` | `<prefix>:workers:history` | histórico opcional (`SCAN_HISTORY=true` + perfil Docker `history`) |
| `<prefix>:jobs:ingest` | `<prefix>:workers:ingest` | drop-zone local |
| `<prefix>:events` | `<prefix>:indexer` | eventos operacionais sanitizados |
| `<prefix>:dead-letter` | operador | mensagens inválidas ou sem rota |
| `<prefix>:raw-evidence` | corpus TCC | respostas HTTP brutas com SHA-256, protegidas por Redis AUTH |

O dashboard consulta `GET /streams` para lag/pendências/consumidores e
`GET /events` para o log já indexado no PostgreSQL.

## Segurança de dados

Mensagens de jobs e eventos passam por sanitização recursiva. Campos cujo nome
indique token, cookie, senha, seed, mnemonic, secret ou private key são
substituídos por `[redacted]`. Findings publicam somente fingerprint HMAC, hint,
tipo, risco e localização. O valor detectado nunca entra no barramento.

O stream de evidência é deliberadamente diferente: preserva corpos HTTP, arquivos
do HEAD que produziram achado e registros aceitos do TruffleHog em formato bruto,
cada um com SHA-256. Arquivos limpos não são copiados, evitando transformar o Redis
em espelho indiscriminado do GitHub. A instância não publica porta no host, exige
uma senha única e persiste com AOF. Quem obtiver a senha e alcançar o Redis poderá
ler o payload; por isso ela não deve ser compartilhada nem usada no dashboard.

## Subir e observar

```powershell
docker compose --profile scanner --profile discovery up -d --build

docker compose ps
docker compose logs --tail 200 redis-dispatcher event-indexer `
  metadata-live-worker metadata-backfill-worker metadata-worker `
  head-live-worker head-backfill-worker head-worker history-worker

$adminToken = (Get-Content .\.secrets\admin_api_token.txt -Raw).Trim()
$headers = @{ Authorization = "Bearer $adminToken" }
Invoke-RestMethod http://127.0.0.1:8000/streams -Headers $headers
Invoke-RestMethod http://127.0.0.1:8000/events?limit=100 -Headers $headers
```

Escalar um estágio não cria uma segunda fila e não duplica efeitos:

```powershell
docker compose --profile discovery up -d --scale head-worker=4
```

Mais workers não aumentam a cota do GitHub. Search e descoberta continuam sob
buckets compartilhados no PostgreSQL. Lag alto deve ser resolvido escalando
somente a etapa correspondente e observando CPU, disco, cota e crescimento do
Redis.

## Limites

- Redis e PostgreSQL no Compose local não possuem alta disponibilidade.
- AOF `everysec` pode perder aproximadamente o último segundo numa falha total
  do host; o dispatcher recompõe jobs duráveis a partir do PostgreSQL.
- Streams não têm trimming automático nesta fase para preservar a trilha do TCC;
  monitore volume e defina retenção antes de produção.
- Notificação externa continua em outro perfil e exige aprovação humana.
- Validação ativa de credenciais continua desligada e exige allowlist explícita.
