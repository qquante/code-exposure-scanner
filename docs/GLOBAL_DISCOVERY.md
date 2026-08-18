# Descoberta global segura de repositórios novos

O objetivo é acompanhar repositórios públicos recém-criados. As 4 horas são
somente o teto de recuperação: o scheduler sempre processa primeiro a janela
fechada mais recente e nunca busca itens antigos para preencher artificialmente
um lote.

Com `DISCOVERY_AUTO_QUEUE_SCANS=true` e `DISCOVERY_HEAD_SCAN_SAMPLE_PERCENT=100`, todos os
candidatos elegíveis seguem para pré-scan raso. Em paralelo, a Code Search consulta
somente sete contextos EVM/Solana/BIP-39 de alto sinal. O histórico completo só é
criado após um achado da allowlist fixa EVM/Solana/BIP39. Nessa fase, Bitcoin WIF,
PEM genérico e demais categorias não são persistidos. Dependências e metadados gerados como
`node_modules`, `.venv`, `site-packages`, `.pnpm`, `.yarn` e `Cargo.lock` são excluídos antes da leitura.
A validação ativa de credenciais continua separada, desabilitada por padrão e
condicionada à allowlist explícita.

## Fluxo

```text
relógio UTC
  -> fecha janela de 60s com atraso de indexação de 120s
  -> ledger PostgreSQL cria janelas faltantes, limitado às últimas 4h
  -> seleciona as 4 janelas pendentes mais recentes
  -> GET /search/repositories
       q=created:INICIO..FIM is:public
       per_page=100
  -> se total_count > 1000, divide a janela e consulta a metade nova primeiro
  -> pagina todos os resultados da subjanela
  -> incomplete_results=true: não conclui a janela; agenda retry
  -> ordena localmente por created_at DESC
  -> deduplica por github_repository_id
  -> persiste todos os IDs novos; não corta em N candidatos
  -> reutiliza os metadados da Search API no job de enriquecimento
  -> filtros determinísticos de metadados
  -> classifica queue_lane: live até 20min; backfill entre 20min e 4h
  -> fila automática: 100% dos candidatos elegíveis
  -> em paralelo: primeira página da Code Search horária, indexed DESC
  -> GET /repos para confirmar created_at dentro das últimas 4h
  -> PostgreSQL cria o job idempotente e o redis-dispatcher publica a etapa
  -> metadata/head live e backfill consomem Redis Streams separados
  -> pré-scan do HEAD: clone raso, até 2.000 arquivos / 20 MB / 120s
  -> sem sinal EVM/Solana/BIP39: encerra sem baixar histórico
  -> com sinal EVM/Solana/BIP39: history-worker recebe scan_history completo
  -> dependências vendorizadas e tipos fora da allowlist são descartados
  -> finding redigido e evento sanitizado
  -> draft pending_review
  -> aprovação humana
  -> notificação privada
```
A lane é gravada no payload dentro da mesma transação que cria candidato e job.
Por isso, um backlog antigo nunca fica na frente de um repositório live. Jobs
criados antes desta mudança, sem `queue_lane`, continuam nos streams legados até
serem drenados. O histórico possui stream e quatro workers próprios: ele não
bloqueia descoberta, metadados ou HEAD.


Janelas recentes são consultadas novamente após 15 minutos para compensar atraso
de indexação. Janelas antigas do backlog precisam apenas da passagem inicial. Em
cada ciclo, uma janela nova sempre fica à frente de reconciliação e recuperação.

Os estados do candidato são:

- `pending_metadata`: capturado e aguardando o job local de filtros.
- `pending_review`: elegível; estado transitório antes da fila automática.
- `filtered`: excluído por idioma, tamanho, fork, idade, archive ou estado.
- `unavailable`: removido, identidade inconsistente ou metadados inválidos.
- `scan_queued`: pré-scan automático ou histórico criado após autorização manual.
- `rejected`: rejeitado manualmente.

## Controle de quota

O bucket `github-search-discovery` é compartilhado no PostgreSQL entre todos os
containers. O default operacional reserva no máximo 24 requisições de Repository
Search por minuto, abaixo do limite autenticado publicado de 30/min. Cada resposta
também respeita `X-RateLimit-Remaining`, `X-RateLimit-Reset` e `Retry-After`.
Erros 403/429 usam espera e retry; continuar consultando durante bloqueio não é
permitido.

O cliente local possui o mesmo throttle como fallback, mas o watcher distribuído
usa o bucket PostgreSQL. Mais workers aceleram scans locais; não aumentam a cota
do GitHub.

## Ativar

O token de busca deve ser read-only. O ambiente permanece inerte até o perfil ser
iniciado explicitamente:

```powershell
docker compose up -d --build api
docker compose --profile scanner --profile discovery up -d --build

```

Com `DISCOVERY_AUTO_QUEUE_SCANS=true`, os workers live têm capacidade reservada e
nunca aguardam a recuperação. O clone de histórico só nasce após sinal `crypto`
e usa workers independentes. PostgreSQL preserva o backlog; Redis Streams separa
fisicamente cada etapa e lane em consumer groups próprios.

## Modo manual opcional

Listar candidatos:

```powershell
$adminToken = (Get-Content .\.secrets\admin_api_token.txt -Raw).Trim()
$headers = @{ Authorization = "Bearer $adminToken" }
$candidates = Invoke-RestMethod `
  "http://127.0.0.1:8000/candidates?status=pending_review" `
  -Headers $headers
```

O endpoint `authorize-scan` continua atômico: trava o candidato, registra ator e
referência, cria run/job e muda o estado para `scan_queued`. Chamadas concorrentes
produzem no máximo um job.

## Configuração

| Variável | Default | Efeito |
|---|---:|---|
| `SEARCH_WINDOW_HOURS` | 1 | agenda a Code Search uma vez por hora |
| `SEARCH_REQUESTS_PER_MINUTE` | 8 | teto local/compartilhado; ambiente ativo usa 5 |
| `SEARCH_MAX_PAGES` | 1 | processa apenas a página mais recentemente indexada por query |
| `SEARCH_TYPES` | vazio | IDs de queries; ambiente ativo usa somente os sete tipos cripto |
| `DISCOVERY_POLL_SECONDS` | 15 | frequência do scheduler |
| `DISCOVERY_LEASE_SECONDS` | 180 | lease exclusivo entre pollers |
| `DISCOVERY_WINDOW_SECONDS` | 60 | tamanho inicial de cada janela |
| `DISCOVERY_HEAD_DELAY_SECONDS` | 120 | atraso de indexação antes de fechar a janela live |
| `DISCOVERY_RECONCILE_SECONDS` | 900 | atraso para a segunda passagem recente |
| `DISCOVERY_WINDOWS_PER_POLL` | 4 | janelas mais novas processadas por ciclo |
| `DISCOVERY_SEARCH_REQUESTS_PER_MINUTE` | 24 | limite compartilhado de Repository Search |
| `DISCOVERY_MAX_PAGES` | 10 | teto do cursor legado; a busca adaptativa pagina até 1.000 |
| `DISCOVERY_METADATA_REQUESTS_PER_HOUR` | 3000 | fallback legado de `GET /repos` |
| `DISCOVERY_REPOSITORIES_PER_POLL` | 1000 | apenas cursor legado `/repositories` |
| `DISCOVERY_INCLUDE_FORKS` | false | inclui forks |
| `DISCOVERY_AUTO_QUEUE_SCANS` | true | enfileira candidatos elegíveis automaticamente |
| `DISCOVERY_LANGUAGES` | vazio | allowlist CSV; vazio aceita qualquer idioma |
| `DISCOVERY_MIN_SIZE_KB` | 1 | elimina repositórios ainda vazios antes de qualquer clone |
| `DISCOVERY_MAX_SIZE_KB` | 50000 | tamanho máximo; `0` desabilita o teto |
| `DISCOVERY_HEAD_SCAN_MAX_FILES` | 2000 | máximo de arquivos lidos no pré-scan |
| `DISCOVERY_HEAD_SCAN_MAX_TOTAL_BYTES` | 20000000 | máximo total lido por árvore |
| `DISCOVERY_HEAD_SCAN_TIMEOUT_SECONDS` | 120 | timeout do clone raso |
| `DISCOVERY_HEAD_SCAN_SAMPLE_PERCENT` | 100 | percentual determinístico; 100 envia todo candidato elegível |
| `DISCOVERY_LIVE_MAX_AGE_MINUTES` | 20 | separa a lane live da recuperação |
| `DISCOVERY_MAX_EVENT_AGE_HOURS` | 4 | teto do ledger e da recuperação |
| `DISCOVERY_RETENTION_DAYS` | 30 | retenção de candidatos terminais |

## Limites reais

A REST API não ordena Repository Search por criação; ela só oferece `updated`
entre os sorts úteis. Por isso, cada intervalo temporal é esgotado e depois
ordenado localmente por `created_at DESC`.

A API fornece no máximo 1.000 resultados por consulta e 100 por página. A divisão
recursiva por tempo evita esse teto enquanto cada intervalo mínimo de um segundo
tiver no máximo 1.000 resultados. Mesmo assim, a cobertura é best-effort: atraso
de indexação, timeout da busca, repositórios removidos e resultados não acessíveis
ao token impedem promessa de cobertura global absoluta.

A Code Search é complementar: usa 5 requisições/minuto no ambiente ativo, abaixo
do limite autenticado de 10/minuto e solicita `sort=indexed&order=desc`. Para cada
resultado da primeira página, consulta os metadados e só baixa o blob se
`created_at` estiver dentro das últimas 4 horas. O sort ainda existe na API, mas está marcado pelo
GitHub como em descontinuação; por isso, a ordem recente é best-effort e deve ser
monitorada. A Code Search cobre apenas a branch padrão, arquivos menores que
384 KB, até 1.000 resultados por consulta e no máximo 4.000 repositórios que
atendam aos filtros.

Fontes oficiais:

- https://docs.github.com/en/rest/search/search#search-repositories
- https://docs.github.com/en/search-github/searching-on-github/searching-for-repositories
- https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api

## Limite de segurança

Descoberta e filtros armazenam somente IDs, nome/URL, timestamps, idioma, tamanho,
flags e branch padrão. O scan seguinte opera sobre código público, com verificação
externa do TruffleHog desabilitada. Nenhum modo de fila autoriza validação ativa:
ela continua dependente de `VALIDATE_SECRETS=true` e de uma allowlist explícita
em `AUTHORIZED_VALIDATION_REPOS`.

Candidatos `scan_queued` nunca são apagados pela retenção automática, pois contêm
a trilha de auditoria. Notificações permanecem sob aprovação humana.
