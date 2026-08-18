# Operação e produção

## Perfis seguros

- Sem perfil: PostgreSQL, migração e API. Nenhuma busca/envio.
- `scanner`: dispatcher, indexador, scheduler e workers `search`/`blob`. Requer token GitHub read-only.
- `notifications`: worker de divulgação. Só consome drafts aprovados.
- `test`: suíte contra PostgreSQL e Redis temporários próprios (`postgres-test` e `redis-test`), sem
  tocar nos volumes operacionais.
- `ingest`: watcher e workers exclusivos para arquivos do drop-zone; não inicia
  busca GitHub nem notificações.
- `discovery`: consulta janelas fechadas de repositórios recém-criados, reutiliza
  metadados da Search API e filtra candidatos. No automático, envia 100% dos elegíveis para pré-scan
  raso e limitado; a Code Search complementa a cobertura e somente um detector da allowlist EVM/Solana/BIP39 expande para histórico completo.
  Validação ativa continua separada.

## Dashboard local

O dashboard é servido pela própria API em `http://127.0.0.1:8000/`. Ele não
adiciona porta nem serviço Docker. O token administrativo é solicitado no login
e permanece somente no `sessionStorage` da aba. Headers CSP, `frame-ancestors`,
`nosniff`, `no-referrer` e `no-store` reduzem a superfície do frontend.
A tabela de achados atualiza a cada 2 segundos enquanto a aba está visível e oferece
um link direto para o arquivo/commit/linha no GitHub. A atualização completa permanece
em 30 segundos para não recarregar todas as coleções continuamente.

Para copiar o token no PowerShell sem imprimi-lo em documentação ou `.env`:

```powershell
Get-Content .\.secrets\admin_api_token.txt -Raw | Set-Clipboard
```

## Concorrência

PostgreSQL mantém o estado durável e idempotente de cada job. O `redis-dispatcher` publica referências sanitizadas em um stream por estágio. Workers usam consumer groups, reclamam mensagens abandonadas e só executam o job exato após `claim_job_by_id`; o `XACK` ocorre depois do commit terminal. Leases e heartbeat permitem retomada após crash. Enqueue, finding e localização são idempotentes. O rate limiter é compartilhado no banco.

O watcher usa lease PostgreSQL e um ledger de janelas de 60 segundos. As janelas
mais recentes são consultadas primeiro, divididas quando ultrapassam 1.000
resultados e reconciliadas após 15 minutos. Candidatos, jobs, estado das janelas e
checkpoint são commitados juntos; falhas ficam pendentes para retry e repetições
após crash são absorvidas pelas chaves únicas.

Repository Search usa um bucket compartilhado de 24 requests/minuto.

É seguro escalar horizontalmente:

```powershell
docker compose --profile scanner --profile discovery up -d
```

O Compose reserva 4 workers para `metadata-live`, 8 para `head-live`, 2/4 para
backfill e 4 para histórico. Dois workers legados de metadata e HEAD drenam jobs
anteriores sem reset. O rate limiter PostgreSQL continua único entre réplicas.

Aumentar workers não aumenta a cota do GitHub. O default é oito páginas de Code Search por minuto; o ambiente ativo usa cinco, abaixo do limite autenticado de dez.

## Notificação e recuperação

Não escale o notification worker sem necessidade, embora o claim também use `SKIP LOCKED`. Antes da chamada externa o draft muda para `sending`, evitando envio simultâneo. Se o processo cair em ponto ambíguo, o draft permanece assim: confira o repositório e só então use `/requeue`. Isso escolhe at-most-once por padrão em vez de duplicar avisos.

## Backup

Faça backup diário e teste restauração. Exemplo executado a partir do host, ajustando destino:

```powershell
docker compose exec -T postgres pg_dump -U secret_hunter -d secret_hunter -Fc > secret-hunter.dump
```

Proteja o dump: ele não contém segredo bruto, mas contém repositórios, caminhos, commits, fingerprints e drafts privados.

No Compose local, “secrets” ainda são arquivos plaintext no host. O script de inicialização restringe as ACLs ao usuário atual e `SYSTEM`; em produção, prefira um secret manager/injetor do provedor da VPS.

## Rotação

- Tokens GitHub de busca/notificação e token admin: podem ser atualizados e os
  containers correspondentes reiniciados. Não reutilize o mesmo PAT nos dois
  workers.
- Senha PostgreSQL: exige alterar o usuário no banco e o secret de forma coordenada.
- Chave `fingerprint_key`: não rotacione diretamente; isso quebraria deduplicação. Planeje migração com período de duas chaves.
- Senha `redis_evidence_password`: é a única camada do corpus bruto; rotacione de forma coordenada e nunca a exponha no dashboard.

O script `init-secrets.ps1` preserva secrets existentes. `-RotateCoreSecrets` é para uma instalação vazia ou rotação planejada.

## Exposição pública

- Não publique a porta 5432.
- Mantenha `127.0.0.1:8000:8000` e coloque um reverse proxy HTTPS no mesmo host.
- Adicione identidade forte além do bearer token (VPN, mTLS ou access proxy).
- Libere no firewall apenas SSH restrito e HTTPS.
- Não registre headers Authorization, drafts privados ou payloads de erro completos.
- Defina retenção e acesso de operadores antes de ativar busca em larga escala.

## Diagnóstico

```powershell
docker compose ps
docker compose logs --tail 200 api redis-dispatcher event-indexer `
  metadata-worker head-worker history-worker search-worker blob-worker
docker compose exec postgres pg_isready -U secret_hunter -d secret_hunter
```

Use `GET /runs`, `/jobs`, `/streams`, `/events` e `/stats` para diferenciar fila vazia, lag de transporte, retry, lease expirado e falha definitiva. O dashboard exibe as mesmas métricas sem expor payload bruto.
