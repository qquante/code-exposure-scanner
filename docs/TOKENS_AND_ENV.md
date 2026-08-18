# Tokens e configuracao do ambiente

O deploy usa dois tokens GitHub independentes e cinco segredos internos. Nenhum
token de Stripe, AWS, Mercado Pago, banco, EVM, Solana ou outro provedor e
necessario para operar o scanner.

## 1. Token de busca

Destino: `.secrets/github_search_token.txt`.

Crie um fine-grained personal access token com expiracao curta (30 a 90 dias):

1. GitHub > Settings > Developer settings > Personal access tokens >
   Fine-grained tokens > Generate new token.
2. Use um nome exclusivo, por exemplo `secret-hunter-search`.
3. Para apenas repositorios publicos, nao conceda permissao de escrita. O
   endpoint `GET /search/code` aceita fine-grained PAT sem permissoes adicionais.
4. Para repositorios privados proprios/autorizados, selecione somente os
   repositorios necessarios e conceda `Contents: read` para permitir a leitura
   dos blobs/arquivos.
5. Nao conceda `Administration`, `Actions`, `Secrets`, `Issues: write` ou
   qualquer permissao de escrita a este token.

O perfil `discovery` reutiliza este token read-only para
`GET /search/repositories`. Os metadados dessa resposta são reaproveitados;
`GET /repos/{owner}/{repo}` fica somente como fallback para jobs antigos.
Para recursos públicos, não adicione escrita.

O Code Search considera somente o branch padrao, arquivos menores que 384 KB e
tem limite proprio de 10 requisicoes por minuto. O projeto usa 8/min por padrao.

## 2. Token de notificacao

Destino: `.secrets/github_notify_token.txt`.

Crie outro fine-grained PAT, com nome `secret-hunter-notify`:

1. Selecione apenas os repositorios em que sua conta/organizacao esta autorizada
   a enviar relatorios pela API.
2. Conceda `Repository security advisories: write`.
3. Nao conceda acesso a `Contents`, `Administration` ou outras permissoes.
4. Deixe `ALLOW_PUBLIC_CONTACT_ISSUE=false`.

O endpoint privado so funciona quando o repositorio publico habilitou Private
Vulnerability Reporting. Em repositorios de terceiros nos quais o PAT nao pode
receber a permissao necessaria, faca a notificacao manual pelo botao privado do
GitHub ou pelo canal de `SECURITY.md`. Nao amplie o token para contornar esse
limite.

O fallback por Issue publica exige `Issues: write`, pode gerar notificacoes e
secondary rate limiting. Ele permanece desabilitado; se for habilitado em um
ambiente autorizado, o texto publico nao inclui segredo, caminho ou commit.

## 3. Segredos internos

- `postgres_password.txt`: senha aleatoria do usuario PostgreSQL.
- `fingerprint_key.txt`: chave HMAC usada para deduplicar sem persistir o segredo
  bruto. Nao rotacione em banco existente sem migracao.
- `admin_api_token.txt`: bearer token da API administrativa local.
- `redis_evidence_password.txt`: única senha da instância Redis, Streams e evidência bruta.

O script gera esses quatro valores com RNG criptografico e restringe a ACL ao
usuario atual e `SYSTEM` no Windows.

## 4. Criar os arquivos sem expor tokens no shell

Salve temporariamente cada PAT em um arquivo fora do repositorio e execute:

```powershell
.\scripts\init-secrets.ps1 `
  -GitHubSearchTokenFile C:\temporario\github-search-token.txt `
  -GitHubNotifyTokenFile C:\temporario\github-notify-token.txt
```

Depois remova com seguranca os arquivos temporarios. Sem parametros, o script
pede os dois tokens com entrada oculta:

```powershell
.\scripts\init-secrets.ps1
```

Nao passe o token diretamente na linha de comando: ele pode ficar no historico
do PowerShell e em ferramentas de monitoramento de processos.

## 5. Configurar `.env`

O arquivo `.env` ja existe e e ignorado pelo Git. Edite principalmente:

```dotenv
SEARCH_SCOPE=repo:owner/repo
ALLOW_GLOBAL_SEARCH=false
SEARCH_WINDOW_HOURS=1
SEARCH_MAX_PAGES=1
SEARCH_TYPES=evm_private_key_to_account,evm_ethers_wallet,evm_account_from_key,evm_private_key_env,solana_from_secret_key,solana_from_seed,bip39_mnemonic_to_account
DISCOVERY_WINDOW_SECONDS=60
DISCOVERY_HEAD_DELAY_SECONDS=3600
DISCOVERY_RECONCILE_SECONDS=900
DISCOVERY_WINDOWS_PER_POLL=4
DISCOVERY_SEARCH_REQUESTS_PER_MINUTE=24
DISCOVERY_MAX_EVENT_AGE_HOURS=48
DISCOVERY_AUTO_QUEUE_SCANS=true
DISCOVERY_HEAD_SCAN_SAMPLE_PERCENT=100
EVENT_BUS_ENABLED=true
EVENT_BUS_PREFIX=secret-hunter
EVENT_BUS_DISPATCH_INTERVAL_MS=250
VALIDATE_SECRETS=false
VALIDATE_CRYPTO=false
AUTHORIZED_VALIDATION_REPOS=
ALLOW_PUBLIC_CONTACT_ISSUE=false
```

Os campos `*_FILE` do `.env` sao apenas caminhos. Os valores secretos ficam em
`.secrets/` e sao montados nos containers em `/run/secrets/...`.

## 6. Ativacao em etapas

```powershell
# Banco + API, sem buscar e sem notificar
docker compose up -d --build api

# Busca no escopo do .env
docker compose --profile scanner up -d --build --scale search-worker=2

# Repositorios publicos recem-criados; scan segue DISCOVERY_AUTO_QUEUE_SCANS
docker compose --profile scanner --profile discovery up -d --build `
  --scale metadata-worker=2 --scale head-worker=2

# Somente depois de revisar e aprovar os drafts na API
docker compose --profile notifications up -d notification-worker
```

Validacao ativa de um segredo encontrado nao usa um token adicional do
provedor: usa o proprio candidato apenas em memoria, somente em repositorios
explicitamente allowlisted. Mantenha `EVENT_BUS_ENABLED=true
EVENT_BUS_PREFIX=secret-hunter
EVENT_BUS_DISPATCH_INTERVAL_MS=250
VALIDATE_SECRETS=false` fora de uma
autorizacao formal. A validacao cripto e local, sem RPC, saldo, assinatura ou
broadcast.
