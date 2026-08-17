# Ingestao modular de arquivos

Este modulo e a fronteira entre um conector futuro e o scanner. Ele nao descobre
repositorios, nao acessa uma API externa e nao baixa conteudo. O conector apenas
materializa arquivos no drop-zone; a ingestao cuida do restante.

## Fluxo

```text
conector futuro
  -> grava arquivos em INGEST_HOST_PATH
  -> adapter tree ou manifest enumera metadados
  -> valida path traversal, symlink, tamanho e binario
  -> calcula SHA-256
  -> PostgreSQL recebe job sem conteudo do arquivo
  -> ingest-worker reabre o arquivo read-only e confere o SHA-256
  -> regex/heuristicas extraem candidatos somente em memoria
  -> PostgreSQL recebe fingerprint HMAC + metadados seguros
  -> draft fica pending_review
```

Se o arquivo mudar entre enqueue e processamento, o worker o rejeita. A proxima
enumeracao calcula um SHA-256 novo e cria outro job. A natural key inclui versao
dos detectores, repositorio, caminho de origem, caminho logico e hash; por isso
watchers concorrentes nao processam a mesma versao duas vezes.

## Adapter `tree`

Use quando o conector puder criar esta estrutura:

```text
ingest/
  owner-a/
    repository-a/
      .env
      src/settings.json
  owner-b/
    repository-b/
      config.yml
```

Configuracao:

```dotenv
INGEST_HOST_PATH=./ingest
INGEST_ADAPTER=tree
INGEST_SOURCE=
```

`INGEST_SOURCE=batch-001` permite manter o mesmo layout dentro de
`ingest/batch-001/owner/repository/...`.

## Adapter `manifest`

Use quando o conector precisar preservar o caminho original, branch ou commit.
Cada linha do JSONL e independente:

```json
{"repository":"owner/repository","file":"payloads/id-1/file.env","path":".env","branch":"main","commit":"0123456789abcdef0123456789abcdef01234567"}
```

- `repository`: obrigatorio, formato `owner/repository`.
- `file`: obrigatorio, caminho relativo ao drop-zone.
- `path`: caminho original; se omitido, usa `file`.
- `branch`: opcional.
- `commit`: opcional, hexadecimal de 7 a 64 caracteres.

Configuracao:

```dotenv
INGEST_ADAPTER=manifest
INGEST_SOURCE=batch.jsonl
```

O manifesto contem apenas metadados. Nunca coloque o conteudo ou o segredo nele.

## Executar uma vez

Suba banco/API e depois enumere o drop-zone:

```powershell
docker compose up -d --build api
docker compose --profile ingest run --rm ingest-watcher secret-hunter ingest-watcher --once
docker compose --profile ingest up -d --scale ingest-worker=4 ingest-worker
```

Ou pela API administrativa:

```powershell
$adminToken = (Get-Content .\.secrets\admin_api_token.txt -Raw).Trim()
$headers = @{ Authorization = "Bearer $adminToken" }
$body = @{ adapter = "tree"; source = "" } | ConvertTo-Json
Invoke-RestMethod http://127.0.0.1:8000/jobs/ingest `
  -Method Post -Headers $headers -ContentType application/json -Body $body
```

## Observar continuamente

```powershell
docker compose --profile ingest up -d --build --scale ingest-worker=4 `
  ingest-worker ingest-watcher
```

O watcher reenumera a cada `INGEST_POLL_SECONDS=60`. A reenumeracao e segura e
idempotente; aumentar workers nao duplica jobs ou achados.

## Contrato para um conector futuro

Um conector precisa fazer somente isto:

1. Obter arquivos dentro do seu escopo autorizado.
2. Gravar cada arquivo completamente usando nome temporario.
3. Renomear atomicamente para o caminho definitivo.
4. Criar/atualizar o JSONL, se usar `manifest`, tambem por rename atomico.
5. Nunca escrever fora de `INGEST_HOST_PATH`.
6. Nao chamar validacao de provedor, RPC, saldo, assinatura ou notificacao.

O conector nao precisa conhecer regex, PostgreSQL ou notificacoes. Para adicionar
outra origem, implemente o protocolo `IngestAdapter` em `secret_hunter/ingest.py`
e registre-a em `build_ingest_adapter`.

## Controles de seguranca

- Volume montado read-only nos containers.
- Caminhos absolutos e `..` sao rejeitados.
- Symlinks sao rejeitados.
- Arquivos binarios e acima de `INGEST_MAX_FILE_BYTES` sao ignorados.
- Conteudo e segredo bruto nao entram na fila nem no banco.
- O worker de ingestao aceita somente `scan_ingested_file`.
- Drafts continuam exigindo aprovacao humana; notification worker nao e iniciado
  pelo perfil `ingest`.
