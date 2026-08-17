# Drop-zone de ingestao

Este diretorio e montado read-only em `/ingest`. Nunca commite os arquivos
recebidos: o `.gitignore` ignora todo o conteudo, exceto este README.

Layout `tree`:

```text
ingest/
  owner/
    repository/
      .env
      config/settings.json
```

Layout `manifest`: coloque os arquivos em qualquer subdiretorio confinado e um
arquivo JSONL, por exemplo `batch.jsonl`:

```json
{"repository":"owner/repository","file":"payloads/42/config.env","path":".env","branch":"main","commit":"0123456789abcdef0123456789abcdef01234567"}
```

O campo `file` aponta para um arquivo relativo a este diretorio. `path` e o
caminho original exibido no achado. `branch` e `commit` sao opcionais.
