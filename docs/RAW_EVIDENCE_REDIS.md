# Evidência bruta simples no Redis

Esta primeira camada preserva as respostas HTTP brutas recebidas da API REST do
GitHub durante descoberta, busca e leitura de blobs. Cada resposta vira uma
entrada em `secret-hunter:raw-evidence`, um Redis Stream sem TTL e sem trimming.

## Garantias atuais

- Redis roda no Docker sem porta publicada no host.
- O acesso exige uma senha aleatória em
  `.secrets/redis_evidence_password.txt`; o arquivo é ignorado pelo Git.
- O volume `redis_evidence_data` usa AOF com `appendfsync everysec`.
- O corpo da resposta é salvo como bytes, acompanhado de SHA-256, tamanho,
  horário, origem e metadados HTTP sanitizados.
- Tokens, cookies e campos de senha nos metadados são substituídos por
  `[redacted]`.
- Falha no Redis interrompe o consumidor quando a captura está habilitada, para
  não processar uma resposta sem preservar a evidência correspondente.

O PostgreSQL continua sendo a fonte de verdade de jobs, achados e auditoria. O
Redis é somente o repositório do material bruto do TCC.

## Inicialização

```powershell
.\scripts\init-secrets.ps1 -RedisOnly
docker compose up -d redis-evidence
docker compose ps
```

Teste a autenticação sem imprimir a senha:

```powershell
docker compose exec redis-evidence sh -c 'REDISCLI_AUTH="$(cat /run/secrets/redis_evidence_password)" redis-cli ping'
```

Os workers dos perfis `scanner` e `discovery` recebem a conexão
automaticamente. `RAW_EVIDENCE_ENABLED=false` desliga a captura.

## Limites desta etapa

- A senha controla acesso, mas não criptografa o volume em repouso.
- AOF e volume Docker não substituem backup externo.
- Ainda não são guardados o bundle do clone Git, webhooks ou uma cadeia de
  hashes entre registros.
- Não há política automática de retenção: o crescimento do volume precisa ser
  monitorado.

Criptografia em repouso, backups imutáveis, cadeia de integridade e captura do
clone completo ficam como camadas futuras, depois da validação deste fluxo
simples.
