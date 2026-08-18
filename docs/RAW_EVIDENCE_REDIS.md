# Evidência bruta criptografada no Redis

Esta primeira camada preserva as respostas HTTP brutas recebidas da API REST do
GitHub durante descoberta, busca e leitura de blobs. Cada resposta vira uma
entrada em `secret-hunter:raw-evidence`, um Redis Stream sem TTL e sem trimming.

A mesma instância hospeda streams operacionais separados e sanitizados. O contrato desses streams está em [REDIS_PIPELINE.md](REDIS_PIPELINE.md); este documento trata apenas do corpus bruto.

## Garantias atuais

- Redis roda no Docker sem porta publicada no host.
- O acesso exige uma senha aleatória em
  `.secrets/redis_evidence_password.txt`; o arquivo é ignorado pelo Git.
- O corpo HTTP é cifrado no cliente com AES-256-GCM antes do `XADD`; a chave em
  `.secrets/evidence_encryption_key.txt` não é montada no container do servidor Redis.
- O volume `redis_evidence_data` usa AOF com `appendfsync everysec`.
- O stream recebe ciphertext, nonce aleatório de 96 bits, tag de autenticação de
  128 bits, ID da chave, SHA-256 do plaintext/ciphertext, tamanho, horário, origem
  e metadados HTTP sanitizados. Os metadados são AAD e qualquer alteração quebra
  a autenticação.
- Tokens, cookies e campos de senha nos metadados são substituídos por
  `[redacted]`.
- Falha no Redis interrompe o consumidor quando a captura está habilitada, para
  não processar uma resposta sem preservar a evidência correspondente.

O PostgreSQL continua sendo a fonte de verdade de jobs, achados e auditoria. O
Redis transporta referências sanitizadas aos jobs e preserva o material bruto cifrado do TCC; não decide o estado transacional.

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

- Senha e chave AES precisam de backup separado; perder a chave torna o corpus irrecuperável.
- AOF e volume Docker não substituem backup externo.
- Ainda não são guardados o bundle do clone Git, webhooks ou uma cadeia de
  hashes entre registros.
- Jobs, eventos e evidência bruta não têm trimming automático: o crescimento do volume precisa ser
  monitorado.

Backups imutáveis, rotação coordenada de chaves, cadeia de integridade entre
entradas e captura do clone completo permanecem como camadas futuras.
