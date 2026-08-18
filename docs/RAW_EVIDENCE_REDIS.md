# Evidência bruta protegida por senha no Redis

Esta primeira camada preserva as respostas HTTP brutas recebidas da API REST do
GitHub durante descoberta, busca e leitura de blobs. Cada resposta vira uma
entrada em `secret-hunter:raw-evidence`, um Redis Stream sem TTL e sem trimming.

A mesma instância hospeda streams operacionais separados e sanitizados. O contrato
desses streams está em [REDIS_PIPELINE.md](REDIS_PIPELINE.md); este documento trata
apenas do corpus bruto.

## Garantias atuais

- Redis roda no Docker sem porta publicada no host.
- Existe uma única camada de acesso: a senha aleatória em
  `.secrets/redis_evidence_password.txt`, ignorada pelo Git.
- O corpo HTTP original é gravado no campo `payload`; `payload_sha256` e tamanho
  permitem conferir integridade sem mostrar o conteúdo.
- O volume `redis_evidence_data` usa AOF com `appendfsync everysec`.
- Tokens, cookies e campos de senha nos metadados são substituídos por
  `[redacted]`.
- Falha no Redis interrompe o consumidor quando a captura está habilitada, para
  não processar uma resposta sem preservar a evidência correspondente.

O PostgreSQL continua sendo a fonte de verdade de jobs, achados e auditoria. O
Redis transporta referências sanitizadas aos jobs e preserva o material bruto do
TCC; não decide o estado transacional.

## Inicialização

```powershell
.\scripts\init-secrets.ps1 -RedisOnly
docker compose up -d redis-evidence
docker compose ps
```

Prova controlada, sem imprimir o payload:

```powershell
.\scripts\prove-redis.ps1
```

O comando grava uma amostra sintética e confirma ID, horário, tamanho e SHA-256.

Teste a autenticação sem imprimir a senha:

```powershell
docker compose exec redis-evidence sh -c 'REDISCLI_AUTH="$(cat /run/secrets/redis_evidence_password)" redis-cli ping'
```

Os workers dos perfis `scanner` e `discovery` recebem a conexão
automaticamente. `RAW_EVIDENCE_ENABLED=false` desliga a captura.

## Limites desta etapa

- Esta versão tem uma única proteção: Redis AUTH. O payload não é cifrado pela
  aplicação e fica legível para qualquer processo que obtenha a senha e acesso à
  rede/volume do Redis.
- AOF e volume Docker não substituem backup externo.
- Ainda não são guardados o bundle do clone Git, webhooks ou uma cadeia de
  hashes entre registros.
- Jobs, eventos e evidência bruta não têm trimming automático: o crescimento do volume precisa ser
  monitorado.
- Registros antigos de schema 2 permanecem cifrados no mesmo stream e são
  identificados como `legacy_encrypted`; novos registros usam schema 3.

Backups imutáveis, criptografia em repouso, cadeia de integridade entre entradas e
captura do clone completo permanecem como camadas futuras.
