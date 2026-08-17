# Benchmark dos detectores cripto

## Objetivo

Este gate mede a classificação local dos detectores EVM e Solana antes de qualquer
coleta pública. Ele usa um corpus sintético rotulado e exige correspondência exata
entre os tipos esperados e detectados em cada caso.

O resultado não mede a prevalência de vazamentos no GitHub e não substitui uma
avaliação posterior com amostra cega. Ele apenas demonstra o comportamento do
conjunto de detectores no corpus versionado desta pesquisa.

## Proteção das fixtures

O arquivo `benchmarks/crypto_corpus.json` guarda somente templates com placeholders,
como `{EVM_HEX}` e `{SOLANA_KEYPAIR_BASE58}`. O runner cria bytes sintéticos e
determinísticos em memória, executa a extração e não imprime os valores gerados.
Nenhuma chave real, RPC, saldo, assinatura ou broadcast participa do benchmark.

## Cobertura

Os casos positivos cobrem:

- chave EVM em contextos Ethereum, Base, BSC, Robinhood, deployer e relayer;
- construtores ethers, web3.py e viem;
- alias curto `PK` somente em arquivo `.env` real;
- keypair Solana em array JSON, Base58, Base64 e hexadecimal;
- seed Solana em array, Base58, Base64 e hexadecimal;
- mnemonic BIP39 com wordlist e checksum válidos;
- keystore EVM v3 classificado separadamente da chave em texto puro.

Os negativos cobrem hash de transação, endereço EVM, `bytes32`, salt CREATE2,
bytecode, template de ambiente, documentação, pubkey e assinatura Solana, arrays
sem contexto, checksum BIP39 inválido, frase natural e placeholder.

## Métricas e regra do gate

Para cada caso são comparados conjuntos de `type_id`, sem contar duplicatas. O
runner calcula `TP`, `FP`, `FN`, `TN`, precisão, recall e F1. O processo retorna
código diferente de zero se qualquer caso divergir, e o teste automatizado exige:

- zero falsos positivos;
- zero falsos negativos;
- precisão, recall e F1 iguais a `1.0` neste corpus;
- todos os casos aprovados por igualdade exata.

## Baseline congelado

Execução local em 2026-08-17:

| Campo | Resultado |
|---|---:|
| Pattern set | `66d2fc27bfb5` |
| Casos | 35 |
| Positivos | 21 |
| Negativos | 14 |
| TP / FP / FN / TN | 21 / 0 / 0 / 14 |
| Precisão / Recall / F1 | 1.0000 / 1.0000 / 1.0000 |

Este número perfeito é interno ao corpus sintético conhecido. Não deve ser
apresentado como acurácia em repositórios reais nem como probabilidade universal
de vazamento.

## Reprodução

```powershell
python scripts/benchmark_crypto_detectors.py
python scripts/benchmark_crypto_detectors.py --json
python -m pytest -q tests/test_crypto_benchmark.py
```

Qualquer mudança nos detectores deve registrar um caso que represente a regressão
ou a nova cobertura. A próxima etapa científica é uma avaliação cega separada,
seguida por piloto pequeno e revisão humana, ainda sem validação ativa das chaves.
