# Templates de divulgação

## Canal privado

O draft privado agrega os achados do repositório e inclui:

- plataforma e `type_id`;
- risco e categoria;
- arquivo e commit, quando disponíveis;
- estado da validação;
- risco real, persistência no histórico e passos de rotação.

Ele nunca inclui o segredo bruto nem um fragmento derivado do valor. O texto real é gerado por `secret_hunter/report.py` e enviado preferencialmente por Private Vulnerability Reporting após aprovação humana.

## Issue pública de contato

```text
Olá! Durante uma varredura defensiva em código público, identifiquei uma possível
credencial exposta relacionada a este repositório.

Para não ampliar a exposição, não publicarei tipo, arquivo, commit nem qualquer
fragmento aqui. Poderiam indicar um canal privado em SECURITY.md ou habilitar o
Private vulnerability reporting do GitHub?
```

O envio público fica desabilitado por padrão. Nunca copie o draft privado para uma Issue pública.
