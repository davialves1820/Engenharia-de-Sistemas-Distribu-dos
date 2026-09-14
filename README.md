# GoFood — Segurança em SPA (Engenharia de Sistemas Distribuídos, UFPB)

Repositório com as **duas entregas** da atividade de segurança.

## Estrutura

```
.
├── tarefa1-sast-dast/     # Tarefa 1: aplicar SAST e DAST no servidor (antes/depois)
│   ├── TAREFA1-SAST-DAST.md    # relatório: 12/12 vulnerável → 0/13 corrigido
│   ├── vuln/  fixed/            # dois servidores executáveis (Express + db mock)
│   ├── dast_probe*.py           # probes DAST (atacam a app rodando)
│   ├── *-dast.json              # resultados DAST
│   └── rules.yml, sast-*.json   # SAST (Semgrep)
│
└── tarefa2-exercicio/     # Tarefa 2: exercício Q1–Q10
    ├── README.md               # descrição do repositório do exercício
    ├── docs/
    │   ├── 01-solucao-exercicio.md          # respostas Q1–Q10
    │   └── 02-relatorio-sast-comparativo.md # relatório SAST (com limitações)
    ├── backend/  frontend/     # código corrigido (Q4–Q7)
    ├── .github/, sonar-project.properties   # pipeline DevSecOps (Q10)
    └── analise-seguranca/      # regras + resultados + código vulnerável
```

## As duas tarefas

**Tarefa 1 — SAST e DAST no servidor, antes e depois.**
Análise estática (Semgrep) **e dinâmica** (servidores subidos localmente e atacados via probe HTTP). Resultado: 13 achados SAST e 12/12 vetores DAST exploráveis no código vulnerável, reduzidos a 0 no código corrigido. Detalhes e reprodução em `tarefa1-sast-dast/TAREFA1-SAST-DAST.md`.

**Tarefa 2 — Exercício GoFood (Q1–Q10).**
Mapeamento OWASP das 20 vulnerabilidades, análise dos ataques (XSS, SQLi), código corrigido (auth, orders, server, SPA), diagrama de sequência, análise arquitetural defense-in-depth e pipeline DevSecOps. Respostas em `tarefa2-exercicio/docs/01-solucao-exercicio.md`.

## Metodologia e limitações (transparência)

O SAST rodou com **Semgrep** usando regras customizadas (o registry oficial não estava acessível no ambiente). O **SonarCloud está configurado, mas não foi executado** — roda no CI após o push. O **DAST foi executado de fato** (Tarefa 1), subindo os servidores localmente com banco em memória mockado e atacando-os. Detalhes na seção 8 do relatório da Tarefa 2 e na nota metodológica do relatório da Tarefa 1.

## Nota sobre uso de IA

Parte deste material foi produzida com apoio de assistente de IA (Claude) e revisada pelo autor. Incluída por transparência — verificar a política da disciplina sobre uso de ferramentas de IA.
