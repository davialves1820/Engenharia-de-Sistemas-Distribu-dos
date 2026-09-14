# GoFood — Exercício Prático: Segurança em SPA

Resolução do exercício de segurança da disciplina **Engenharia de Sistemas Distribuídos** (UFPB, Prof. Raoni Kulesza — Material 2: Segurança da Informação).

O exercício parte de uma aplicação SPA (React) + API REST (Node.js/Express) com 20 vulnerabilidades plantadas (V1–V20), pede o mapeamento ao OWASP Top 10, a análise dos vetores de ataque, a correção do código e a análise arquitetural (defense-in-depth + pipeline DevSecOps).

## Estrutura do repositório

```
.
├── backend/                    # API Express CORRIGIDA (Q4, Q5, Q7)
│   ├── auth.js                 # autenticação: bcrypt, JWT+refresh, cookie HttpOnly
│   ├── orders.js               # pedidos: query parametrizada, ownership, Zod, requireRole
│   ├── server.js               # helmet+CSP, CORS restrito, rate limit, error handler seguro
│   └── package.json
├── frontend/                   # SPA React CORRIGIDA (Q6)
│   └── src/App.jsx             # sem token no localStorage, authz no servidor, DOMPurify
├── .github/
│   ├── dependabot.yml          # SCA: atualização de dependências + CVE (OWASP A06)
│   └── workflows/security.yml  # pipeline: Semgrep (SAST) + npm audit + SonarCloud
├── sonar-project.properties    # config SonarCloud/SonarQube
├── docs/
│   ├── 01-solucao-exercicio.md            # respostas completas Q1–Q10
│   └── 02-relatorio-sast-comparativo.md   # varredura Semgrep antes vs depois
└── analise-seguranca/
    ├── rules.yml                          # regras Semgrep customizadas (V1–V20)
    ├── vulneravel-results.{json,sarif}    # 13 achados no código original
    ├── corrigido-results.{json,sarif}     # 0 vulnerabilidades reais (1 falso positivo)
    └── codigo-vulneravel/                 # código original, para referência/comparação
```

## Respostas do exercício

As respostas das 10 questões estão em [`docs/01-solucao-exercicio.md`](docs/01-solucao-exercicio.md):

- **Parte 1 (Análise):** Q1 mapeamento OWASP das 20 vulns; Q2 XSS/roubo de token; Q3 SQL Injection.
- **Parte 2 (Correção):** Q4 `auth.js`, Q5 `orders.js`, Q6 `App.jsx`, Q7 `server.js` — código em `backend/` e `frontend/`.
- **Parte 3 (Arquitetura):** Q8 diagrama de sequência; Q9 defense-in-depth (dados em repouso, mTLS, observabilidade); Q10 pipeline DevSecOps.

## Análise de segurança (SAST)

Varredura com **Semgrep** sobre o código vulnerável e o corrigido — relatório comparativo em [`docs/02-relatorio-sast-comparativo.md`](docs/02-relatorio-sast-comparativo.md).

| Base | Total | ERROR | WARNING |
|---|---|---|---|
| Vulnerável | 13 | 7 | 6 |
| Corrigido | 1* | 1* | 0 |

\* Falso positivo (variável já sanitizada por DOMPurify) — triado no relatório. Redução efetiva: 100% das vulnerabilidades reais.

> **Metodologia (resumo):** o SAST foi executado com Semgrep usando **regras customizadas** (`analise-seguranca/rules.yml`), pois o registry oficial não estava acessível no ambiente de execução. O **SonarCloud está configurado mas não foi executado** aqui — roda no CI após o push, com `SONAR_TOKEN`. A seção 8 do relatório detalha essas limitações. A validação **dinâmica (DAST)** foi feita à parte, na Tarefa 1.

Reproduzir:
```bash
pip install semgrep
semgrep --config=analise-seguranca/rules.yml analise-seguranca/codigo-vulneravel
semgrep --config=analise-seguranca/rules.yml backend frontend
```

## CI/CD

Ao subir para o GitHub, ativar em *Settings → Code security*: Dependabot alerts e updates. O workflow `security.yml` roda em push/PR. Para o SonarCloud, adicionar o secret `SONAR_TOKEN` e criar o projeto com a `organization` correta em `sonar-project.properties`.

## Nota sobre uso de IA

Parte deste material (respostas, relatórios e configs) foi produzida com apoio de assistente de IA, revisada pelo autor.
