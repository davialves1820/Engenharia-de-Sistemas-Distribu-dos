# Análise de Segurança — GoFood: Antes vs Depois (SAST) + Configs CI

**Complemento ao exercício** · Ferramenta: **Semgrep 1.176.1** (SAST) · Configs para **Dependabot** e **SonarCloud/SonarQube**
Análise executada sobre os dois códigos: o **vulnerável original** e o **corrigido** (Q4–Q7).

> **Nota honesta sobre a ferramenta.** Dependabot (serviço do GitHub) e o servidor SonarQube não rodam neste ambiente isolado — o primeiro atua num repositório hospedado, o segundo precisa de um servidor. Então a varredura executada de fato aqui foi com **Semgrep**, que é um motor SAST equivalente ao núcleo de análise do Sonar. Para Dependabot e Sonar, entrego os **arquivos de configuração prontos** para plugar no seu repositório (seção final). Os números abaixo são reais, gerados pela execução do Semgrep — não são estimativas.

---

## 1. Resultado da varredura

| Base de código | Total | ERROR | WARNING |
|---|---|---|---|
| **Vulnerável (antes)** | **13** | 7 | 6 |
| **Corrigido (depois)** | **1*** | 1* | 0 |
| **Redução** | **-12 (92%)** | -6 | -6 |

\* O único achado remanescente no código corrigido é um **falso positivo** — explicado na seção 3.

Um regra do conjunto (V15) precisou ser escrita em modo regex por limitação do parser JSX; as 11 regras rodam sem erro nas duas bases após ajuste.

---

## 2. Vulnerabilidades detectadas no código original

Cada linha abaixo foi apontada pelo Semgrep, com arquivo, linha e mapeamento OWASP — os mesmos V1–V20 do enunciado, agora confirmados por ferramenta:

| V | Severidade | Local | OWASP | Regra |
|---|---|---|---|---|
| V1 | ERROR | `auth.js:5` | A02 | `hardcoded-jwt-secret` |
| V2/V6 | ERROR | `auth.js:9` | A03 | `sql-injection-concat` |
| V3 | WARNING | `auth.js:14` | A07 | `jwt-without-expiration` |
| V5 | WARNING | `auth.js:22` | A07 | `token-from-auth-header` |
| V2/V6 | ERROR | `orders.js:6` | A03 | `sql-injection-concat` |
| V11 | WARNING | `App.jsx:7` | A02 | `insecure-http` |
| V12/V13 | ERROR | `App.jsx:13` | A07 | `token-role-in-localstorage` |
| V12/V13 | ERROR | `App.jsx:14` | A07 | `token-role-in-localstorage` |
| V14 | ERROR | `App.jsx:19` | A01 | `client-authz-localstorage` |
| V15 | ERROR | `App.jsx:27` | A03 | `react-dangerous-innerhtml` |
| V16 | WARNING | `server.js:5` | A05 | `cors-wildcard` |
| V17 | WARNING | `server.js:6` | A05 | `json-no-limit` |
| V20 | WARNING | `server.js:15` | A05 | `error-leaks-stack` |

**Cobertura:** o Semgrep pegou 13 dos 20 marcadores. Os que **não** aparecem (V4, V7, V8, V9, V10, V18, V19) são falhas que padrões sintáticos simples não detectam bem — ausência de algo (falta de ownership check em V7/V10, falta de rate limit em V18, falta de helmet em V19) ou lógica de negócio (V9, preço vindo do cliente). Isso é uma lição real de SAST: **ferramenta pega presença de padrão ruim, não ausência de controle**. Por isso o pipeline combina SAST + DAST + revisão + testes de autorização (Q10).

---

## 3. O código corrigido e o falso positivo (lição de triagem)

O Semgrep reporta **1 achado** no código corrigido, em `App.jsx:55`:

```jsx
const clean = DOMPurify.sanitize(html, { ALLOWED_TAGS: [...] });
return <div dangerouslySetInnerHTML={{ __html: clean }} />;
```

Isto é um **falso positivo**. A regra detecta o padrão `dangerouslySetInnerHTML`, mas o valor injetado (`clean`) **já foi sanitizado** por `DOMPurify.sanitize()` duas linhas acima. Uma regra baseada em linha não enxerga esse fluxo de dados entre linhas.

Este é exatamente o tipo de achado que um analista **tria e fecha** como aceito, documentando a justificativa — e ilustra por que "quantidade de findings" é uma métrica ruim: o valor está em separar o positivo real do ruído. Ferramentas com análise de *taint/dataflow* (como o SonarQube nas regras de segurança, ou o modo Pro do Semgrep) rastreiam a origem da variável e suprimem esse caso automaticamente.

**Resultado após triagem: 0 vulnerabilidades reais no código corrigido.**

---

## 4. Comparação visual

```
ERROR    ██████████████ 7   →  █ 1(FP)
WARNING  ████████████ 6      →  0
         antes                depois
```

Todas as 6 falhas de severidade ERROR reais (V1, V2/V6, V12/V13, V14, V15) e as 6 WARNING (V3, V5, V11, V16, V17, V20) foram eliminadas pelas correções da Parte 2. O achado restante é ruído de ferramenta, não vulnerabilidade.

---

## 5. Como reproduzir a varredura

```bash
# instalar
pip install semgrep

# rodar as regras customizadas (incluídas: rules.yml) sobre cada base
semgrep --config=rules.yml ./vulneravel
semgrep --config=rules.yml ./corrigido

# ou, num projeto real, usar os rulesets públicos do registry:
semgrep --config=p/owasp-top-ten --config=p/javascript --config=p/nodejs .
```

Saídas geradas nesta análise: `vulneravel-results.json`, `corrigido-results.json` e os equivalentes `.sarif` (formato que o GitHub Security e o Sonar importam).

---

## 6. Configs de CI entregues (para o repositório)

Estes arquivos plugam a análise contínua no seu repositório GitHub. Cobrem o **Q10 (pipeline DevSecOps)** com ferramentas reais.

### 6.1 `.github/dependabot.yml` — SCA / OWASP A06

Monitora `npm` do backend e do frontend + as GitHub Actions, abre PRs semanais de atualização e alerta sobre CVEs. Agrupa patches menores para reduzir ruído. Teria pego dependências vulneráveis (A06) — a categoria que o SAST de código próprio não cobre.

### 6.2 `.github/workflows/security.yml` — pipeline

Três jobs em push/PR/agenda semanal:
- **semgrep** — SAST com `p/owasp-top-ten`, `p/javascript`, `p/nodejs`; envia SARIF para a aba Security do GitHub. Pega V1, V2/V6, V15 etc.
- **dependency-audit** — `npm audit --audit-level=high` no backend e frontend; falha o build em CVE alto (complementa o Dependabot).
- **sonarcloud** — análise de qualidade + segurança com Quality Gate que barra o PR se introduzir bug/vulnerabilidade nova.

### 6.3 `sonar-project.properties` — SonarCloud/SonarQube

Define `projectKey`, fontes (`backend,frontend`), exclusões (`node_modules`, `dist`), caminho de cobertura e `qualitygate.wait=true` (o pipeline espera o veredito do gate).

**Setup necessário no seu lado:** adicionar o secret `SONAR_TOKEN` no repositório (Settings → Secrets), criar o projeto no SonarCloud com a `organization` correta, e ativar o Dependabot em Settings → Code security. Sem isso, o job do Sonar falha por falta de credencial — comportamento esperado.

---

## 7. Mapeamento ferramenta → etapa do pipeline (Q10)

| Etapa | Ferramenta (config entregue) | Vs que pega |
|---|---|---|
| Pre-commit | Gitleaks + ESLint security (local) | V1, V15 |
| Build | **Semgrep** (`security.yml`) + **npm audit** + **Dependabot** | V2, V6, V3, V16, V17, V20 + A06 |
| Test | Testes de autorização (ownership/role) | V7, V10, V14, V9 |
| Deploy | **SonarCloud** Quality Gate + DAST (ZAP) | regressões + V11, V15, V16, V19 |
| Runtime | WAF + SIEM (Q9c) | V2, V6, V10, V18 |

---

## 8. Limitações e metodologia (transparência)

Para que este relatório seja avaliado corretamente, é importante ser explícito sobre **como** a análise foi executada e o que não foi feito:

**O que rodou de fato:** a varredura SAST foi executada com **Semgrep 1.176.1**, rodando localmente. Os números (13 achados no código vulnerável, 1 no corrigido) são reais, gerados por execução da ferramenta — não são estimativas.

**Regras customizadas, não o registry oficial:** o ambiente de execução não teve acesso ao registry do Semgrep (`semgrep.dev` retornou HTTP 403), então os rulesets públicos (`p/owasp-top-ten`, `p/javascript`, `p/nodejs`) **não puderam ser baixados**. A varredura usou **11 regras escritas manualmente** (`analise-seguranca/rules.yml`), desenhadas para casar com os padrões das vulnerabilidades V1–V20 do exercício. Consequência honesta: este SAST **não é uma auditoria por ferramenta independente com regras de terceiros** — é um harness de verificação construído para confirmar a presença/ausência dos padrões conhecidos. Os rulesets oficiais rodam automaticamente no CI (`.github/workflows/security.yml`), onde o `semgrep.dev` é acessível.

**SonarQube/SonarCloud: configurado, não executado.** O Sonar **não rodou** nesta análise. Ele exige um servidor (SonarQube) ou o serviço hospedado (SonarCloud) com autenticação via `SONAR_TOKEN` — nenhum disponível neste ambiente. O que foi entregue do lado do Sonar é apenas a **configuração** (`sonar-project.properties` e o job `sonarcloud` no workflow), pronta para executar quando o repositório for subido e o token configurado.

**Limitação intrínseca do SAST:** ferramentas de análise estática detectam *presença* de padrão inseguro, não *ausência* de controle. Por isso V4, V7, V8, V9, V10, V18 e V19 (falhas de "falta algo": sem ownership check, sem rate limit, sem helmet) não aparecem no scan. Essa lacuna é coberta na Tarefa 1 (DAST dinâmico, que testa o comportamento em runtime) e no desenho do pipeline (Q10), que combina SAST + SCA + DAST + testes de autorização.

**Validação dinâmica complementar:** a validação por DAST (subir o servidor e atacá-lo de verdade) foi feita como Tarefa 1, num pacote separado, e confirma dinamicamente o antes/depois — inclusive as falhas de ausência de controle que o SAST não pega.

---

*Fim do relatório comparativo.*
