# Tarefa 1 — SAST e DAST no servidor GoFood (antes e depois)

**Objetivo:** aplicar análise estática (SAST) e dinâmica (DAST) no código do servidor GoFood, comparando o estado **antes** (código vulnerável do exercício) e **depois** (código corrigido nas Q4–Q7).

**Ferramentas:**
- **SAST:** Semgrep 1.176.1 (regras customizadas para os padrões V1–V20).
- **DAST:** servidores subidos localmente (Express + banco mockado) e sondados com um probe HTTP em Python que executa os vetores de ataque reais e avalia as respostas. Alvo sempre `localhost` — nenhum sistema de terceiros foi tocado.

> **Metodologia honesta.** O DAST aqui é um *probe* dirigido (não o ZAP completo): sobe a aplicação de verdade e dispara requisições reais — SQLi, IDOR, token forjado, brute-force, etc. — verificando o comportamento do servidor vivo. Isso é DAST de fato (teste dinâmico caixa-preta contra a app rodando), ainda que mais enxuto que uma varredura automatizada de mercado. Para uma varredura completa em produção usaria-se OWASP ZAP; o comando está no fim.

---

## 1. Resultado consolidado

| Análise | Servidor vulnerável (antes) | Servidor corrigido (depois) |
|---|---|---|
| **SAST** (Semgrep) | 13 achados (7 ERROR, 6 WARNING) | 0 reais (1 falso positivo triado) |
| **DAST** (probe dinâmico) | **12 / 12 vetores exploráveis** | **0 / 13 — todos bloqueados** |

O DAST é a evidência mais forte: não diz "o código *parece* vulnerável", diz "eu **ataquei** o servidor e o ataque **funcionou**" — e, depois, "ataquei de novo e o servidor **rejeitou**".

---

## 2. DAST — antes (servidor vulnerável, `localhost:3000`)

Cada linha é um ataque real executado contra a aplicação rodando, com a resposta HTTP observada:

| V | OWASP | Ataque executado | Resultado (vulnerável) |
|---|---|---|---|
| V2 | A03 | `POST /api/login` com `email = ' OR '1'='1' --` | **HTTP 200, token com `role=admin`** — bypass de autenticação |
| V1 | A02 | Token JWT forjado com o secret `gofood2024secret` | **Aceito** em `/api/admin/orders` (HTTP 200) |
| V3 | A07 | Inspeção do JWT emitido | Sem claim `exp` — token eterno |
| V4 | A02 | Leitura do corpo da resposta de login | `token` e `role` expostos no body |
| V7 | A01 | Usuário comum (id=2) pede `/api/orders/2` (pedido do admin) | **HTTP 200** — leu pedido alheio (IDOR) |
| V6 | A03 | `/api/orders/1 UNION SELECT id,email,password,role FROM users --` | **Retornou coluna `password`** dos usuários |
| V10 | A01 | Token de `role=customer` acessa `/api/admin/orders` | **HTTP 200** — painel admin liberado |
| V9 | A04 | `POST /api/orders` com item `price=0` | **HTTP 200** — preço do cliente aceito |
| V16 | A05 | Preflight CORS com `Origin: https://evil.com` | `Access-Control-Allow-Origin: *` |
| V19 | A05 | Inspeção de headers | Sem HSTS, sem X-Frame-Options, `X-Powered-By: Express` exposto |
| V18 | A07 | 12 logins seguidos com senha errada | Nenhum HTTP 429 — brute-force livre |
| V20 | A05 | `POST /api/orders` com corpo inválido | Resposta de erro contém `stack` (traceback) |

**12 de 12 vetores exploráveis.** O único item não testado dinamicamente foi V15 (XSS armazenado), que é do frontend, não do servidor — coberto no SAST/exercício.

---

## 3. DAST — depois (servidor corrigido, `localhost:3001`)

Mesmos ataques, contra o servidor com as correções das Q4–Q7:

| V | Ataque | Resultado (corrigido) |
|---|---|---|
| V2 | SQLi no login | **HTTP 400** — input rejeitado pela validação Zod |
| V1 | Token forjado com secret antigo | **HTTP 401** — assinatura inválida (secret via env) |
| V3 | Inspeção do JWT | Claims incluem `exp` — token expira em 15 min |
| V4 | Corpo do login | Só `{user:{id,email}}` — sem token nem role |
| V12/V13 | Inspeção do `Set-Cookie` | `HttpOnly=True, Secure=True, SameSite=Strict` |
| V7 | IDOR no pedido do admin | **HTTP 403** — ownership check barra |
| V6 | UNION SELECT | **HTTP 400** — sem coluna `password`; query parametrizada |
| V10 | Customer em `/admin/orders` | **HTTP 403** — `requireRole('admin')` barra |
| V9 | Pedido com preço do cliente | **HTTP 201** com `total` calculado no servidor (produto = 25) |
| V16 | CORS de `evil.com` | `Allow-Origin: https://app.gofood.com` — origem restrita |
| V19 | Headers | CSP, HSTS, X-Frame-Options, X-Content-Type-Options presentes (helmet) |
| V18 | Brute-force | **HTTP 429** após 3 tentativas — rate limiter ativo |
| V20 | Erro | HTTP 400 sem stack no corpo |

**0 de 13 — todos os ataques bloqueados.** Cada correção foi validada dinamicamente contra o servidor vivo, não apenas por leitura de código.

---

## 4. Destaques (prova viva do antes/depois)

**Bypass de autenticação (V2)** — o mesmo request, dois servidores:
```
# ANTES:  email = "' OR '1'='1' --"  →  HTTP 200 {"role":"admin", "token":"eyJ..."}
# DEPOIS: mesmo payload             →  HTTP 400 {"error":"Dados inválidos"}
```

**Escalação de privilégio (V10)** — token de cliente comum em rota de admin:
```
# ANTES:  GET /api/admin/orders (role=customer)  →  HTTP 200  [lista de pedidos]
# DEPOIS: GET /api/admin/orders (role=customer)  →  HTTP 403  {"error":"Acesso negado"}
```

**Manipulação de preço (V9)** — comprar por R$0:
```
# ANTES:  items:[{price:0, qty:1}]  →  HTTP 200 {"success":true}   (aceito!)
# DEPOIS: preço ignorado; servidor busca no catálogo  →  HTTP 201 {"total":25}
```

---

## 5. SAST — resumo (detalhe no relatório da Tarefa 2)

O Semgrep confirmou estaticamente 13 achados no código vulnerável e 0 reais no corrigido (1 falso positivo de `dangerouslySetInnerHTML` já sanitizado por DOMPurify, triado). A limitação conhecida: SAST não pega *ausência* de controle (V7, V10, V18) — e é exatamente aí que o **DAST brilha**, pois testa o comportamento em runtime. As duas técnicas se complementam: juntas cobrem os 20 marcadores.

---

## 6. Como reproduzir

```bash
# subir o servidor vulnerável e rodar o DAST (tudo local)
cd vuln && npm install && PORT=3000 node server.js &
python3 dast_probe.py http://localhost:3000

# subir o servidor corrigido (precisa de secrets no ambiente) e rodar o DAST
cd fixed && npm install
env JWT_ACCESS_SECRET=$(openssl rand -hex 32) JWT_REFRESH_SECRET=$(openssl rand -hex 32) \
    NODE_ENV=production PORT=3001 SPA_ORIGIN=https://app.gofood.com node server.js &
python3 dast_probe_fixed.py http://localhost:3001

# SAST
semgrep --config=rules.yml vuln
semgrep --config=rules.yml fixed

# DAST completo de mercado (opcional), contra a instância local:
docker run -t ghcr.io/zaproxy/zaproxy zap-baseline.py -t http://localhost:3000
```

---

*Nota: os servidores usam um banco em memória mockado para permitir a execução — a lógica de autenticação, autorização, validação e montagem de query é a real do exercício. Os resultados de DAST refletem o comportamento verdadeiro desse código.*
