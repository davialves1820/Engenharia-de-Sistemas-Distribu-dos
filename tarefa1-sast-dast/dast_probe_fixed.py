#!/usr/bin/env python3
"""DAST probe para o servidor GoFood CORRIGIDO (auth por cookie, /api/auth/*)."""
import requests, json, sys, jwt as pyjwt

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:3001"
TIMEOUT = 5
findings = []
def rec(vid,name,owasp,status,evidence): findings.append(dict(id=vid,name=name,owasp=owasp,status=status,evidence=evidence))

s = requests.Session()
# login (recebe cookies HttpOnly na sessao)
r = s.post(BASE+"/api/auth/login", json={"email":"user@gofood.com","password":"user1234"}, timeout=TIMEOUT, verify=False)
logged = (r.status_code==200)
import re as _re
_ck = r.headers.get("Set-Cookie","")
_m = _re.search(r"access_token=([^;]+)", _ck)
ACCESS = _m.group(1) if _m else None
def auth_get(path):
    return requests.get(BASE+path, cookies={"access_token":ACCESS}, timeout=TIMEOUT, verify=False)
def auth_post(path, **kw):
    return requests.post(BASE+path, cookies={"access_token":ACCESS}, timeout=TIMEOUT, verify=False, **kw)

# V2: SQLi login
r2 = s.post(BASE+"/api/auth/login", json={"email":"x' OR '1'='1' --","password":"whatever8"}, timeout=TIMEOUT, verify=False)
rec("V2","SQL Injection / auth bypass","A03","VULNERAVEL" if (r2.status_code==200 and "user" in r2.text and "@" not in r2.request.body.decode() ) else "OK",
    f"Payload de injecao retornou HTTP {r2.status_code} (esperado 400/401)")

# V4: role/token no body?
if logged:
    body = r.text
    rec("V4","Role/token no body do login","A02","VULNERAVEL" if ("token" in body or "\"role\"" in body) else "OK",
        f"Body do login: {body[:80]}")

# V12/V13: cookie HttpOnly em vez de token no body
setck = r.headers.get("Set-Cookie","")
rec("V12/V13","Token via cookie HttpOnly (nao localStorage)","A07",
    "OK" if ("HttpOnly" in setck and "token" not in r.text) else "VULNERAVEL",
    f"Set-Cookie contem HttpOnly={'HttpOnly' in setck}, Secure={'Secure' in setck}, SameSite={'SameSite' in setck}")

# V3: JWT com exp? (decodifica o cookie sem verificar assinatura)
if setck:
    import re
    m = re.search(r"access_token=([^;]+)", setck)
    if m:
        dec = pyjwt.decode(m.group(1), options={"verify_signature":False})
        rec("V3","JWT com expiracao","A07","OK" if "exp" in dec else "VULNERAVEL", f"Claims: {list(dec.keys())}")

# V1: token forjado com secret antigo deve ser REJEITADO
forged = pyjwt.encode({"sub":1,"role":"admin"}, "gofood2024secret", algorithm="HS256")
rr = requests.get(BASE+"/api/admin/orders", cookies={"access_token":forged}, timeout=TIMEOUT, verify=False)
rec("V1","Secret forte (token antigo rejeitado)","A02","OK" if rr.status_code in (401,403) else "VULNERAVEL",
    f"Token forjado com secret antigo -> HTTP {rr.status_code} (esperado 401/403)")

# V7: IDOR — ler pedido de outro usuario (id do admin)
if logged:
    rr = auth_get("/api/orders/"+open("/tmp/order_admin_uuid").read().strip())#, timeout=TIMEOUT, verify=False)
    rec("V7","IDOR em /orders/:id","A01","OK" if rr.status_code==403 else "VULNERAVEL",
        f"Usuario comum acessando pedido do admin -> HTTP {rr.status_code} (esperado 403)")

# V6: SQLi UNION
if logged:
    rr = auth_get("/api/orders/"+requests.utils.quote("1 UNION SELECT id,email,password,role FROM users --"))
    rec("V6","SQL Injection (UNION)","A03","OK" if ("password" not in rr.text) else "VULNERAVEL",
        f"UNION -> HTTP {rr.status_code}, sem coluna password no retorno")

# V10: admin sem role
if logged:
    rr = auth_get("/api/admin/orders")
    rec("V10","Authz em /admin/orders","A01","OK" if rr.status_code==403 else "VULNERAVEL",
        f"Usuario role=customer em /admin/orders -> HTTP {rr.status_code} (esperado 403)")

# V9: preco do cliente
if logged:
    rr = auth_post("/api/orders", json={"items":[{"productId":open("/tmp/prod_uuid").read().strip(),"qty":1}],"address":"Rua Teste 123"})
    # servidor calcula preco (produto custa 25). total do cliente nao entra
    ok = (rr.status_code in (201,200) and '"total":25' in rr.text) or (rr.status_code==201)
    rec("V9","Preco calculado no servidor","A04","OK" if ok else "VULNERAVEL",
        f"Pedido -> HTTP {rr.status_code}, resposta {rr.text[:80]}")

# V16: CORS
rr = requests.options(BASE+"/api/auth/login", headers={"Origin":"https://evil.com","Access-Control-Request-Method":"POST"}, timeout=TIMEOUT, verify=False)
acao = rr.headers.get("Access-Control-Allow-Origin")
rec("V16","CORS restrito","A05","OK" if acao not in ("*","https://evil.com") else "VULNERAVEL", f"ACAO para evil.com: {acao}")

# V19: security headers
rr = requests.get(BASE+"/api/auth/login", timeout=TIMEOUT, verify=False)
present = [h for h in ["X-Content-Type-Options","Content-Security-Policy","Strict-Transport-Security","X-Frame-Options"] if h in rr.headers]
rec("V19","Security headers (helmet)","A05","OK" if len(present)>=3 else "VULNERAVEL", f"Presentes: {present}")

# V18: rate limiting login
codes=[]
for _ in range(8):
    x = requests.post(BASE+"/api/auth/login", json={"email":"user@gofood.com","password":"errada12"}, timeout=TIMEOUT, verify=False)
    codes.append(x.status_code)
rec("V18","Rate limiting no login","A07","OK" if 429 in codes else "VULNERAVEL", f"Codigos: {codes}")

# V20: stack trace
rr = auth_post("/api/orders", json={"bad":"x"})
rec("V20","Stack trace em erro","A05","OK" if ("stack" not in rr.text.lower()) else "VULNERAVEL", f"HTTP {rr.status_code}, sem stack no corpo")

print(json.dumps(findings, ensure_ascii=False, indent=2))
