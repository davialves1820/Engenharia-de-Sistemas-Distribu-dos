# Tarefa 1 — SAST + DAST no servidor GoFood (antes/depois)

Relatório completo em **TAREFA1-SAST-DAST.md**.

## Conteúdo
- `vuln/` — servidor vulnerável executável (Express + db mock)
- `fixed/` — servidor corrigido executável (Q4–Q7)
- `dast_probe.py` / `dast_probe_fixed.py` — probes DAST (atacam a app rodando)
- `vuln-dast.json` / `fixed-dast.json` — resultados DAST (12/12 vuln → 0/13)
- `rules.yml` — regras Semgrep (SAST)
- `sast-*-results.json` — resultados SAST (13 → 0)

## Rodar
```bash
cd vuln && npm install && PORT=3000 node server.js &
python3 ../dast_probe.py http://localhost:3000

cd ../fixed && npm install
env JWT_ACCESS_SECRET=$(openssl rand -hex 32) JWT_REFRESH_SECRET=$(openssl rand -hex 32) \
    NODE_ENV=production PORT=3001 SPA_ORIGIN=https://app.gofood.com node server.js &
python3 ../dast_probe_fixed.py http://localhost:3001
```
Requer Node 18+, Python 3 com `requests` e `pyjwt`, e Semgrep para o SAST.
