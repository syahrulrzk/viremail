<div align="center">

# 🕵️ VIRE — Verified Intelligence & Recon Engine

**`viremail`** · Email Discovery & Domain Intelligence for OSINT

Discover publicly available email addresses from any domain — powered by a
**100% self-built reconnaissance engine**. No third-party data APIs, no paid
services, no API keys.

[Features](#-features) · [Architecture](#-architecture) · [Getting Started](#-getting-started) ·
[API](#-api) · [Contributing](#-contributing) · [License](#-license)

</div>

---

## What is VIRE?

VIRE turns a single domain into a full reconnaissance report:

- every **publicly exposed email address** for that domain,
- its **DNS footprint** (A/AAAA/MX/NS/TXT, SPF, DMARC),
- **subdomains**, **WHOIS** metadata and **mail security posture**,
- even the **people** behind public git commits and mailing-list archives.

Everything runs on **self-built engines** — direct DNS protocol queries, a deep
web crawler, document parsers, local OCR, public search-engine scraping and
SMTP verification — so the tool stays free, transparent and audit-friendly.

> ⚠️ **Responsible use**
> VIRE only collects *publicly available* information. Use it for legitimate
> security research, authorized penetration testing, and education. Respect
> target websites' `robots.txt`, your local laws, and platform terms of service.

---

## ✨ Features

### 🎯 Email Discovery
- **Deep web crawl** — BFS up to depth 2, ~40 pages, prioritizing contact /
  about / team pages (EN + ID keywords), honoring `robots.txt` & `sitemap.xml`
- **`mailto:` extraction** with obfuscation decoding (`\u0040`, HTML entities)
- **security.txt** parsing (`.well-known/security.txt` + fallback)
- **Public documents** — PDF / DOCX / XLSX / TXT / CSV / RTF / MD (bounded)
- **Local OCR** — Tesseract for images & scanned PDFs (self-hosted)
- **Subdomain enumeration** (~60 common names) + crawling of active hosts
- **WHOIS** — registrar, dates, name servers, contact emails
- **Search engines** — DuckDuckGo + Bing, multi-query dorks
- **Wayback Machine** — archived pages often still leak what the live site removed
- **GitHub commit harvesting** & **mailing-list archives** → people/contacts
- **Job portal HRD emails** — polite, ban-averse scraping of public job
  portals (Karir.com, JobStreet, Kalibrr, Glints, …) via search-engine
  discovery; HRD/recruitment addresses are flagged automatically
- **SMTP verification** — RCPT TO probe (**no mail is ever sent**), with
  catch-all & anti-enumeration detection
- **Pattern emails** (info@, admin@, …) — only shown when SMTP-verified as active
- **Parallel scan engine** — web crawl, search engines, Wayback, documents,
  subdomain crawl & SMTP probes all run concurrently (connection-reuse
  sessions), cutting per-domain scan time dramatically

### 🌐 Domain Intelligence
- DNS records: A / AAAA / MX / NS / TXT
- SPF & DMARC checks + mail security posture (MX/SPF/DMARC)
- Google dorking — one-click manual queries for advanced hunting

### 🧬 Deep OSINT (optional mode)
- **BBOT** — `email-enum` preset (crt, pgp, securitytxt, sslcert, …), self-hosted
- **Holehe** — check where a found email is registered (~120 platforms)

### 🧠 VIRE Atlas — Knowledge Graph
- Scan results are no longer a single JSON blob — they are normalized into a
  **knowledge model**: `atlas_domains`, `atlas_emails`, `atlas_sources`,
  `atlas_relationships` (graph edges: who → email → source), subdomains, DNS,
  certificates, documents, technologies, history & more
- Every entity has its own lifecycle (`first_seen` / `last_seen`) and can be
  updated independently; scans and the knowledge base are fully separated
- **Scan** (process) vs **Atlas** (intelligence) — jobs, progress, tasks & results
  live in `models/scan/` + `models/worker/`, the normalized knowledge in
  `models/atlas/`

### 🛡️ Built-in Safety
- **SSRF guard** on every HTTP fetch — private/loopback/cloud-metadata hosts are
  blocked before connecting, including through redirects
- Rate, size & time budgets on every source — no runaway scans
- Neutral SMTP sender — VIRE never impersonates the scanned domain
- No third-party data APIs — the engine is fully auditable

---

## 🏗️ Architecture

```
┌─────────────┐      ┌──────────────┐      ┌──────────────────────────────┐
│   Browser   │ ───► │  Next.js UI  │ ───► │  FastAPI (REST /api/v1)      │
│  dashboard  │      │  :3000       │      │  :8000                       │
└─────────────┘      └──────────────┘      └──────────────┬───────────────┘
                                                          │ POST /search/domain
                                                          ▼
                                                ┌──────────────────────┐
                                                │ Celery + Redis queue │
                                                └──────────┬───────────┘
                                                           ▼
                                                ┌──────────────────────┐
                                                │  Recon worker        │
                                                │ (self-built engines) │
                                                └──────────────────────┘
```

- **Next.js** — single-page dashboard (TailwindCSS + shadcn/ui)
- **FastAPI** — REST API, sync handlers run in a threadpool
- **Celery + Redis** — async scan queue with hard time budgets
- **PostgreSQL** — persistence & migrations (Alembic)

---

## 📁 Project Structure

```
viremail/
├── backend/                      # FastAPI + Celery worker
│   ├── app/
│   │   ├── api/v1/endpoints/     # REST endpoints (search, auth, apikeys, webhooks)
│   │   ├── core/                 # config, celery app
│   │   ├── db/                   # SQLAlchemy session
│   │   ├── models/               # database models — organized by domain
│   │   │   ├── auth/             #   user, organization, team, api_key, audit_log…
│   │   │   ├── scan/             #   scan, scan_job, scan_task, scan_progress…
│   │   │   ├── worker/           #   worker, worker_job, worker_queue, worker_log
│   │   │   ├── atlas/            #   🧠 knowledge graph (12 tables)
│   │   │   │                     #   domain, email, source, relationship, subdomain…
│   │   │   └── source.py         #   connector registry (17 seeded sources)
│   │   ├── services/             # atlas_service.py — writes/reads the knowledge base
│   │   └── tasks/                # recon engine 🧠
│   │       ├── domain_tasks.py   #   domain scan (parallel, all source connectors)
│   │       └── portals.py        #   job-portal HRD hunting (polite scraping)
│   ├── alembic/                  # database migrations
│   ├── main.py                   # FastAPI entrypoint
│   └── requirements.txt
├── frontend/                     # Next.js dashboard
│   └── src/
│       ├── app/                  # page.tsx (SPA), layout, globals.css
│       ├── components/ui/        # shadcn/ui primitives
│       └── lib/
├── docker-compose.yml            # PostgreSQL + Redis
├── start.sh / stop.sh            # dev orchestration
├── example.env                   # environment template
└── prd.md                        # product requirements & roadmap
```

The heart of the tool is `backend/app/tasks/` — `domain_tasks.py` (all
self-built domain connectors: DNS, crawl, documents, OCR, WHOIS, search,
wayback, SMTP, …) and `portals.py` (polite job-portal HRD hunting). Scan
results are persisted to the VIRE Atlas knowledge graph via
`app/services/atlas_service.py`. Great starting point for contributors.

---

## 🚀 Getting Started

### Prerequisites
- Docker (for PostgreSQL + Redis)
- Python 3.10+
- Node.js 18+
- Optional: `tesseract-ocr` (local OCR), `pipx` + `bbot` + `holehe` (Deep OSINT)

### Option A — Scripts (quickest)
```bash
./start.sh     # starts docker-compose, backend, celery worker & frontend
./stop.sh      # stops app services (keeps the databases running)
```

### Option B — Manual

**1. Infrastructure**
```bash
docker compose up -d        # PostgreSQL + Redis
```

**2. Backend**
```bash
cd backend
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp ../example.env ../.env    # then edit .env to match your setup
alembic upgrade head         # create the database tables
uvicorn main:app --host 0.0.0.0 --port 8000
```

**3. Celery worker** (separate terminal)
```bash
cd backend && source venv/bin/activate
celery -A app.core.celery_app worker --loglevel=info
```

**4. Frontend**
```bash
cd frontend
npm install
npm run dev    # serve on http://localhost:3000
# To reach the API from another device, set NEXT_PUBLIC_API_URL
# to the backend's LAN/domain address, e.g. http://192.168.1.10:8000/api/v1
```

Open the dashboard and scan your first domain 🎉.

---

## 🔌 API

### `POST /api/v1/search/domain`

```bash
curl -X POST http://localhost:8000/api/v1/search/domain \
  -H 'Content-Type: application/json' \
  -d '{"domain": "example.com", "mode": "deep"}'
```

| Field     | Type    | Description                                            |
|-----------|---------|--------------------------------------------------------|
| `domain`  | string  | **required** — the domain to scan (e.g. `example.com`) |
| `mode`    | string  | `quick` \| `smart` \| `deep` (default `smart`) — engine subset & time budget |
| `deep`    | boolean | legacy alias — `true` forces `mode="deep"` (BBOT + Holehe) |
| `force`   | boolean | skip the Atlas cache and re-scan from scratch           |
| `sources` | array   | optional — subset of engines, e.g. `["dns","smtp"]`    |

The response includes `emails` (with source & SMTP status), `email_stats`,
`smtp_check`, `dns_records`, `spf`, `dmarc`, `security_posture`,
`security_txt`, `crawl_stats`, `doc_stats`, `ocr_stats`, `subdomains`,
`whois`, `people`, `jobportal_stats`, `deep_osint`, `search_stats`,
`confidence_score` and `timings`.

### `POST /api/v1/search/jobportal` — HRD Hunter (bulk)

Hunt HRD / recruitment emails across public job portals for many companies at
once. Discovery is done via public search-engine dorks, fetches are
rate-limited per host with jitter, `robots.txt` is honored and LinkedIn is
never fetched directly (anti-bot) — designed to be ban-averse.

```bash
curl -X POST http://localhost:8000/api/v1/search/jobportal \
  -H 'Content-Type: application/json' \
  -d '{"keyword": "software engineer", "location": "jakarta"}'
```

| Field      | Type    | Description                                   |
|------------|---------|-----------------------------------------------|
| `keyword`  | string  | **required** — job / company keyword          |
| `location` | string  | optional city / region filter                 |
| `max_pages`| integer | listing pages to check (5–60, default 20)     |

Interactive docs: `http://localhost:8000/docs` (Swagger UI).

---

## ⚙️ Configuration

All backend settings live in `.env` (see [`example.env`](example.env)):

| Variable                   | Default                        | Description                              |
|----------------------------|--------------------------------|------------------------------------------|
| `POSTGRES_SERVER` / `_USER` / `_PASSWORD` / `_DB` / `_PORT` | `localhost` / `osintmail` / … | PostgreSQL connection |
| `REDIS_HOST` / `REDIS_PORT` | `localhost` / `6379`           | Redis (Celery broker)                    |
| `SECRET_KEY`               | dev default (change!)          | JWT secret for future auth               |
| `GITHUB_TOKEN`             | —                              | Optional: raise GitHub commit-search rate limits |
| `SMTP_VERIFY_ENABLED`      | `false` (default off)          | SMTP RCPT-TO active-mailbox check — off by default: the tool collects emails *found on the internet* as references, so inactive addresses are still useful. Enable only when you need active-mailbox filtering (slower scans) |
| `OCR_ENABLED`              | `true`                         | Toggle local Tesseract OCR               |
| `DEEP_TOOLS_ENABLED`       | `true`                         | Toggle BBOT + Holehe (deep mode)         |
| `PORTAL_SCRAPING_ENABLED`  | `true`                         | Toggle job-portal HRD scraping           |
| `PORTAL_MIN_DELAY`         | `2.0`                          | Min seconds between requests to the same host |
| `PORTAL_JITTER`            | `2.5`                          | Extra random delay (0..jitter) per request  |
| `PORTAL_HOST_CAP`          | `40`                           | Max requests per host per scan           |
| `BACKEND_CORS_ORIGINS`     | localhost + LAN list           | JSON list of allowed frontend origins    |

Frontend: `NEXT_PUBLIC_API_URL` (defaults to `http://localhost:8000/api/v1`).

---

## 🧪 Deep OSINT Tools (optional)

```bash
pipx install bbot
pipx install holehe
# OCR (Linux)
sudo apt install tesseract-ocr
```

BBOT's first run downloads wordlists to `~/.bbot`, so the first deep scan can
take longer.

---

## 🗺️ Roadmap

- ✅ SMTP verification (RCPT-TO probe), catch-all & anti-enumeration detection
- ✅ Public document extraction + local OCR (Tesseract)
- ✅ Subdomain enumeration + WHOIS lookup
- ✅ Multi-engine search scraping (DuckDuckGo + Bing) + Wayback Machine
- ✅ Deep OSINT mode (BBOT + Holehe)
- ✅ Job-portal HRD email hunting (polite, ban-averse scraping)
- ✅ Parallel scan engine (crawl, search, wayback, docs, SMTP run concurrently)
- ✅ VIRE Atlas knowledge graph (scan ⇄ knowledge separated, graph edges)
- ⏳ Real authentication (JWT) & user dashboards
- ⏳ Certificate transparency / TLS certificate analysis / RDAP
- ⏳ Website technology detection & ASN lookup
- ⏳ WebSocket live updates & graph visualization
- ⏳ Scheduled scans, notifications & export (CSV/PDF/JSON)

See [`prd.md`](prd.md) for the full product plan.

---

## 🤝 Contributing

We welcome contributors of all levels — this project is built to be extended!

### Ways to contribute
- **Report bugs** — open an issue with steps to reproduce
- **Request features** — open an issue with a use case
- **Add source connectors** — new engines are just functions in
  `backend/app/tasks/domain_tasks.py` (keep them < ~100 LOC and bounded)
- **Improve the UI** — the dashboard is a single React page
  (`frontend/src/app/page.tsx`) + Tailwind theme (`globals.css`)
- **Write tests** — unit tests for parsers, email extraction, DNS helpers…

### Workflow
1. **Fork** the repository and clone it locally.
2. Create a branch with a descriptive name:
   ```bash
   git checkout -b feat/add-rdap-connector
   ```
3. Make your changes. Keep them **small and focused**; follow the existing
   style (the codebase is heavily commented — match that).
4. Validate before submitting:
   ```bash
   # frontend
   cd frontend && npx tsc --noEmit && npx eslint src
   # backend
   cd backend && python -m compileall -q app main.py
   ```
5. Open a **Pull Request** with a clear description of what & why, and any
   testing you did. Mention `closes #issue` when applicable.

### Guidelines
- Keep PRs reviewable: one logical change per PR.
- No third-party data APIs: connectors must stay self-built (that's the point!).
- Always bound work (max pages, timeouts, size caps) — the scan has a hard
  global budget.
- Respect target sites (robots.txt) and add SSRF guards to any new fetcher.

---

## 📄 License

Distributed under the [MIT License](LICENSE). See `LICENSE` for details.

---

<div align="center">
Made with ❤️ for the OSINT community — <b>stay legal, stay curious</b>
</div>
