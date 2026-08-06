# PRD — OSINTMail
Version: 1.4 (MVP — Email Discovery + Deep Search + HRD Hunter + Atlas Knowledge Graph)

## 1. Overview

OSINTMail adalah platform OSINT (Open Source Intelligence) untuk menemukan alamat email publik berdasarkan sebuah domain.

Fokus utama v1.1: **Domain → Email Discovery** dengan engine 100% self-built (tanpa integrasi API pihak ketiga). Pencarian berdasarkan email address maupun username yang sebelumnya hanya berupa stub (data palsu) telah **dihapus** di v1.1.

Tujuan utama adalah membantu SOC, Security Analyst, Pentester, Blue Team, Red Team, dan IT Administrator menemukan jejak digital yang tersedia secara publik tanpa bergantung pada API berbayar.

## 2. Goals

- Platform 100% dapat berjalan tanpa API pihak ketiga.
- Modular source connector.
- Cepat, scalable, dan mudah dikembangkan.
- Multi-user dengan API Key.
- Dashboard modern.

## 3. Target Users

- Security Operation Center (SOC)
- Pentester
- Bug Hunter
- Blue Team
- Red Team
- IT Administrator
- Digital Forensic Investigator

## 4. Core Features

### Email Search 🗑️ (Dihapus di v1.1)

> **Status: DIHAPUS.** Endpoint `POST /api/v1/search/email` sebelumnya hanya stub dengan data palsu (fake) dan tidak pernah diimplementasikan secara nyata. Mulai v1.1 endpoint ini dihapus. Pemeriksaan terkait email (MX, SPF, DMARC) sekarang menjadi bagian dari **Domain Search**. Ke depannya bisa dihadirkan kembali sebagai fitur verifikasi email yang murni self-built (cek DNS + SMTP probe) — bukan sebagai stub.

### Domain Search ✅ (Fitur utama v1.1)

Input:

- example.com

Output (sudah diimplementasikan):

- DNS Records: A, AAAA, MX, NS, TXT
- SPF & DMARC
- Email Discovery (engine self-built, tanpa API pihak ketiga):
  - **Emails (observed)** — email yang benar-benar terpublikasi: hasil web crawl, ekstraksi `mailto:`, security.txt, dokumen publik, OCR, subdomain, WHOIS, dan referensi search engine. Inilah yang dihitung sebagai "email ditemukan".
  - 🗑️ **Suggestions / pola tebakan — DIHAPUS di v1.1.1** atas permintaan user: hasil generate pola (info@, admin@, dll) tidak diverifikasi dan menyesatkan.
  - ✅ **Pola email terverifikasi (v1.2)** — pola umum (info@, admin@, dll) di-generate ulang, tetapi **hanya yang lolos verifikasi SMTP (`ok`) yang ditampilkan**, dengan label sumber "Pola (SMTP ✓)". Tanpa MX / MX tidak bisa dihubungi / mail server catch-all → tidak ada pola sama sekali. Tidak ada tebakan yang tidak diverifikasi.
- security.txt (/.well-known/security.txt + fallback /security.txt)
- robots.txt (diparse & dihormati saat crawl)
- sitemap.xml (termasuk sitemap index / nested)
- **Deep crawl (v1.2)**: BFS sampai depth 2, hingga ~40 halaman, keyword kontak EN+ID (kontak/hubungi/tentang/karir/profil/tim)
- **Public document extraction (v1.2)**: PDF/DOCX/XLSX/TXT/CSV/RTF/MD (max 10 dokumen, cap 3MB)
- **OCR lokal (v1.2)**: Tesseract (self-hosted) untuk gambar (JPG/PNG/WebP/BMP, max 5) & PDF scan (render max 5 halaman, hanya PDF tanpa text-layer). Flag `OCR_ENABLED` untuk nonaktif.
- **Subdomain enumeration (v1.2)**: DNS brute-force ~60 nama umum (concurrent), host aktif di-crawl (max 5)
- **WHOIS lookup (v1.2)**: registrar, tanggal, name servers, email kontak (public whois protocol, tanpa API)
- **Deep OSINT tools (v1.3, mode opsional)**: checkbox "Deep OSINT" di frontend → jalanin **BBOT** (email-enum preset: subdomain + email via crt/pgp/securitytxt/sslcert dll, self-hosted, `--no-deps`; max 15 email di-merge) & **Holehe** (cek jejak akun email di ~120 platform). Tanpa API key. Scan deep bisa 3-5 menit. Catatan: run BBOT pertama kali mendownload wordlist ke `~/.bbot` (bisa bikin scan pertama lebih lama).
- **Job Portal HRD emails (v1.4)**: source baru `jobportal` di dalam scan domain — discovery listing via search-engine dork (`site:karir.com …`), fetch listing dengan polite scraping (rate-limit per host + jitter, rotasi User-Agent, hormati robots.txt, cap request per host), **LinkedIn sengaja tidak di-fetch langsung** (anti-bot brutal — hanya diambil jika muncul di hasil search engine). Email HRD/recruitment (hr@, recruitment@, people@, dsb) ditandai otomatis. Aman tanpa banned.
- **Parallel scan engine (v1.4)**: web crawl (fetch paralel + keep-alive session), search engine DDG + Bing barengan, Wayback snapshots, dokumen publik, crawl subdomain, dan SMTP probe (pool kecil dengan shared budget) semuanya berjalan konkuren → waktu scan per domain turun drastis.
- **VIRE Atlas knowledge graph (v1.4)**: hasil scan tidak lagi disimpan sebagai 1 blob JSON — dipecah menjadi knowledge model ternormalisasi (`atlas_domains`, `atlas_emails`, `atlas_sources`, `atlas_relationships`, dll, 12 tabel). Konsep **Scan** (proses: job/progress/status) dipisah dari **Atlas** (intelligence: hasil yang sudah dinormalisasi & di-cache). Setiap entity punya lifecycle sendiri (first_seen/last_seen), update independen, dan siap untuk graph visualization.
- Referensi search engine publik — **multi-query (v1.2)**: Bing (RSS) & DuckDuckGo (HTML POST), 3-4 variasi dork per engine
- Google dorking manual — query siap-pakai (`site:"@domain" email`, dll) yang dibuka di browser user sendiri; Google memblokir scraping otomatis, jadi dork dijalankan manual
- Verifikasi SMTP per email (RCPT TO probe ke mail server — tanpa mengirim email): status **aktif / tidak ada / tak tentu**, plus deteksi mail server catch-all, sender netral (noreply@example.org), budget waktu 45 detik/scan — **default OFF sejak v1.4.1** (`SMTP_VERIFY_ENABLED=false`): tujuan utama app adalah mengumpulkan email yang **pernah muncul di internet** sebagai rujukan, jadi email non-aktif pun tetap berguna dan tidak perlu diverifikasi. Aktifkan kembali hanya jika butuh filter mailbox aktif (scan lebih lama)
- Security posture (MX/SPF/DMARC terdeteksi atau tidak)
- Recon stats (halaman di-crawl, subdomain, dokumen, OCR, hasil search, timing)
- Confidence score

Belum diimplementasikan (roadmap):

- Certificate Transparency
- TLS Certificate analysis
- ASN lookup
- Website Technology detection

### Username Search 🗑️ (Dihapus di v1.1)

> **Status: DIHAPUS.** Endpoint `POST /api/v1/search/username` sebelumnya berupa stub dengan hasil dummy (hardcoded) dan belum pernah diimplementasikan secara nyata. Mulai v1.1 endpoint ini dihapus agar tidak menyesatkan pengguna. Jika nanti diimplementasikan, akan memakai HTTP probe self-built (cek status halaman profil publik) — bukan data dummy.

## 5. Dashboard

- Overview
- Recent Scan
- Queue Status
- Worker Status
- Search History
- API Usage
- Statistics

## 6. API

### Search Endpoints

POST /api/v1/search/domain      ✅ Aktif — email discovery & domain intelligence
                                (body: {"domain": "example.com", "mode": "quick|smart|deep", "force": false})

POST /api/v1/search/jobportal   ✅ Aktif (v1.4) — HRD Hunter bulk: keyword + lokasi →
                                email HRD dari banyak company via job portal
                                (body: {"keyword": "software engineer", "location": "jakarta", "max_pages": 20})

🗑️ POST /api/v1/search/email      — dihapus di v1.1 (sebelumnya stub data palsu)
🗑️ POST /api/v1/search/username   — dihapus di v1.1 (sebelumnya stub data palsu)

### History & Reports

GET /api/v1/history

GET /api/v1/report/{id}

### API Key Management (Integration)

POST /api/v1/apikeys - Generate new API key
GET /api/v1/apikeys - List user's API keys
DELETE /api/v1/apikeys/{id} - Revoke API key
PUT /api/v1/apikeys/{id} - Update API key (name, scopes, rate limit)
GET /api/v1/apikeys/{id}/usage - View API key usage statistics

### Webhooks (Integration)

POST /api/v1/webhooks - Register webhook endpoint
GET /api/v1/webhooks - List webhooks
DELETE /api/v1/webhooks/{id} - Remove webhook
PUT /api/v1/webhooks/{id} - Update webhook (URL, events, secret)

## 7. Architecture

Frontend

- Next.js
- TailwindCSS
- Shadcn UI
- TanStack Query
- Recharts

Backend

- FastAPI
- SQLAlchemy
- Alembic
- Redis
- Celery

Database

- PostgreSQL

## 8. Data Flow

User

↓

FastAPI

↓

Queue

↓

Worker

↓

Source Connector

↓

Normalizer

↓

Deduplicate

↓

Confidence Score

↓

PostgreSQL

↓

Realtime Dashboard

## 9. Source Connectors (100% Self-Built, Tanpa API Pihak Ketiga)

Prinsip v1.1: **tidak ada integrasi ke aplikasi/layanan lain sebagai sumber data** (tidak ada Hunter.io, tidak ada HaveIBeenPwned/HIBP, tidak ada crt.sh, tidak ada RDAP API, dst). Semua sumber data dibuat sendiri:

- ✅ DNS (A, AAAA, MX, NS, TXT) — query protokol langsung via dnspython
- ✅ Deep Website Crawl — BFS depth 2, ~40 halaman, keyword kontak EN+ID
- ✅ Ekstraksi link `mailto:`
- ✅ robots.txt — parsing + penghormatan rule (`User-agent: *` + strip komentar)
- ✅ sitemap.xml — termasuk sitemap index (recursion, dibatasi)
- ✅ security.txt — /.well-known/security.txt + fallback /security.txt
- ✅ Public Document Crawl — PDF/DOCX/XLSX/TXT/CSV/RTF/MD (max 10, cap 3MB)
- ✅ Local OCR (Tesseract) — gambar & PDF scan, self-hosted, flag OCR_ENABLED
- ✅ Subdomain enumeration — DNS brute-force ~60 nama umum + crawl host aktif
- ✅ WHOIS lookup — public whois protocol (registrar/dates/emails), tanpa API
- ✅ Search engine scraping publik — multi-query: Bing (RSS) & DuckDuckGo (HTML POST)
- ✅ SMTP verification — probe RCPT TO ke mail server domain (tanpa mengirim email), deteksi catch-all, sender netral, budget 45 detik/scan
- ✅ Pattern emails (SMTP-verified only) — pola umum ditampilkan HANYA jika lolos verifikasi `ok`
- ✅ Deep OSINT tools (BBOT email-enum + Holehe footprint) — self-hosted via pipx, mode opsional
- ⏳ RDAP / Certificate Transparency / TLS — belum diimplementasikan

Keamanan: semua request HTTP memakai SSRF guard — host private/loopback/cloud-metadata diblokir sebelum koneksi, termasuk lewat redirect.

## 10. Database

Struktur model dipecah per domain (v1.4):

```
models/
├── auth/      user, organization, team (+team_members), api_key, audit_log, webhook, notification, api_key_usage
├── scan/      scan, scan_job, scan_task, scan_progress, scan_result
├── worker/    worker, worker_job, worker_queue, worker_log
├── atlas/     🧠 Knowledge Graph (12 tabel):
│              atlas_domains, atlas_emails, atlas_sources, atlas_relationships,
│              atlas_subdomains, atlas_dns_records, atlas_certificates,
│              atlas_documents, atlas_persons, atlas_usernames,
│              atlas_technologies, atlas_histories
└── source.py  registry connector (17 source di-seed: website, mailto, careers,
               jobportal, github, wayback, ocr, smtp, …)
```

Tabel lama (scaffold yang tidak terpakai: `domains`, `emails`, `usernames`,
`dns_records`, `certificates`, `technologies`, `scan`, `worker`, dan blob
`vire_atlas`) di-drop di migration `b7c9d1e2f3a4`; data cache `vire_atlas`
lama di-migrate ke `atlas_domains` + `atlas_histories`.

## 11. Security

- JWT Authentication
- API Keys
- API Key Scopes (read, write, admin)
- IP Whitelisting for API Keys
- API Key Expiration
- RBAC
- Audit Log
- Rate Limiting (per user & per API key)
- Input Validation
- Webhook Signature Verification

## 12. Non Functional Requirements

- Async workers
- Horizontal scaling
- Docker support
- REST API
- OpenAPI documentation
- WebSocket live updates

## 13. Roadmap

### Phase 0.5 ✅ COMPLETED (v1.4)
- ✅ Job Portal HRD hunting (polite scraping, tanpa banned)
- ✅ HRD Hunter bulk endpoint
- ✅ Parallel scan engine (percepatan scan per domain)
- ✅ Restructure Atlas → Knowledge Model (auth/ scan/ worker/ atlas/ + source registry)
- ✅ Cache & lookup hasil scan via Atlas history (bukan blob JSON)

### Phase 1 ✅ COMPLETED (dirapikan di v1.1)
- ✅ Authentication (API endpoints structure)
- ✅ Dashboard (Frontend UI — redesain total di v1.1)
- ✅ Queue (Celery + Redis)
- 🗑️ Email Search (API endpoints) — dihapus di v1.1, sebelumnya stub palsu
- ✅ Domain Search (email discovery self-built, tanpa breach check pihak ketiga)
- 🗑️ Username Search (API endpoints) — dihapus di v1.1, sebelumnya stub palsu
- ✅ API Key Management (CRUD endpoints)
- ✅ Webhook Management (CRUD endpoints)

### Phase 2
- Public document crawler
- Technology detection
- Certificate intelligence

### Phase 3
- Graph visualization
- Scheduled scans
- Notifications
- Export CSV/PDF/JSON

### Phase 4
- Optional external connectors
- Multi-tenant SaaS
- Billing
- Plugin SDK

## 13.1 Implementation Status (per v1.1)

### Completed Features
- ✅ Project structure (Next.js + FastAPI)
- ✅ Database models (14 tables)
- ✅ Alembic migrations
- ✅ Docker Compose (PostgreSQL + Redis)
- ✅ Backend API endpoints (auth, search/domain, apikeys, webhooks)
- ✅ Celery async workers
- ✅ Frontend UI dengan TailwindCSS + Shadcn UI (redesain total v1.1)
- ✅ Email discovery engine self-built (v1.1 → v1.2 deep search):
  - ✅ Deep web crawl BFS depth-2 (~40 halaman), keyword kontak EN+ID
  - ✅ robots.txt parsing & penghormatan rule
  - ✅ sitemap.xml parsing (termasuk sitemap index)
  - ✅ security.txt parsing (dengan fallback path)
  - ✅ Public document extraction (PDF/DOCX/XLSX/TXT/CSV/RTF/MD)
  - ✅ Local OCR Tesseract — gambar & PDF scan (self-hosted)
  - ✅ Subdomain enumeration (~60 nama umum) + crawl host aktif
  - ✅ WHOIS lookup (registrar/dates/emails)
  - ✅ Search engine scraping multi-query: Bing (RSS) + DuckDuckGo (HTML POST)
  - ✅ Google dorking manual — query siap-pakai (site: / email: / contact:) dibuka di browser user
  - ✅ Klasifikasi email: hanya email observed (website/mailto/security.txt/search/ocr/subdomain/whois) yang ditampilkan
- 🗑️ Pola email tebakan (suggestions) — DIHAPUS di v1.1.1 (tidak valid, menyesatkan user)
- ✅ Pola email terverifikasi SMTP (v1.2) — pola umum hanya tampil jika lolos probe RCPT TO (`ok`)
- ✅ DNS records analysis (A, AAAA, MX, NS, TXT)
- ✅ SPF/DMARC record checking
- ✅ Security posture (MX/SPF/DMARC) & confidence score
- ✅ SSRF guard di semua HTTP fetch (private/loopback/cloud-metadata diblokir)
- ✅ Endpoint /search/domain sebagai sync handler (tidak memblokir event loop)
- ✅ Single-page frontend: scan animation, recent searches, copy email, hasil terstruktur
- 🗑️ Data breach checking (HaveIBeenPwned) — DIHAPUS di v1.1 (integrasi pihak ketiga)
- 🗑️ Email search & Username search endpoints — DIHAPUS di v1.1 (stub data palsu)
- 🗑️ Auto-detection of search type (frontend) — dihapus, UI sekarang domain-only

### In Progress
- ⏳ Actual authentication implementation (JWT)
- ⏳ Real user registration/login
- ⏳ Dashboard dengan real-time updates

### TODO
- ⏳ Technology detection
- ⏳ Certificate transparency
- ⏳ TLS certificate analysis
- ⏳ ASN lookup
- ⏳ WebSocket live updates
- ⏳ Graph visualization
- ⏳ Scheduled scans
- ⏳ Export functionality
- ✅ SMTP verification (RCPT TO probe ke MX server, tanpa kirim email; deteksi catch-all) — selesai di v1.1.1, **dimatikan default di v1.4.1** (kumpul email sebagai rujukan, tanpa validasi aktif)
- ✅ Public document crawler — selesai di v1.2
- ✅ Local OCR (Tesseract) untuk gambar & PDF scan — selesai di v1.2
- ✅ Subdomain enumeration — selesai di v1.2
- ✅ WHOIS lookup — selesai di v1.2
- ✅ Search engine multi-query — selesai di v1.2
- ✅ Deep crawl BFS depth-2 — selesai di v1.2
- ✅ Deep OSINT tools: BBOT + Holehe (mode opsional) — selesai di v1.3
- ✅ Job Portal HRD emails (source `jobportal`, polite scraping, ban-averse) — selesai di v1.4
- ✅ HRD Hunter bulk endpoint `POST /search/jobportal` (keyword + lokasi) — selesai di v1.4
- ✅ Parallel scan engine (crawl/search/wayback/docs/subdomain/SMTP konkuren) — selesai di v1.4
- ✅ VIRE Atlas knowledge graph (12 tabel, scan⇄atlas dipisah, `atlas_service.py`) — selesai di v1.4
- ✅ Mode scan (`quick|smart|deep`) diterima API & dipakai engine (v1.4)

## 14. Success Metrics

- < 5 detik untuk lookup dasar
- 95%+ job success rate
- Modular connector (<100 LOC per connector)
- Mendukung ribuan scan per hari menggunakan worker terpisah.

## 15. Future Vision

OSINTMail berkembang menjadi platform Email Intelligence dan External Attack Surface Management (EASM) yang menggabungkan email discovery, domain intelligence, asset discovery, serta enrichment OSINT dalam satu dashboard modern.

