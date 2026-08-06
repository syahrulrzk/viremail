"""Job portal scraping for HRD / recruitment emails.

Safety-first design (the goal is *no bans*, so everything here is polite):
  - Discovery through public search engines (DDG HTML + Bing RSS) using
    `site:` dorks — we never hammer portal search endpoints directly.
  - Per-host rate limiting with jittered delays (POLITE window).
  - Rotating User-Agent pool so requests look like a real browser.
  - robots.txt is fetched once per host and honored (Disallow rules).
  - Hard caps: requests per host and total pages fetched per scan.
  - LinkedIn is deliberately NOT fetched directly (aggressive anti-bot +
    login walls). `site:linkedin.com` URLs surfaced by search engines are
    skipped, and a note is added to the stats.

Two entry points:
  - scrape_hrd_for_domain(domain) — used by the domain scan engine. Only
    emails @ the scanned domain are returned (tagged source "jobportal").
  - scrape_hrd_bulk(keyword, location) — the "HRD Hunter" bulk mode. Emails
    from many companies' job listings, HRD-like addresses flagged.
"""

import random
import re
import threading
import time
import xml.etree.ElementTree as ET
from collections import defaultdict
from urllib.parse import urlencode, urljoin, urlparse, parse_qs

import requests
from bs4 import BeautifulSoup

from app.core.config import settings

# ---------------------------------------------------------------------------
# Lightweight copies of the shared helpers from domain_tasks.py.
# Duplicated (not imported) so this module stays import-independent and there
# is no circular import (domain_tasks imports this module).
# ---------------------------------------------------------------------------

EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")

SENTINEL_DOMAINS = {
    "example.com", "example.org", "example.net", "example.edu",
    "domain.com", "domain.net", "domain.org", "yourdomain.com",
    "your-domain.com", "your-site.com", "yoursite.com", "wixpress.com",
    "wix.com", "godaddy.com", "placeholder.com", "acme.com", "test.com",
    "sample.com", "email.com", "youremail.com", "name.com", "user.com",
    "username.com", "mycompany.com", "company.com", "company.co", "brand.com",
    "yourbrand.com", "example.co", "example.io", "example.app", "mydomain.com",
    "sentry.io",
}

SENTINEL_LOCALPARTS = {
    "name", "user", "username", "yourname", "your-name", "your_name",
    "email", "mail", "emailaddress", "someone", "nobody", "user.name",
    "firstname", "lastname", "first.last", "first_name", "last_name",
    "your-email", "your_email", "youremail", "recipient", "receiver",
    "address", "e-mail", "emailid",
}

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0 Safari/537.36 Edg/125.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
]


def normalize_email(raw: str) -> str:
    email = raw.strip().strip(".,;:()[]{}<>\"'").lower()
    while email.endswith("."):
        email = email[:-1]
    return email


def deobfuscate(text: str) -> str:
    """Decode JS unicode escapes (`\\u0040` -> `@`) and HTML entities."""
    if not text:
        return text
    try:
        text = re.sub(r"\\u([0-9a-fA-F]{4})", lambda m: chr(int(m.group(1), 16)), text)
    except Exception:
        pass
    try:
        text = __import__("html").unescape(text)
    except Exception:
        pass
    return text


def extract_emails(text: str) -> set:
    if not text:
        return set()
    return {normalize_email(m) for m in EMAIL_RE.findall(deobfuscate(text))}


def extract_mailto_emails(soup: BeautifulSoup) -> set:
    emails = set()
    for link in soup.find_all("a", href=True):
        href = link["href"].strip()
        if href.lower().startswith("mailto:"):
            raw = href[len("mailto:"):].split("?")[0].strip()
            if raw:
                emails.add(normalize_email(raw))
    return emails


def is_private_host(host: str) -> bool:
    """SSRF guard — reject internal/loopback/cloud-metadata hosts."""
    import ipaddress
    host = (host or "").lower().strip(".")
    if not host or host in ("localhost", "metadata.google.internal"):
        return True
    try:
        ip = ipaddress.ip_address(host)
        return (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_multicast or ip.is_reserved or ip.is_unspecified)
    except ValueError:
        return False


def _headers() -> dict:
    return {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": random.choice(["en-US,en;q=0.9", "id-ID,id;q=0.9,en-US;q=0.8"]),
        "Referer": random.choice(["https://www.google.com/", "https://www.bing.com/", ""]),
    }


def _is_usable_email(email: str) -> bool:
    if "@" not in email:
        return False
    local, _, maildomain = email.rpartition("@")
    if maildomain in SENTINEL_DOMAINS:
        return False
    if local in SENTINEL_LOCALPARTS:
        return False
    if not local or local.replace(".", "").replace("-", "").replace("_", "").isnumeric():
        return False
    return True


# ---------------------------------------------------------------------------
# Polite rate limiter + robots.txt awareness
# ---------------------------------------------------------------------------

class PoliteLimiter:
    """Per-host rate limiter with jittered delay windows and request caps.

    Sleep happens inside a per-host lock, so different hosts proceed in
    parallel while the same host is never hit twice within the delay window.
    """

    def __init__(self, min_delay: float = 2.0, jitter: float = 2.0,
                 host_cap: int = 40):
        self.min_delay = min_delay
        self.jitter = jitter
        self.host_cap = host_cap
        self._locks: dict = defaultdict(threading.Lock)
        self._last: dict = defaultdict(float)
        self._counts: dict = defaultdict(int)

    def take(self, host: str) -> bool:
        """Block until the polite window for `host` passes; then allow the
        request (returns False when the per-host cap is exhausted)."""
        with self._locks[host]:
            if self._counts[host] >= self.host_cap:
                return False
            now = time.monotonic()
            wait = (self._last[host] + self.min_delay + random.random() * self.jitter) - now
            if wait > 0:
                time.sleep(wait)
            self._counts[host] += 1
            self._last[host] = time.monotonic()
            return True


class _Robots:
    """Fetches and caches robots.txt per host; honors Disallow rules."""

    def __init__(self):
        self._cache: dict = {}
        self._lock = threading.Lock()

    def _fetch(self, host: str) -> list:
        rules = []
        for scheme in ("https", "http"):
            try:
                resp = requests.get(f"{scheme}://{host}/robots.txt",
                                    headers=_headers(), timeout=4)
            except Exception:
                continue
            if resp.status_code != 200:
                continue
            for raw in resp.text.splitlines():
                line = raw.split("#", 1)[0].strip()
                if not line:
                    continue
                low = line.lower()
                if low.startswith("user-agent:"):
                    ua = line.split(":", 1)[1].strip().lower()
                    if ua != "*":
                        continue
                elif low.startswith("disallow:"):
                    path = line.split(":", 1)[1].strip()
                    if path:
                        rules.append(path)
            break
        return rules

    def allowed(self, host: str, path: str) -> bool:
        with self._lock:
            if host not in self._cache:
                self._cache[host] = self._fetch(host)
        rules = self._cache[host]
        if not rules:
            return True
        for rule in rules:
            if rule.endswith("$"):
                if path == rule[:-1]:
                    return False
            elif path.startswith(rule):
                return False
        return True


_ROBOTS = _Robots()


def polite_get(url: str, limiter: PoliteLimiter | None = None,
               timeout: int = 10) -> requests.Response | None:
    """Fetch a URL politely: rate-limited, UA-rotated, robots-aware, SSRF-guarded.

    Every redirect hop's host is validated with `is_private_host` *before*
    connecting, so internal/loopback hosts are never reached.
    """
    host = (urlparse(url).hostname or "").lower()
    if not host or is_private_host(host):
        return None
    if limiter and not limiter.take(host):
        return None
    if not _ROBOTS.allowed(host, urlparse(url).path or "/"):
        return None

    current = url
    for _ in range(4 + 1):
        hop_host = (urlparse(current).hostname or "").lower()
        if is_private_host(hop_host):
            return None
        try:
            resp = requests.get(current, timeout=timeout, headers=_headers(),
                                allow_redirects=False)
        except Exception:
            return None
        if resp.is_redirect:
            location = resp.headers.get("Location")
            if not location:
                return None
            current = urljoin(current, location)
            continue
        return resp
    return None


# ---------------------------------------------------------------------------
# Portals
# ---------------------------------------------------------------------------

# Portals we actively look for & fetch. LinkedIn is intentionally excluded
# from direct fetching (aggressive anti-bot / login walls).
PORTAL_SITE_DOMAINS = [
    "jobstreet.co.id",
    "id.jobstreet.com",   # JobStreet Indonesia actually serves from this host
    "id.indeed.com",
    "glints.com",
    "kalibrr.com",
    "karir.com",
    "topkarir.com",
    "loker.id",
    "urbanhire.com",
]

SKIP_FETCH_DOMAINS = {"linkedin.com", "www.linkedin.com", "id.linkedin.com"}

# HRD-like mailbox local-parts, e.g. hr@ / recruitment@ / career@ / lowongan@
HRD_LOCAL_RE = re.compile(
    r"^(hr|hrd|hrga|hrm|recruit\w*|career\w*|karir|lowongan|job\w*|hiring|"
    r"talent\w*|people\w*|human\w*|staffing|hc|rekrut\w*)[._-]?\d*$", re.I)


def _portal_of(url: str) -> str:
    host = (urlparse(url).hostname or "").lower()
    for d in PORTAL_SITE_DOMAINS + ["linkedin.com"]:
        if host == d or host.endswith("." + d):
            return d
    return host


def _company_name(resp: requests.Response, soup: BeautifulSoup) -> str:
    og = soup.find("meta", attrs={"property": "og:site_name"})
    if og and og.get("content"):
        return og["content"].strip()
    title = (soup.title.get_text(strip=True) if soup.title else "") or ""
    if not title:
        return ""
    # "Lowongan Kerja X | Karir.com" → keep the brand-ish part
    for sep in ("|", "–", "-", "—"):
        if sep in title:
            return title.split(sep)[0].strip()
    return title[:60]


# ---------------------------------------------------------------------------
# Search-engine discovery (DDG HTML + Bing RSS — no API keys)
# ---------------------------------------------------------------------------

def search_urls_ddg(query: str, limit: int = 6, timeout: int = 5) -> list:
    urls = []
    try:
        resp = requests.post("https://html.duckduckgo.com/html/",
                             data={"q": query}, headers=_headers(), timeout=timeout)
        if resp.status_code == 200 and "anomaly" not in resp.text.lower():
            soup = BeautifulSoup(resp.text, "html.parser")
            for a in soup.select("a.result__a")[:limit]:
                href = a.get("href", "")
                if href.startswith("//"):
                    href = "https:" + href
                u = urlparse(href)
                qp = parse_qs(u.query)
                if "uddg" in qp and qp["uddg"]:
                    urls.append(qp["uddg"][0])
                elif href.startswith("http"):
                    urls.append(href)
    except Exception:
        pass
    return urls


def search_urls_bing(query: str, limit: int = 6, timeout: int = 5) -> list:
    urls = []
    try:
        resp = requests.get("https://www.bing.com/search",
                            params={"q": query, "format": "rss"},
                            headers=_headers(), timeout=timeout)
        if resp.status_code == 200:
            root = ET.fromstring(resp.text)
            for item in root.iter("item"):
                link = item.findtext("link") or ""
                if link.startswith("http") and len(urls) < limit:
                    urls.append(link)
    except Exception:
        pass
    return urls


# Direct search-page URLs per portal (fallback when search engines block
# us). Each is a plain GET of the portal's own job search page — fetched at
# most once per portal per scan, through the polite limiter, so it stays far
# below anything that could look like hammering.
PORTAL_SEARCH_ENDPOINTS = [
    # (portal host, search url, query param)
    ("loker.id", "https://www.loker.id/cari-lowongan-kerja", "q"),
    ("jobstreet.co.id", "https://id.jobstreet.com/id/jobs", "keywords"),
    ("karir.com", "https://www.karir.com/lowongan-kerja", "q"),
    ("kalibrr.com", "https://www.kalibrr.com/id_ID/job-board", "search"),
    ("topkarir.com", "https://www.topkarir.com/lowongan-kerja", "search"),
]


def _job_detail_patterns(host: str) -> list:
    """Path fragments that mark a job-detail page on a given portal."""
    host = (host or "").lower()
    if "jobstreet" in host:
        return ["/id/job/", "/id/companies/"]
    if "loker" in host:
        return ["/lowongan-kerja/", "/loker/"]
    if "kalibrr" in host:
        return ["/job/", "/id_ID/job/"]
    if "glints" in host:
        return ["/id/lowongan/"]
    if "karir" in host or "topkarir" in host:
        return ["/lowongan/", "/job/", "/pekerjaan/"]
    return ["/lowongan", "/job/", "/pekerjaan/"]


def extract_job_detail_urls(soup, base_url: str, limit: int = 12) -> list:
    """Pull job-detail URLs out of a listing page.

    Only links whose path matches a known job-detail pattern for the portal
    host are kept (nav links, login links, etc. are ignored). Relative links
    are resolved against the listing page URL.
    """
    host = (urlparse(base_url).hostname or "").lower()
    patterns = _job_detail_patterns(host)
    urls: list = []
    seen: set = set()
    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        if not href or href.startswith(("#", "javascript:", "mailto:")):
            continue
        low = href.lower()
        if not any(p in low for p in patterns):
            continue
        full = urljoin(base_url, href)
        # strip tracking query strings (?ref=..., &origin=...) so the same job
        # appearing 3x with different params counts once against the limit
        key = full.split("?")[0]
        if key in seen:
            continue
        seen.add(key)
        urls.append(full)
        if len(urls) >= limit:
            break
    return urls


def discover_listing_urls(keyword: str, location: str = "",
                          max_urls: int = 30,
                          limiter: PoliteLimiter | None = None,
                          deadline: float | None = None) -> list:
    """Discover job-listing URLs — search-engine `site:` dorks first, then a
    direct, polite fetch of each portal's own search page as fallback.

    Search engines (DDG/Bing) often block datacenter IPs or drop the `site:`
    operator, so the direct portal fallback keeps discovery working. Every
    URL kept is validated against the known portal list — no junk hosts.
    """
    urls: list = []
    seen: set = set()
    keyword = (keyword or "").strip()
    if not keyword:
        return urls

    def _add(u: str) -> bool:
        u = u.split("?")[0]
        if u in seen or _portal_of(u) not in PORTAL_SITE_DOMAINS:
            return False
        seen.add(u)
        urls.append(u)
        return True

    def _expired() -> bool:
        return deadline is not None and time.monotonic() > deadline

    # 1) search engines (best-effort; often rate-limited from servers).
    #    One cheap probe query tells us if the engines work at all — when
    #    they're blocking us, the full dork loop is skipped entirely so we
    #    don't burn the polite window on dead engines.
    probe = f'site:{PORTAL_SITE_DOMAINS[0]} "{keyword}"'
    engines_alive = False
    if not _expired():
        for engine in (search_urls_ddg, search_urls_bing):
            try:
                for u in engine(probe, limit=3):
                    if _portal_of(u) in PORTAL_SITE_DOMAINS:
                        engines_alive = True
                        break
            except Exception:
                pass
            if engines_alive:
                break
            time.sleep(random.uniform(0.4, 0.9))

    if engines_alive:
        for portal in PORTAL_SITE_DOMAINS[:4]:
            if len(urls) >= max_urls or _expired():
                break
            queries = [f'site:{portal} "{keyword}"']
            if location:
                queries.append(f'site:{portal} "{keyword}" "{location}"')
            queries.append(f'site:{portal} "{keyword}" (hrd OR hr OR lowongan OR recruitment)')
            for q in queries:
                if len(urls) >= max_urls or _expired():
                    break
                for engine in (search_urls_ddg, search_urls_bing):
                    if _expired():
                        break
                    for u in engine(q, limit=6):
                        _add(u)
                        if len(urls) >= max_urls:
                            break
                    time.sleep(random.uniform(0.6, 1.4))  # human-like pause
            time.sleep(random.uniform(0.8, 1.8))  # pause between portals

    # 2) direct portal search pages (fallback, 1 request per portal).
    #    Portals proven to be reachable & server-rendered are tried first;
    #    the whole loop is bounded so a single slow portal can't stall a scan.
    fallback_start = time.monotonic()
    # order: known-good first, then the rest
    ordered = sorted(PORTAL_SEARCH_ENDPOINTS,
                     key=lambda e: 0 if e[0] in ("loker.id", "jobstreet.co.id") else 1)
    for portal, base, qp in ordered:
        if len(urls) >= max_urls or _expired():
            break
        if time.monotonic() - fallback_start > 25:
            break  # hard ceiling on the whole fallback phase
        try:
            q = f"{keyword} {location}".strip()  # location folded into the query
            url = base + "?" + urlencode({qp: q})
            resp = polite_get(url, limiter=limiter, timeout=10)
            if resp is None or resp.status_code != 200:
                continue
            soup = BeautifulSoup(resp.text, "html.parser")
            # the search page itself can carry emails; detail links get added
            for detail in extract_job_detail_urls(soup, url, limit=6):
                if _add(detail) and len(urls) >= max_urls:
                    break
        except Exception:
            continue
        time.sleep(random.uniform(0.6, 1.2))

    return urls[:max_urls]


# ---------------------------------------------------------------------------
# Scrape entry points
# ---------------------------------------------------------------------------

def _harvest_page(url: str, limiter: PoliteLimiter, resp=None):
    """Fetch one listing page politely; returns (emails, company, soup)."""
    resp = resp or polite_get(url, limiter=limiter, timeout=10)
    if not resp or resp.status_code != 200:
        return None, "", None  # fetch failed -> caller skips this page
    soup = BeautifulSoup(resp.text, "html.parser")
    found = extract_emails(resp.text) | extract_mailto_emails(soup)
    return {e for e in found if _is_usable_email(e)}, _company_name(resp, soup), soup


def scrape_hrd_bulk(keyword: str, location: str = "", max_pages: int = 20,
                    deadline: float | None = None) -> dict:
    """HRD Hunter: collect HRD/recruitment emails across many companies.

    Returns:
      {"results": [{"email", "company", "portal", "url", "is_hrd"}],
       "stats": {...}}
    """
    stats = {
        "portals_queried": len(PORTAL_SITE_DOMAINS),
        "listings_found": 0,
        "pages_fetched": 0,
        "emails_found": 0,
        "hrd_emails": 0,
        "message": "",
    }
    limiter = PoliteLimiter(
        min_delay=settings.PORTAL_MIN_DELAY,
        jitter=settings.PORTAL_JITTER,
        host_cap=settings.PORTAL_HOST_CAP,
    )
    urls = discover_listing_urls(keyword, location, max_urls=max_pages * 2,
                                 limiter=limiter, deadline=deadline)
    stats["listings_found"] = len(urls)

    results: list = []
    seen: set = set()
    fetched = 0
    for url in urls:
        if fetched >= max_pages:
            break
        if deadline is not None and time.monotonic() > deadline:
            break
        if _portal_of(url) in SKIP_FETCH_DOMAINS:
            continue
        emails, company, _ = _harvest_page(url, limiter)
        if emails is None:
            continue  # fetch failed
        fetched += 1  # a page we actually managed to fetch
        if not emails:
            continue
        for e in sorted(emails):
            if e in seen:
                continue
            seen.add(e)
            is_hrd = bool(HRD_LOCAL_RE.match(e.split("@")[0].lower()))
            if is_hrd:
                stats["hrd_emails"] += 1
            results.append({
                "email": e,
                "company": company,
                "portal": _portal_of(url),
                "url": url,
                "is_hrd": is_hrd,
            })

    stats["pages_fetched"] = fetched
    stats["emails_found"] = len(results)
    if not results:
        stats["message"] = ("Tidak ada email ditemukan. Coba keyword/lokasi lain, atau "
                            "jalankan lagi nanti (portal bisa rate-limit).")
    return {"results": results, "stats": stats}


def scrape_hrd_for_domain(domain: str, deadline: float | None = None,
                          max_pages: int = 8) -> tuple:
    """Domain-scan integration: find the company's job listings on portals.

    Only emails @ the scanned domain are returned (tagged "jobportal" by the
    caller). Returns (emails_by_source, stats, email_urls).
    """
    stats = {
        "portals_queried": len(PORTAL_SITE_DOMAINS),
        "listings_found": 0,
        "pages_fetched": 0,
        "emails_found": 0,
        "message": "",
    }
    emails: dict = {}
    email_urls: dict = {}
    brand = domain.split(".")[0] if domain else ""
    limiter = PoliteLimiter(
        min_delay=settings.PORTAL_MIN_DELAY,
        jitter=settings.PORTAL_JITTER,
        host_cap=settings.PORTAL_HOST_CAP,
    )
    urls = discover_listing_urls(brand, "", max_urls=max_pages * 2,
                                 limiter=limiter, deadline=deadline)
    stats["listings_found"] = len(urls)

    fetched = 0
    for url in urls:
        if fetched >= max_pages:
            break
        if deadline is not None and time.monotonic() > deadline:
            break
        if _portal_of(url) in SKIP_FETCH_DOMAINS:
            continue
        found, _, _ = _harvest_page(url, limiter)
        if found is None:
            continue
        fetched += 1  # a page we actually managed to fetch (even with 0 emails)
        for e in found:
            # reuse domain_tasks validation semantics: only @domain addresses
            local, _, maildomain = e.rpartition("@")
            if maildomain.lower() == domain.lower() and local not in SENTINEL_LOCALPARTS:
                emails.setdefault(e, "jobportal")
                email_urls.setdefault(e, url)

    stats["pages_fetched"] = fetched
    stats["emails_found"] = len(emails)
    if not emails and not stats["listings_found"]:
        stats["message"] = "Tidak ada listing job portal ditemukan untuk domain ini."
    elif not emails:
        stats["message"] = ("Listing ditemukan, tapi portal modern tidak menampilkan "
                            "email HRD publik (pakai form aplikasi).")
    return emails, stats, email_urls


# ---------------------------------------------------------------------------
# Celery task (bulk HRD Hunter)
# ---------------------------------------------------------------------------

from app.core.celery_app import celery_app  # noqa: E402


@celery_app.task(name="app.tasks.portals.search_job_portals")
def search_job_portals(keyword: str, location: str = "", max_pages: int = 20):
    """Bulk HRD Hunter — Celery task. Polite, rate-limited, bounded."""
    started = time.time()
    deadline = time.monotonic() + 240.0
    payload = scrape_hrd_bulk(keyword, location, max_pages=max_pages,
                              deadline=deadline)
    payload["status"] = "completed"
    payload["keyword"] = keyword
    payload["location"] = location
    payload["duration_ms"] = int((time.time() - started) * 1000)
    return payload
