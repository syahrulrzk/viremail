"""Domain → email discovery engine.

100% self-built OSINT. Data sources:
  - DNS (A/AAAA/MX/NS/TXT, SPF, DMARC)  -> direct protocol queries
  - Deep public web crawl of the target domain (BFS up to depth 2, ~40 pages,
    homepage, contact/about/team/hubungi/tentang pages, mailto: links,
    robots.txt, sitemap.xml incl. index recursion, security.txt)
  - Public document extraction (PDF / DOCX / XLSX / TXT / CSV / RTF / MD)
  - WHOIS lookup (registrant / registrar / admin contact, public protocol)
  - Subdomain enumeration (DNS brute-force of ~60 common names) + crawl
  - Public search-engine scraping (DuckDuckGo HTML + Bing RSS), multi-query
  - Wayback Machine public archive (CDX API) — emails from historical pages
  - SMTP RCPT-TO verification of every displayed address (no mail is ever sent)

No third-party data APIs (no Hunter, no HIBP, no crt.sh, etc.).
"""

import glob
import html
import io
import ipaddress
import json
import os
import re
import secrets
import shutil
import smtplib
import subprocess
import tempfile
import time
import xml.etree.ElementTree as ET
import zipfile
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin, urlparse, parse_qs

import dns.resolver
import requests
from bs4 import BeautifulSoup

from app.core.celery_app import celery_app
from app.core.config import settings

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0 Safari/537.36 VIRE/1.3"
)

HEADERS = {
    "User-Agent": USER_AGENT,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}

EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")

# Sentinel domains that appear in website templates / placeholders
SENTINEL_DOMAINS = {
    "example.com", "example.org", "example.net", "example.edu",
    "domain.com", "domain.net", "domain.org",
    "yourdomain.com", "your-domain.com", "your-site.com", "yoursite.com",
    "sentry.io", "wixpress.com", "wix.com", "godaddy.com", "placeholder.com",
    "acme.com", "test.com", "sample.com", "email.com", "youremail.com",
    "name.com", "user.com", "username.com", "mycompany.com",
    "company.com", "company.co", "brand.com", "yourbrand.com",
    "example.co", "example.io", "example.app", "mydomain.com",
}

# Local parts that are template placeholders, not real mailboxes
SENTINEL_LOCALPARTS = {
    "name", "user", "username", "yourname", "your-name", "your_name",
    "email", "mail", "emailaddress", "someone", "nobody", "user.name",
    "firstname", "lastname", "first.last", "first_name", "last_name",
    "your-email", "your_email", "youremail", "recipient", "receiver",
    "address", "emailaddress", "mailaddress", "e-mail", "emailid",
}

SOURCE_PRIORITY = {
    "mailto": 0,
    "website": 1,
    "careers": 2,
    "document": 3,
    "security_txt": 4,
    "search": 5,
    "wayback": 6,
    "github": 7,
    "mailing_list": 8,
    "ocr": 9,
    "bbot": 10,
    "subdomain": 11,
    "whois": 12,
    "pattern_verified": 13,
}

# User-selectable data sources — the frontend sends the enabled subset with
# each scan (toggle chips under the search bar).
SOURCE_KEYS = [
    "dns", "website", "docs", "subdomains", "whois", "search",
    "wayback", "github", "mailing", "patterns", "smtp",
]
DEFAULT_SOURCES = list(SOURCE_KEYS)

MAX_BBOT_EMAILS = 15
DNS_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT"]

MAX_GITHUB_COMMITS = 50
MAX_MAILING_MESSAGES = 6
MAX_TEAM_PAGES = 12
MAX_PATTERN_NAMES = 8
MAX_NAME_PATTERN_CHECKS = 32
MAX_PEOPLE = 40

MAX_CRAWL_PAGES = 40
MAX_CRAWL_DEPTH = 2
MAX_SITEMAP_URLS = 15
MAX_SITEMAP_FETCHES = 25  # cap sitemap-index recursion (huge sites have hundreds)
MAX_SEARCH_RESULT_PAGES = 4
MAX_EMAILS = 60
MAX_DOCS = 10
MAX_DOC_BYTES = 3 * 1024 * 1024  # 3 MB
MAX_SUBDOMAIN_CRAWLS = 5
MAX_SMTP_CHECKS = 20
MAX_PATTERN_CHECKS = 14
SMTP_TIMEOUT = 6
SMTP_BUDGET_SECONDS = 45
HTTP_TIMEOUT = 8
WHOIS_TIMEOUT = 12

DOC_EXTS = {".pdf", ".docx", ".xlsx", ".txt", ".csv", ".rtf", ".md", ".odt"}
IMAGE_EXTS = {".jpg", ".jpeg", ".png", ".webp", ".bmp", ".gif"}

MAX_OCR_IMAGES = 5
MAX_OCR_PDF_PAGES = 5
MAX_WAYBACK_PAGES = 20
MAX_HOLEHE_EMAILS = 4

PATTERN_PREFIXES = [
    "info", "admin", "support", "contact", "sales", "hello", "marketing",
    "press", "media", "privacy", "legal", "security", "abuse", "billing",
    "finance", "hr", "jobs", "careers", "recruitment", "office", "reception",
    "webmaster", "postmaster", "hostmaster", "it", "dev", "tech", "team",
    "service", "services", "feedback", "help", "business", "partnership",
    "inquiry", "enquiry", "complaints", "newsletter",
]

SUBDOMAIN_WORDLIST = [
    "www", "mail", "webmail", "smtp", "pop", "pop3", "imap", "mx", "mx1",
    "mx2", "mx3", "ftp", "sftp", "ssh", "vpn", "api", "app", "apps", "dev",
    "staging", "test", "testing", "qa", "beta", "demo", "admin", "portal",
    "cpanel", "whm", "ns1", "ns2", "ns3", "dns", "dns1", "dns2", "blog",
    "news", "shop", "store", "cdn", "static", "assets", "images", "img",
    "media", "docs", "support", "help", "forum", "status", "git", "gitlab",
    "jenkins", "ci", "dashboard", "panel", "billing", "login", "auth",
    "sso", "intranet", "office", "remote", "cloud", "monitor", "monitoring",
    "grafana", "kibana", "backup", "db", "database", "sql", "old", "new",
    "mobile", "ws", "web", "site", "sandbox", "preprod", "prod", "www2",
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def normalize_email(raw: str) -> str:
    """Lowercase and strip junk from a raw extracted email."""
    email = raw.strip().strip(".,;:()[]{}<>\"'").lower()
    while email.endswith("."):
        email = email[:-1]
    return email


def is_valid_target_email(email: str, domain: str) -> bool:
    """An email is usable only when it belongs to the queried domain and is
    not a template placeholder."""
    if "@" not in email:
        return False
    local, _, maildomain = email.rpartition("@")
    if maildomain.lower() != domain.lower():
        return False
    if maildomain.lower() in SENTINEL_DOMAINS:
        return False
    if local in SENTINEL_LOCALPARTS:
        return False
    if not local or local.replace(".", "").replace("-", "").replace("_", "").isnumeric():
        return False
    return True


def deobfuscate(text: str) -> str:
    """Decode common email-obfuscation used by websites:
    - JS unicode escapes: `\\u0040` -> `@` (many WP/JS sites)
    - HTML entities: `&#64;` / `&commat;` -> `@`
    This is why Google 'sees' emails that plain HTML parsers miss.
    """
    if not text:
        return text
    try:
        text = re.sub(r"\\u([0-9a-fA-F]{4})", lambda m: chr(int(m.group(1), 16)), text)
    except Exception:
        pass
    try:
        text = html.unescape(text)
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
    """Reject hosts that resolve to internal/loopback ranges (SSRF guard)."""
    host = (host or "").lower().strip(".")
    if not host or host in ("localhost", "metadata.google.internal"):
        return True
    try:
        ip = ipaddress.ip_address(host)
        return (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_multicast or ip.is_reserved or ip.is_unspecified)
    except ValueError:
        return False


def fetch(url: str, timeout: int = HTTP_TIMEOUT, max_redirects: int = 4) -> requests.Response | None:
    """Fetch a URL with manual redirect handling.

    Every hop's host (including the initial URL) is validated with
    `is_private_host` *before* connecting, so internal/loopback hosts are
    never reached even via redirects. Note: DNS-rebinding (a hostname that
    resolves to a private range) is not detected here — acceptable for this
    user-driven tool.
    """
    current = url
    for _ in range(max_redirects + 1):
        if is_private_host(urlparse(current).hostname or ""):
            return None
        try:
            resp = requests.get(current, timeout=timeout, headers=HEADERS, allow_redirects=False)
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


def is_same_site(url: str, domain: str) -> bool:
    host = (urlparse(url).hostname or "").lower()
    return host == domain or host.endswith(f".{domain}")


TEAM_PATH_KEYWORDS = ("team", "about", "tentang", "profil", "staff", "people",
                      "kontak", "hubungi", "author", "karyawan", "founder")


def _is_team_page(url: str) -> bool:
    path = (urlparse(url).path or "/").lower()
    return any(k in path for k in TEAM_PATH_KEYWORDS)


# ---------------------------------------------------------------------------
# Name extraction & pattern generation (Hunter-style email finder)
# ---------------------------------------------------------------------------

NAME_RE = re.compile(r"(?<![A-Za-z@.])[A-Z][a-z]+(?:[ -][A-Z][a-z]+){1,3}(?![a-z])")

NAME_STOP_WORDS = {
    "home", "about", "contact", "team", "menu", "read", "more", "login",
    "sign", "register", "english", "indonesia", "indonesian", "search",
    "submit", "view", "back", "next", "prev", "click", "here", "news",
    "blog", "privacy", "terms", "cookie", "careers", "jobs", "sitemap",
    "newsletter", "email", "phone", "address", "faq", "help", "support",
    "get", "started", "free", "download", "learn", "join", "follow",
    "share", "tweet", "facebook", "twitter", "instagram", "linkedin",
    "youtube", "whatsapp", "order", "checkout", "cart", "shop", "store",
    "product", "products", "service", "services", "feature", "features",
    "testimonial", "review", "reviews", "portfolio", "project", "projects",
}


def extract_names_from_texts(texts: list, max_names: int = 8) -> list:
    """Heuristic Title-Case name extraction from team/about page texts.

    Only names found on team-ish pages count; the SMTP verification step
    filters false positives — only active mailboxes are ever shown.
    """
    counts: dict = {}
    for text in texts:
        for m in NAME_RE.findall(text or ""):
            words = [w for w in m.split() if w]
            if len(words) < 2:
                continue
            if any(w.lower() in NAME_STOP_WORDS for w in words):
                continue
            counts[m] = counts.get(m, 0) + 1
    ranked = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    return [n for n, _ in ranked[:max_names]]


def name_patterns(name: str, domain: str) -> list:
    """Generate likely mailbox patterns for a person (Hunter-style finder)."""
    parts = [p for p in re.split(r"[\s._\-']+", name.strip().lower()) if p.isalpha()]
    if not parts:
        return []
    first, last = parts[0], parts[-1]
    cands = set()
    if first and last and first != last:
        cands.update([
            f"{first}.{last}@{domain}",
            f"{first}_{last}@{domain}",
            f"{first}{last}@{domain}",
            f"{first[0]}{last}@{domain}",
            f"{first[0]}.{last}@{domain}",
            f"{last}.{first}@{domain}",
            f"{last}_{first}@{domain}",
            f"{last}{first}@{domain}",
        ])
    if first:
        cands.add(f"{first}@{domain}")
    if last:
        cands.add(f"{last}@{domain}")
    return sorted(cands)


# ---------------------------------------------------------------------------
# DNS
# ---------------------------------------------------------------------------

def collect_dns(domain: str) -> tuple:
    """Return (dns_records, spf, dmarc, mx_count)."""
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2
    resolver.lifetime = 4

    dns_records: dict = {}
    for rtype in DNS_RECORD_TYPES:
        try:
            answers = resolver.resolve(domain, rtype)
            dns_records[rtype] = [str(rdata) for rdata in answers]
        except Exception:
            dns_records[rtype] = []

    spf = None
    for txt in dns_records.get("TXT", []):
        txt_str = txt.strip('"')
        if txt_str.startswith("v=spf1"):
            spf = txt_str
            break

    dmarc = None
    try:
        for txt in resolver.resolve(f"_dmarc.{domain}", "TXT"):
            txt_str = str(txt).strip('"')
            if txt_str.startswith("v=DMARC1"):
                dmarc = txt_str
                break
    except Exception:
        pass

    mx_count = len(dns_records.get("MX", []))
    return dns_records, spf, dmarc, mx_count


# ---------------------------------------------------------------------------
# Crawling (deep BFS)
# ---------------------------------------------------------------------------

def get_robots(domain: str) -> tuple:
    """Fetch /robots.txt -> (disallowed_paths, sitemap_urls)."""
    disallowed: list = []
    sitemaps: list = []
    for base in (f"https://{domain}", f"http://{domain}"):
        resp = fetch(f"{base}/robots.txt", timeout=5)
        if not resp or resp.status_code != 200:
            continue
        in_wildcard_group = False
        for raw in resp.text.splitlines():
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            low = line.lower()
            if low.startswith("user-agent:"):
                ua = line.split(":", 1)[1].strip().lower()
                in_wildcard_group = ua == "*"
            elif low.startswith("disallow:"):
                if in_wildcard_group:
                    path = line.split(":", 1)[1].strip()
                    if path:
                        disallowed.append(path)
            elif low.startswith("sitemap:"):
                url = line.split(":", 1)[1].strip()
                if url.lower().startswith("http"):
                    sitemaps.append(url)
        break
    return disallowed, sitemaps


def is_allowed(path: str, disallowed: list) -> bool:
    for rule in disallowed:
        if rule.endswith("$"):
            if path == rule[:-1]:
                return False
        elif path.startswith(rule):
            return False
    return True


def get_sitemap_urls(domain: str, robots_sitemaps: list) -> list:
    candidates = robots_sitemaps[:] or [
        f"https://{domain}/sitemap.xml",
        f"https://{domain}/sitemap_index.xml",
        f"http://{domain}/sitemap.xml",
    ]
    urls: list = []
    to_fetch = list(candidates)
    fetched: set = set()
    fetches = 0
    for sitemap_url in to_fetch:
        if fetches >= MAX_SITEMAP_FETCHES:
            break
        if len(urls) >= MAX_SITEMAP_URLS or sitemap_url in fetched:
            continue
        if not is_same_site(sitemap_url, domain):
            continue
        fetched.add(sitemap_url)
        resp = fetch(sitemap_url, timeout=6)
        fetches += 1
        if not resp or resp.status_code != 200:
            continue
        soup = BeautifulSoup(resp.text, "html.parser")
        if soup.find("sitemapindex"):
            for loc in soup.find_all("loc"):
                u = loc.get_text(strip=True)
                if u and is_same_site(u, domain):
                    to_fetch.append(u)
            continue
        for loc in soup.find_all("loc"):
            u = loc.get_text(strip=True)
            if u and is_same_site(u, domain) and len(urls) < MAX_SITEMAP_URLS:
                urls.append(u)
    return urls[:MAX_SITEMAP_URLS]


def get_security_txt(domain: str) -> tuple:
    """Return (found, contact_emails, contact_urls)."""
    contacts = set()
    contacts_urls: dict = {}
    for path in (f"https://{domain}/.well-known/security.txt",
                 f"https://{domain}/security.txt",
                 f"http://{domain}/.well-known/security.txt"):
        resp = fetch(path, timeout=5)
        if not resp or resp.status_code != 200:
            continue
        for email in extract_emails(resp.text):
            if is_valid_target_email(email, domain):
                contacts.add(email)
                contacts_urls.setdefault(email, path)
        if contacts:
            return True, sorted(contacts), contacts_urls
    return False, [], {}


CONTACT_KEYWORDS = ("contact", "about", "team", "staff", "support", "help",
                    "imprint", "legal", "impressum", "kontak", "hubungi",
                    "tentang", "karir", "profil", "tim", "people", "career",
                    "careers", "jobs", "job", "lowongan", "hiring",
                    "recruitment")


def _harvest(base: str, text: str, soup: BeautifulSoup, emails_by_source: dict,
             doc_urls: list, img_urls: list, domain: str,
             emails_by_url: dict | None = None) -> None:
    for e in extract_emails(text):
        if is_valid_target_email(e, domain):
            emails_by_source.setdefault(e, "website")
            if emails_by_url is not None:
                emails_by_url.setdefault(e, base)
    for e in extract_mailto_emails(soup):
        if is_valid_target_email(e, domain):
            emails_by_source.setdefault(e, "mailto")
            if emails_by_url is not None:
                emails_by_url.setdefault(e, base)
    for link in soup.find_all("a", href=True):
        href = link["href"].strip()
        if href.lower().startswith(("mailto:", "javascript:", "tel:")):
            continue
        absolute = urljoin(base, href)
        # same-site only — off-site links could point at internal hosts (SSRF)
        if not is_same_site(absolute, domain):
            continue
        ext = os.path.splitext(urlparse(absolute).path)[1].lower()
        if ext in DOC_EXTS and len(doc_urls) < MAX_DOCS and absolute not in doc_urls:
            doc_urls.append(absolute)
        elif ext in IMAGE_EXTS and len(img_urls) < MAX_OCR_IMAGES and absolute not in img_urls:
            img_urls.append(absolute)


def crawl_site(domain: str, disallowed: list, sitemap_urls: list) -> tuple:
    """BFS crawl up to MAX_CRAWL_PAGES pages (depth <= MAX_CRAWL_DEPTH).

    Returns (emails_by_source, crawl_stats, doc_urls, img_urls, team_texts).
    """
    base_urls = [
        f"https://{domain}", f"http://{domain}",
        f"https://www.{domain}", f"http://www.{domain}",
    ]

    emails_by_source: dict = {}
    emails_by_url: dict = {}
    doc_urls: list = []
    img_urls: list = []
    team_texts: list = []
    visited: set = set()
    frontier: list = []  # (priority, depth, url)
    pages_crawled = 0
    links_found = 0
    max_depth = 0

    def _priority(url: str) -> int:
        path = urlparse(url).path.lower()
        return 0 if any(k in path for k in CONTACT_KEYWORDS) else 1

    def _enqueue(url: str, depth: int) -> None:
        key = url.rstrip("/")
        if key in visited:
            return
        frontier.append((_priority(url), depth, url))

    # homepage (depth 0)
    for base in base_urls:
        resp = fetch(base, timeout=6)
        if not resp or resp.status_code != 200:
            continue
        pages_crawled += 1
        soup = BeautifulSoup(resp.text, "html.parser")
        _harvest(base, resp.text, soup, emails_by_source, doc_urls, img_urls, domain, emails_by_url)
        if len(team_texts) < MAX_TEAM_PAGES and _is_team_page(base):
            team_texts.append(resp.text)
        visited.add(base.rstrip("/"))
        for link in soup.find_all("a", href=True):
            href = link["href"].strip()
            if href.startswith(("#", "javascript:", "tel:", "mailto:")):
                continue
            absolute = urljoin(base, href)
            if not is_same_site(absolute, domain):
                continue
            path = urlparse(absolute).path or "/"
            if not is_allowed(path, disallowed):
                continue
            links_found += 1
            _enqueue(absolute, 1)
        break

    # sitemap URLs also as depth-1 seeds
    for su in sitemap_urls:
        _enqueue(su, 1)

    # de-dupe + contact pages first
    seen: set = set()
    ordered: list = []
    for prio, depth, url in sorted(frontier, key=lambda x: (x[0], x[1])):
        key = url.rstrip("/")
        if key in seen:
            continue
        seen.add(key)
        ordered.append((prio, depth, url))

    idx = 0
    while (idx < len(ordered) and pages_crawled < MAX_CRAWL_PAGES
           and len(emails_by_source) < MAX_EMAILS):
        prio, depth, url = ordered[idx]
        idx += 1
        key = url.rstrip("/")
        if key in visited:
            continue
        visited.add(key)
        resp = fetch(url, timeout=5)
        if not resp or resp.status_code != 200:
            continue
        pages_crawled += 1
        max_depth = max(max_depth, depth)
        soup = BeautifulSoup(resp.text, "html.parser")
        _harvest(url, resp.text, soup, emails_by_source, doc_urls, img_urls, domain, emails_by_url)
        if len(team_texts) < MAX_TEAM_PAGES and _is_team_page(url):
            team_texts.append(resp.text)
        if depth < MAX_CRAWL_DEPTH:
            for link in soup.find_all("a", href=True):
                href = link["href"].strip()
                if href.startswith(("#", "javascript:", "tel:", "mailto:")):
                    continue
                absolute = urljoin(url, href)
                if not is_same_site(absolute, domain):
                    continue
                if not is_allowed(urlparse(absolute).path or "/", disallowed):
                    continue
                if absolute.rstrip("/") in visited:
                    continue
                links_found += 1
                ordered.append((_priority(absolute), depth + 1, absolute))

    return emails_by_source, {
        "pages_crawled": pages_crawled,
        "links_found": links_found,
        "max_depth": max_depth,
    }, doc_urls, img_urls, team_texts, emails_by_url


# ---------------------------------------------------------------------------
# Public document extraction (PDF/DOCX/XLSX/TXT/CSV/RTF/MD — no API)
# ---------------------------------------------------------------------------

def _document_text(url: str) -> str | None:
    ext = os.path.splitext(urlparse(url).path)[1].lower()
    content = _download_bytes(url)
    if not content:
        return None

    try:
        if ext == ".pdf":
            from pdfminer.high_level import extract_text as pdf_extract
            return pdf_extract(io.BytesIO(content))
        if ext == ".docx":
            with zipfile.ZipFile(io.BytesIO(content)) as z:
                xml = z.read("word/document.xml").decode("utf-8", "ignore")
            return BeautifulSoup(xml, "html.parser").get_text(" ", strip=True)
        if ext == ".xlsx":
            parts = []
            with zipfile.ZipFile(io.BytesIO(content)) as z:
                for name in ("xl/sharedStrings.xml", "xl/worksheets/sheet1.xml"):
                    try:
                        xml = z.read(name).decode("utf-8", "ignore")
                    except KeyError:
                        continue
                    soup = BeautifulSoup(xml, "html.parser")
                    parts.extend(t.get_text(" ", strip=True) for t in soup.find_all("t"))
            return " ".join(parts)
        text = content.decode("utf-8", "ignore")
        if ext == ".rtf":
            text = re.sub(r"\\[a-zA-Z]+-?\d* ?", " ", text)  # strip RTF control words
        return text
    except Exception:
        return None


def extract_emails_from_docs(doc_urls: list, domain: str) -> tuple:
    """Download public documents and pull emails -> (emails, doc_stats)."""
    emails: dict = {}
    email_urls: dict = {}
    parsed = 0
    for url in doc_urls:
        if len(emails) >= MAX_EMAILS:
            break
        text = _document_text(url)
        if not text:
            continue
        parsed += 1
        for e in extract_emails(text):
            if is_valid_target_email(e, domain):
                emails.setdefault(e, "document")
                email_urls.setdefault(e, url)
    return emails, {"docs_found": len(doc_urls), "docs_parsed": parsed,
                    "emails_found": len(emails)}, email_urls


# ---------------------------------------------------------------------------
# Local OCR (Tesseract — self-hosted, reads text from images & scanned PDFs)
# ---------------------------------------------------------------------------

def _download_bytes(url: str) -> bytes | None:
    """Download bytes with SSRF guard: every hop (incl. redirects) is checked
    with `is_private_host` *before* connecting, and size is capped at
    MAX_DOC_BYTES. Returns None on failure/oversize/private host."""
    current = url
    for _ in range(4 + 1):
        if is_private_host(urlparse(current).hostname or ""):
            return None
        try:
            resp = requests.get(current, timeout=HTTP_TIMEOUT, headers=HEADERS,
                                allow_redirects=False, stream=True)
        except Exception:
            return None
        try:
            if resp.is_redirect:
                location = resp.headers.get("Location")
                if not location:
                    return None
                current = urljoin(current, location)
                continue
            if resp.status_code != 200:
                return None
            content = b""
            for chunk in resp.iter_content(chunk_size=65536):
                content += chunk
                if len(content) > MAX_DOC_BYTES:
                    return None
            return content
        finally:
            resp.close()
    return None


def _tesseract_available() -> bool:
    import shutil
    return shutil.which("tesseract") is not None


def _ocr_bytes(content: bytes) -> str:
    """Run Tesseract on raw image bytes. Returns extracted text (may be empty)."""
    import pytesseract
    from PIL import Image
    return pytesseract.image_to_string(Image.open(io.BytesIO(content)))


def _ocr_pdf(content: bytes) -> str:
    """Render scanned-PDF pages to images and OCR them (bounded pages)."""
    import fitz
    texts = []
    doc = fitz.open(stream=content, filetype="pdf")
    mat = fitz.Matrix(200 / 72, 200 / 72)  # ~200 dpi
    try:
        for i, page in enumerate(doc):
            if i >= MAX_OCR_PDF_PAGES:
                break
            pix = page.get_pixmap(matrix=mat)
            texts.append(_ocr_bytes(pix.tobytes("png")))
    finally:
        doc.close()
    return "\n".join(t for t in texts if t)


def ocr_emails(img_urls: list, doc_urls: list, domain: str) -> tuple:
    """OCR images + scanned PDFs found during crawl -> (emails, ocr_stats).

    Only literal, @domain addresses count. Bounded: MAX_OCR_IMAGES images and
    MAX_OCR_PDF_PAGES pages per PDF. Gracefully skips when disabled or when
    the Tesseract binary is missing.
    """
    stats = {"enabled": False, "images_found": len(img_urls),
             "images_ocred": 0, "pdfs_ocred": 0, "emails_found": 0,
             "message": ""}
    if not settings.OCR_ENABLED:
        stats["message"] = "OCR dinonaktifkan (OCR_ENABLED=false)."
        return {}, stats, {}
    if not _tesseract_available():
        stats["message"] = "Binary Tesseract tidak ditemukan — OCR dilewati."
        return {}, stats, {}

    stats["enabled"] = True
    emails: dict = {}
    email_urls: dict = {}

    # 1) images
    for url in img_urls[:MAX_OCR_IMAGES]:
        if len(emails) >= MAX_EMAILS:
            break
        content = _download_bytes(url)
        if not content:
            continue
        try:
            text = _ocr_bytes(content)
        except Exception:
            continue
        stats["images_ocred"] += 1
        for e in extract_emails(text):
            if is_valid_target_email(e, domain):
                emails.setdefault(e, "ocr")
                email_urls.setdefault(e, url)

    # 2) scanned PDFs — only those whose embedded text layer is (nearly) empty
    pdf_urls = [u for u in doc_urls if os.path.splitext(urlparse(u).path)[1].lower() == ".pdf"]
    for url in pdf_urls[:MAX_OCR_PDF_PAGES]:
        if len(emails) >= MAX_EMAILS:
            break
        text = _document_text(url)
        if text and len(text.strip()) >= 40:  # real text layer → not scanned
            continue
        content = _download_bytes(url)
        if not content:
            continue
        try:
            ocr_text = _ocr_pdf(content)
        except Exception:
            continue
        if not ocr_text:
            continue
        stats["pdfs_ocred"] += 1
        for e in extract_emails(ocr_text):
            if is_valid_target_email(e, domain):
                emails.setdefault(e, "ocr")
                email_urls.setdefault(e, url)

    stats["emails_found"] = len(emails)
    if not stats["images_ocred"] and not stats["pdfs_ocred"]:
        stats["message"] = "Tidak ada gambar / PDF scan yang bisa di-OCR."
    else:
        stats["message"] = (f"{stats['images_ocred']} gambar & {stats['pdfs_ocred']} PDF "
                            f"di-OCR via Tesseract lokal.")
    return emails, stats, email_urls


# ---------------------------------------------------------------------------
# Subdomain enumeration (DNS brute-force) + crawl of active hosts
# ---------------------------------------------------------------------------

def enumerate_subdomains(domain: str) -> list:
    names = [f"{sub}.{domain}" for sub in SUBDOMAIN_WORDLIST if len(sub) + len(domain) + 1 <= 253]

    def check(name: str):
        try:
            r = dns.resolver.Resolver()
            r.timeout = 2
            r.lifetime = 3
            if list(r.resolve(name, "A")):
                return name
        except Exception:
            pass
        return None

    active = []
    with ThreadPoolExecutor(max_workers=12) as ex:
        for res in ex.map(check, names):
            if res:
                active.append(res)
    active.sort()
    return active


def crawl_subdomains(active: list, domain: str) -> tuple:
    """Fetch homepages of discovered subdomains -> (emails_by_source, stats)."""
    emails: dict = {}
    email_urls: dict = {}
    crawled = 0
    for host in active[:MAX_SUBDOMAIN_CRAWLS]:
        for scheme in ("https", "http"):
            resp = fetch(f"{scheme}://{host}/", timeout=5)
            if not resp or resp.status_code != 200:
                continue
            crawled += 1
            soup = BeautifulSoup(resp.text, "html.parser")
            for e in extract_emails(resp.text) | extract_mailto_emails(soup):
                if is_valid_target_email(e, domain):
                    emails.setdefault(e, "subdomain")
                    email_urls.setdefault(e, f"{scheme}://{host}/")
            break
    return emails, {"subdomains_crawled": crawled}, email_urls


# ---------------------------------------------------------------------------
# WHOIS lookup (public whois protocol, no API key)
# ---------------------------------------------------------------------------

def whois_lookup(domain: str) -> dict | None:
    def _run():
        import whois as whois_mod
        return whois_mod.query(domain)

    # NOTE: shutdown(wait=False) — the `with` form would wait for a hung
    # whois query forever and stall the celery worker.
    pool = ThreadPoolExecutor(max_workers=1)
    fut = pool.submit(_run)
    try:
        w = fut.result(timeout=WHOIS_TIMEOUT)
    except Exception:
        w = None
    finally:
        pool.shutdown(wait=False)
    if w is None:
        return None

    def _fmt(v):
        if isinstance(v, (list, tuple)):
            return [str(x) for x in v if x]
        return str(v) if v else None

    def _date(v):
        if isinstance(v, (list, tuple)):
            v = v[0] if v else None
        return str(v).split(" ")[0] if v else None

    emails = set()
    for f in ("emails", "registrant_emails", "admin_emails", "tech_emails"):
        val = getattr(w, f, None)
        if isinstance(val, (list, tuple)):
            emails.update(str(x) for x in val if x)
        elif val:
            emails.add(str(val))
    emails.update(extract_emails(str(w)))

    raw = str(w)
    return {
        "registrar": _fmt(getattr(w, "registrar", None)),
        "creation_date": _date(getattr(w, "creation_date", None)),
        "expiration_date": _date(getattr(w, "expiration_date", None)),
        "updated_date": _date(getattr(w, "updated_date", None)),
        "name_servers": [str(x).rstrip(".") for x in (getattr(w, "name_servers", None) or [])][:8],
        "emails": sorted(e.lower() for e in emails if "@" in e)[:15],
        "raw_found": bool(raw and raw.strip() not in ("", "None", "{}")),
    }


# ---------------------------------------------------------------------------
# Search engine scraping (public, no API keys) — multi-query
# ---------------------------------------------------------------------------

def search_duckduckgo(domain: str) -> dict:
    """Scrape DuckDuckGo HTML results across several dork queries."""
    emails = set()
    email_urls: dict = {}
    urls = []
    results = 0
    queries = [
        f'"{domain}" contact email',
        f'"{domain}" email',
        f'"@{domain}"',
        f'site:{domain} "@{domain}"',
    ]
    for q in queries:
        try:
            resp = requests.post(
                "https://html.duckduckgo.com/html/",
                data={"q": q}, headers=HEADERS, timeout=8,
            )
            if resp.status_code == 200 and "anomaly" not in resp.text.lower():
                soup = BeautifulSoup(resp.text, "html.parser")
                blocks = soup.select("div.result")
                results += len(blocks)
                for block in blocks:
                    title_el = block.select_one("a.result__a")
                    snippet_el = block.select_one("a.result__snippet")
                    text = " ".join(t for t in [
                        title_el.get_text(" ", strip=True) if title_el else "",
                        snippet_el.get_text(" ", strip=True) if snippet_el else "",
                    ] if t)
                    block_url = ""
                    if title_el:
                        href = title_el.get("href", "")
                        if href.startswith("//"):
                            href = "https:" + href
                        u = urlparse(href)
                        qp = parse_qs(u.query)
                        if "uddg" in qp and qp["uddg"]:
                            block_url = qp["uddg"][0]
                            urls.append(block_url)
                        elif href.startswith("http"):
                            block_url = href
                            urls.append(href)
                    block_emails = extract_emails(text)
                    emails.update(block_emails)
                    for e in block_emails:
                        if block_url:
                            email_urls.setdefault(e, block_url)
        except Exception:
            pass

    fetched = 0
    for url in urls:
        if fetched >= MAX_SEARCH_RESULT_PAGES:
            break
        resp = fetch(url, timeout=5)
        if not resp or resp.status_code != 200:
            continue
        fetched += 1
        for e in extract_emails(resp.text):
            email_urls.setdefault(e, url)
        emails.update(extract_emails(resp.text))
    return {"emails": sorted(emails), "results": results, "urls": email_urls}


def search_bing(domain: str) -> dict:
    """Fetch Bing results via its RSS output (no JS required, no API key)."""
    emails = set()
    email_urls: dict = {}
    count = 0
    queries = [
        f'site:{domain} "@{domain}"',
        f'"@{domain}" email',
        f'"{domain}" contact email',
    ]
    for q in queries:
        try:
            resp = requests.get(
                "https://www.bing.com/search",
                params={"q": q, "format": "rss"},
                headers=HEADERS, timeout=8,
            )
            if resp.status_code == 200:
                root = ET.fromstring(resp.text)
                for item in root.iter("item"):
                    title = item.findtext("title") or ""
                    desc = item.findtext("description") or ""
                    link = item.findtext("link") or ""
                    count += 1
                    for e in extract_emails(f"{title} {desc}"):
                        emails.add(e)
                        if link:
                            email_urls.setdefault(e, link)
        except Exception:
            pass
    return {"emails": sorted(emails), "results": count, "urls": email_urls}


# ---------------------------------------------------------------------------
# Wayback Machine (public web archive — no API key, self-built)
# ---------------------------------------------------------------------------

_WAYBACK_ASSET_RE = re.compile(
    r"\.(css|js|png|jpe?g|gif|svg|webp|ico|woff2?|ttf|map|xml|json|pdf)(\?.*)?$", re.I)


def search_wayback(domain: str, deadline: float | None = None) -> tuple:
    """Find emails in archived snapshots of the domain.

    Google indexes historical content; live sites often remove or obfuscate
    emails afterwards. The Wayback CDX API lists archived URLs — we fetch a
    bounded set of snapshots and extract (deobfuscated) emails + mailto:.
    Returns (emails_by_source, wayback_stats).
    """
    stats = {"pages_found": 0, "pages_fetched": 0, "emails_found": 0}
    emails: dict = {}
    email_urls: dict = {}
    try:
        resp = requests.get(
            "https://web.archive.org/cdx/search/cdx",
            params={
                "url": f"{domain}*",
                "output": "json",
                "filter": "statuscode:200",
                "collapse": "urlkey",
                "fl": "original,timestamp",
                "limit": "100",
            },
            headers=HEADERS, timeout=45,
        )
        if resp.status_code != 200:
            return emails, stats, email_urls
        rows = json.loads(resp.text)
    except Exception:
        return emails, stats, email_urls

    if not rows or len(rows) < 2:
        return emails, stats, email_urls

    stats["pages_found"] = len(rows) - 1
    for row in rows[1:]:
        if len(row) < 2:
            continue
        if stats["pages_fetched"] >= MAX_WAYBACK_PAGES or len(emails) >= MAX_EMAILS:
            break
        if deadline is not None and time.monotonic() > deadline:
            break
        original, ts = row[0], row[1]
        if not is_same_site(original, domain):
            continue
        if _WAYBACK_ASSET_RE.search(urlparse(original).path or "/"):
            continue
        snapshot = f"https://web.archive.org/web/{ts}id_/{original}"
        resp = fetch(snapshot, timeout=10)
        if not resp or resp.status_code != 200:
            continue
        ctype = resp.headers.get("Content-Type", "")
        if ctype and "html" not in ctype.lower():
            continue
        stats["pages_fetched"] += 1
        soup = BeautifulSoup(resp.text, "html.parser")
        for e in extract_emails(resp.text):
            if is_valid_target_email(e, domain):
                emails.setdefault(e, "wayback")
                email_urls.setdefault(e, snapshot)
        for e in extract_mailto_emails(soup):
            if is_valid_target_email(e, domain):
                emails.setdefault(e, "wayback")
                email_urls.setdefault(e, snapshot)

    stats["emails_found"] = len(emails)
    return emails, stats, email_urls


# ---------------------------------------------------------------------------
# GitHub commit harvesting (public API — emails in public git histories)
# ---------------------------------------------------------------------------

def _github_headers() -> dict:
    headers = {**HEADERS, "Accept": "application/vnd.github+json"}
    if settings.GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {settings.GITHUB_TOKEN}"
    return headers


def search_github_commits(domain: str, max_items: int = MAX_GITHUB_COMMITS) -> tuple:
    """Search public commits mentioning the domain -> (people, stats).

    GitHub's commit-search API returns each commit's author/committer name and
    email — a large, legit source of professional contacts, fully public.
    Unauthenticated search is rate-limited (10 req/min); set GITHUB_TOKEN in
    .env to raise it.
    """
    people: dict = {}
    stats = {"requests": 0, "commits_found": 0, "emails_found": 0, "message": ""}
    try:
        resp = requests.get(
            "https://api.github.com/search/commits",
            params={"q": domain, "per_page": min(max_items, 100)},
            headers=_github_headers(),
            timeout=15,
        )
        stats["requests"] += 1
        if resp.status_code == 403:
            stats["message"] = "GitHub rate limit (403) — set GITHUB_TOKEN di .env."
            return people, stats
        if resp.status_code != 200:
            stats["message"] = f"GitHub API error {resp.status_code}."
            return people, stats
        items = resp.json().get("items") or []
        stats["commits_found"] = len(items)
        for item in items:
            commit = item.get("commit") or {}
            # loose search tokenizes the domain; keep only commits whose
            # message actually references the full domain (no 'SIM card' noise)
            if domain not in (commit.get("message") or "").lower():
                continue
            repo = ((item.get("repository") or {}).get("full_name")) or ""
            url = item.get("html_url") or ""
            for who in (commit.get("author"), commit.get("committer")):
                if not who:
                    continue
                email = normalize_email(str(who.get("email") or ""))
                if not email or "@" not in email:
                    continue
                # skip GitHub/other noreply aliases — they are not real mailboxes
                if "noreply" in email or email.endswith("@users.noreply.github.com"):
                    continue
                name = (who.get("name") or "").strip() or email.split("@")[0]
                people.setdefault(email, {
                    "name": name,
                    "email": email,
                    "source": "github",
                    "context": repo,
                    "url": url,
                })
        stats["emails_found"] = len(people)
    except Exception as e:
        stats["message"] = f"GitHub error: {type(e).__name__}."
    return people, stats


# ---------------------------------------------------------------------------
# Public mailing-list archives (mail-archive.com + marc.info)
# ---------------------------------------------------------------------------

def search_mailing_lists(domain: str, max_messages: int = MAX_MAILING_MESSAGES) -> tuple:
    """Search public mailing-list archives -> (people, stats).

    Mailing-list archives publish raw `From:` headers, so they expose the real
    work/personal addresses of people discussing the target domain.
    """
    people: dict = {}
    stats = {"sources": 0, "messages": 0, "emails_found": 0, "message": ""}

    def _add(email: str, context: str, url: str = "") -> None:
        email = normalize_email(email)
        if not email or "@" not in email:
            return
        if email.split("@")[1] in SENTINEL_DOMAINS:
            return
        people.setdefault(email, {
            "name": "",
            "email": email,
            "source": "mailing_list",
            "context": context,
            "url": url,
        })

    # mail-archive.com — plain-HTML search over all public lists
    try:
        resp = requests.get("https://www.mail-archive.com/search",
                            params={"q": domain, "l": "all"},
                            headers=HEADERS, timeout=12)
        if resp.status_code == 200:
            stats["sources"] += 1
            for e in extract_emails(resp.text):
                _add(e, "mail-archive.com")
    except Exception:
        pass

    # marc.info — follow a few message pages (they carry raw From: headers)
    try:
        resp = requests.get("https://marc.info/", params={"s": domain},
                            headers=HEADERS, timeout=12)
        if resp.status_code == 200:
            stats["sources"] += 1
            soup = BeautifulSoup(resp.text, "html.parser")
            hrefs = [a.get("href") for a in soup.find_all("a", href=True)
                     if "m=" in (a.get("href") or "")]
            for href in hrefs[:max_messages]:
                url = urljoin("https://marc.info/", href)
                try:
                    m = requests.get(url, headers=HEADERS, timeout=10)
                    if m.status_code == 200:
                        stats["messages"] += 1
                        for e in extract_emails(m.text):
                            _add(e, "marc.info", url)
                except Exception:
                    continue
    except Exception:
        pass

    stats["emails_found"] = len(people)
    return people, stats


# ---------------------------------------------------------------------------
# Career / job pages (HR & recruitment mailboxes)
# ---------------------------------------------------------------------------

CAREER_PATHS = [
    "/careers", "/career", "/jobs", "/job", "/karir", "/lowongan",
    "/recruitment", "/hiring", "/careers/", "/tentang-kami/karir",
]


def harvest_career_pages(domain: str, deadline: float | None = None) -> tuple:
    """Fetch common career/job pages -> (emails_by_source, stats, email_urls)."""
    emails: dict = {}
    email_urls: dict = {}
    fetched = 0
    for path in CAREER_PATHS:
        if deadline is not None and time.monotonic() > deadline:
            break
        page_url = f"https://{domain}{path}"
        resp = fetch(page_url, timeout=5)
        if not resp or resp.status_code != 200:
            continue
        fetched += 1
        for e in extract_emails(resp.text):
            if is_valid_target_email(e, domain):
                emails.setdefault(e, "careers")
                email_urls.setdefault(e, page_url)
    return emails, {"career_pages_fetched": fetched, "emails_found": len(emails)}, email_urls


# ---------------------------------------------------------------------------
# SMTP verification (RCPT TO probe — no mail is ever sent)
# ---------------------------------------------------------------------------

def _smtp_probe(mx_host: str, email: str, from_addr: str, timeout: int) -> str:
    """Probe one mailbox via SMTP RCPT TO -> ok / rejected / unknown."""
    server = None
    try:
        server = smtplib.SMTP(mx_host, 25, timeout=timeout)
        server.ehlo()
        code, _ = server.mail(from_addr)
        if code >= 400:
            return "unknown"
        code, _ = server.rcpt(email)
        if code >= 500:
            return "rejected"
        if code >= 400:
            return "unknown"
        return "ok"
    except smtplib.SMTPRecipientsRefused:
        return "rejected"
    except Exception:
        return "unknown"
    finally:
        if server is not None:
            try:
                server.close()  # close() — quit() can hang on dead peers
            except Exception:
                pass


def verify_emails_smtp(emails: list, mx_hosts: list, domain: str, *,
                       max_checks: int = MAX_SMTP_CHECKS,
                       working_host: str | None = None,
                       deadline: float | None = None) -> tuple:
    """Verify emails against the domain's mail server (RCPT TO probe).

    Detects catch-all servers. Returns (status_map, stats, meta).
    `working_host`/`deadline` let callers reuse one SMTP session across
    observed emails and pattern candidates (shared time budget).
    """
    stats = {"ok": 0, "rejected": 0, "unknown": 0, "unchecked": 0}
    from_addr = "noreply@example.org"  # neutral sender — never claim the scanned domain

    if not settings.SMTP_VERIFY_ENABLED:
        meta = {"enabled": False, "mx": [], "catch_all": False,
                "working_host": None,
                "message": "Verifikasi SMTP dinonaktifkan (SMTP_VERIFY_ENABLED=false)."}
        return {e: "unchecked" for e in emails}, {**stats, "unchecked": len(emails)}, meta

    if not emails:
        return {}, {**stats, "unchecked": 0}, {
            "enabled": False, "mx": mx_hosts, "catch_all": False,
            "working_host": None, "message": "Tidak ada email untuk diverifikasi.",
        }

    if not mx_hosts:
        meta = {"enabled": False, "mx": [], "catch_all": False, "working_host": None,
                "message": "Domain tidak punya mail server (MX) — verifikasi SMTP dilewati."}
        return {e: "unchecked" for e in emails}, {**stats, "unchecked": len(emails)}, meta

    if deadline is None:
        deadline = time.monotonic() + SMTP_BUDGET_SECONDS

    # find a responsive MX host once (unless caller already found one)
    catch_all = False
    if working_host is None:
        probe_addr = f"nobody-{secrets.token_hex(3)}@{domain}"
        for host in mx_hosts:
            if time.monotonic() > deadline:
                break
            r = _smtp_probe(host, probe_addr, from_addr, SMTP_TIMEOUT)
            if r != "unknown":
                working_host = host
                catch_all = (r == "ok")
                break

    if working_host is None:
        meta = {"enabled": True, "mx": mx_hosts, "catch_all": False,
                "working_host": None,
                "message": "Tidak bisa terhubung ke mail server (port 25 diblokir / server tidak merespons)."}
        return {e: "unknown" for e in emails}, {**stats, "unknown": len(emails)}, meta

    if catch_all:
        meta = {"enabled": True, "mx": mx_hosts, "catch_all": True,
                "working_host": working_host,
                "message": "Mail server menerima semua alamat (catch-all) — verifikasi tidak bisa dipercaya."}
        return {e: "unknown" for e in emails}, {**stats, "unknown": len(emails)}, meta

    # Anti-enumeration detection: if even random non-existent addresses are
    # rejected, "rejected" cannot be trusted as 'mailbox does not exist'
    # (many corporate mail gateways 550 everything).
    anti_enumeration = False
    if working_host:
        rejected_all = True
        for _ in range(2):
            r = _smtp_probe(working_host, f"nobody-{secrets.token_hex(3)}@{domain}",
                            from_addr, SMTP_TIMEOUT)
            if r != "rejected":
                rejected_all = False
                break
        anti_enumeration = rejected_all
    if anti_enumeration:
        meta = {"enabled": True, "mx": mx_hosts, "catch_all": False,
                "working_host": working_host, "anti_enumeration": True,
                "message": "Mail server menolak semua probe (anti-enumeration) — status verifikasi tidak bisa dipercaya."}
        return {e: "unknown" for e in emails}, {**stats, "unknown": len(emails)}, meta

    status_map: dict = {}
    for email in emails:
        if len(status_map) >= max_checks or time.monotonic() > deadline:
            break
        status_map[email] = _smtp_probe(working_host, email, from_addr, SMTP_TIMEOUT)
    for email in emails:
        if email not in status_map:
            status_map[email] = "unchecked"

    for s in status_map.values():
        if s in stats:
            stats[s] += 1

    meta = {"enabled": True, "mx": mx_hosts, "catch_all": False,
            "working_host": working_host,
            "message": f"Verifikasi via {working_host} (probe RCPT TO, tanpa mengirim email)."}
    return status_map, stats, meta


# ---------------------------------------------------------------------------
# Pattern candidates (SMTP-verified only — never shown unverified)
# ---------------------------------------------------------------------------

def generate_pattern_emails(domain: str) -> list:
    return [f"{p}@{domain}" for p in PATTERN_PREFIXES]


# ---------------------------------------------------------------------------
# Deep OSINT tools (BBOT + Holehe — self-hosted CLIs, no API keys)
# ---------------------------------------------------------------------------

def _run_cmd(cmd: list, timeout: int) -> tuple:
    """Run a subprocess; returns (stdout, returncode). Negative codes = errors."""
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=timeout)
        return p.stdout.decode("utf-8", "ignore"), p.returncode
    except subprocess.TimeoutExpired:
        return "", -1
    except FileNotFoundError:
        return "", -2
    except Exception:
        return "", -3


def _tool_bin(name: str) -> str | None:
    """Locate a pipx-installed CLI binary (PATH or ~/.local/bin)."""
    path = shutil.which(name)
    if path and os.access(path, os.X_OK):
        return path
    fallback = os.path.expanduser(f"~/.local/bin/{name}")
    if os.access(fallback, os.X_OK):
        return fallback
    return None


def bbot_enum(domain: str, timeout: int) -> tuple:
    """Run BBOT's email-enum preset -> (emails, subdomains, stats).

    Uses --no-deps so it never asks for root to install module deps; passive
    sources (crt, pgp, securitytxt, sslcert, emailformat, ...) still work.
    """
    emails: set = set()
    subdomains: set = set()
    bin_path = _tool_bin("bbot")
    if bin_path is None:
        return emails, subdomains, {"ran": False,
                                    "message": "BBOT binary tidak ditemukan (pipx install bbot)."}
    outdir = tempfile.mkdtemp(prefix="bbot_")
    try:
        stdout, code = _run_cmd(
            [bin_path, "-t", domain, "-p", "email-enum", "-o", outdir,
             "--json", "--no-color", "--no-deps", "-S"],
            timeout=timeout,
        )
        if code not in (0, -1):
            return emails, subdomains, {"ran": False, "code": code,
                                        "message": f"BBOT gagal dijalankan ({code}). {stdout[-300:].strip()}"}
        for output_file in glob.glob(os.path.join(outdir, "**", "output.json"), recursive=True):
            try:
                with open(output_file, encoding="utf-8", errors="ignore") as fh:
                    for line in fh:
                        try:
                            ev = json.loads(line)
                        except Exception:
                            continue
                        etype = ev.get("type") or ev.get("event_type")
                        data = (ev.get("data") or "").strip()
                        if etype == "EMAIL_ADDRESS" and "@" in data:
                            emails.add(normalize_email(data))
                        elif etype == "DNS_NAME" and data:
                            host = data.lower().rstrip(".")
                            if host.endswith(f".{domain}"):
                                subdomains.add(host)
            except Exception:
                continue
    finally:
        shutil.rmtree(outdir, ignore_errors=True)

    timed_out = " (waktu habis)" if code == -1 else ""
    return emails, subdomains, {
        "ran": True,
        "emails_found": len(emails),
        "subdomains_found": len(subdomains),
        "message": f"BBOT email-enum selesai{timed_out}: {len(emails)} email, {len(subdomains)} subdomain.",
    }


def holehe_check(emails: list, timeout: int) -> dict:
    """Run Holehe per email -> {email: [registered sites]}. Bounded & best-effort."""
    results: dict = {}
    bin_path = _tool_bin("holehe")
    if bin_path is None:
        return results
    # match only "[+] sitename" where sitename is a real domain — the legend
    # line "[+] Email used, [-] Email not used, [x] Rate limit" must be skipped
    site_re = re.compile(r"^\[\+\]\s*([a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,})$")
    for email in emails:
        stdout, _ = _run_cmd([bin_path, email, "--no-color", "--only-used"],
                             timeout=timeout)
        used = []
        for line in stdout.splitlines():
            line = line.strip()
            m = site_re.match(line)
            if m:
                used.append(m.group(1).lower())
        if used:
            results[email] = sorted(set(used))[:25]
    return results


# ---------------------------------------------------------------------------
# Task
# ---------------------------------------------------------------------------

@celery_app.task(name="app.tasks.domain_tasks.process_domain_search")
def process_domain_search(domain: str, scan_id: int, deep: bool = False,
                          sources: list | None = None):
    """Discover email addresses for a domain using self-built OSINT sources."""
    # NOTE: use removeprefix, NOT lstrip — lstrip("www.") strips ANY leading
    # "w"/"." chars (waicast.id -> aicast.id!).
    domain = (domain or "").strip().lower().removeprefix("www.").rstrip(".")
    enabled = set(sources or DEFAULT_SOURCES)
    started = time.time()
    timings = {}
    # Hard global budget: keeps the whole scan under the API's task.get()
    # timeout even for pathological domains (slow crawl / hung MX / etc.).
    # Deep mode gets a bigger budget because BBOT + Holehe need time.
    HARD_DEADLINE = 540.0 if deep else 260.0

    def _remaining() -> float:
        return HARD_DEADLINE - (time.time() - started)

    # 1) DNS + email security posture
    t0 = time.time()
    if "dns" in enabled:
        dns_records, spf, dmarc, mx_count = collect_dns(domain)
    else:
        dns_records, spf, dmarc, mx_count = {}, None, None, 0
    timings["dns"] = int((time.time() - t0) * 1000)

    # 2) Deep crawl (BFS depth-2, up to 40 pages) + robots/sitemap/security.txt
    #    + career/job pages + team-page texts (for name-pattern generation)
    t0 = time.time()
    if "website" in enabled:
        disallowed, robots_sitemaps = get_robots(domain)
        sitemap_urls = get_sitemap_urls(domain, robots_sitemaps)
        security_found, security_contacts, security_txt_urls = get_security_txt(domain)
        crawled_emails, crawl_stats, doc_urls, img_urls, team_texts, crawled_email_urls = crawl_site(
            domain, disallowed, sitemap_urls)
        career_emails, career_stats, career_email_urls = (
            harvest_career_pages(domain, deadline=time.monotonic() + 25)
            if _remaining() > 20 else ({}, {"career_pages_fetched": 0,
                                            "emails_found": 0, "skipped": True}, {}))
    else:
        disallowed, robots_sitemaps = [], []
        sitemap_urls = []
        security_found, security_contacts, security_txt_urls = False, [], {}
        crawled_emails, crawl_stats, doc_urls, img_urls, team_texts, crawled_email_urls = (
            {}, {"pages_crawled": 0, "links_found": 0, "max_depth": 0}, [], [], [], {})
        career_emails, career_stats, career_email_urls = {}, {"career_pages_fetched": 0,
                                                              "emails_found": 0, "skipped": True}, {}
    timings["crawl"] = int((time.time() - t0) * 1000)

    # 3) Public documents (PDF/DOCX/XLSX/TXT...) — skip when budget is tight
    t0 = time.time()
    if "docs" in enabled and _remaining() > 20:
        doc_emails, doc_stats, doc_email_urls = extract_emails_from_docs(doc_urls, domain)
    else:
        doc_emails, doc_stats, doc_email_urls = {}, {"docs_found": len(doc_urls), "docs_parsed": 0,
                                                     "emails_found": 0, "skipped": True}, {}
    timings["docs"] = int((time.time() - t0) * 1000)

    # 3b) Local OCR — images & scanned PDFs (Tesseract, self-hosted)
    t0 = time.time()
    if "docs" in enabled and _remaining() > 20:
        ocr_emails_map, ocr_stats, ocr_email_urls = ocr_emails(img_urls, doc_urls, domain)
    else:
        ocr_emails_map, ocr_stats, ocr_email_urls = ({}, {"enabled": settings.OCR_ENABLED,
                                                          "images_found": len(img_urls),
                                                          "images_ocred": 0, "pdfs_ocred": 0,
                                                          "emails_found": 0, "skipped": True}, {})
    timings["ocr"] = int((time.time() - t0) * 1000)

    # 4) Subdomain enumeration + crawl of active hosts
    t0 = time.time()
    if "subdomains" in enabled and _remaining() > 20:
        subdomains = enumerate_subdomains(domain)
        sub_emails, sub_stats, sub_email_urls = crawl_subdomains(subdomains, domain)
    else:
        subdomains, sub_emails, sub_stats, sub_email_urls = [], {}, {"subdomains_crawled": 0, "skipped": True}, {}
    timings["subdomains"] = int((time.time() - t0) * 1000)

    # 5) WHOIS lookup
    t0 = time.time()
    whois = (whois_lookup(domain) if "whois" in enabled and _remaining() > 10
             else None)
    timings["whois"] = int((time.time() - t0) * 1000)

    # 6) Search-engine layer (multi-query)
    t0 = time.time()
    if "search" in enabled and _remaining() > 10:
        ddg = search_duckduckgo(domain)
        bing = search_bing(domain)
    else:
        ddg, bing = {"emails": [], "results": 0}, {"emails": [], "results": 0}
    timings["search"] = int((time.time() - t0) * 1000)

    # 6b) Wayback Machine — historical pages often still carry the emails
    #     Google indexes but the live site removed/obfuscated.
    t0 = time.time()
    if "wayback" in enabled and _remaining() > 35:
        wb_deadline = time.monotonic() + min(50.0, max(_remaining() - 5, 10))
        wayback_emails, wayback_stats, wayback_email_urls = search_wayback(domain, deadline=wb_deadline)
    else:
        wayback_emails, wayback_stats, wayback_email_urls = {}, {"pages_found": 0, "pages_fetched": 0,
                                                                 "emails_found": 0, "skipped": True}, {}
    timings["wayback"] = int((time.time() - t0) * 1000)

    # 6c) GitHub commit harvesting — emails in public git histories
    t0 = time.time()
    if "github" in enabled and _remaining() > 20:
        gh_people, gh_stats = search_github_commits(domain)
    else:
        gh_people, gh_stats = {}, {"requests": 0, "commits_found": 0,
                                   "emails_found": 0, "skipped": True}
    timings["github"] = int((time.time() - t0) * 1000)

    # 6d) Public mailing-list archives (mail-archive.com + marc.info)
    t0 = time.time()
    if "mailing" in enabled and _remaining() > 20:
        ml_people, ml_stats = search_mailing_lists(domain)
    else:
        ml_people, ml_stats = {}, {"sources": 0, "messages": 0,
                                   "emails_found": 0, "skipped": True}
    timings["mailing"] = int((time.time() - t0) * 1000)

    # 6e) Deep OSINT tools — BBOT email-enum (deep mode only, self-hosted)
    deep_osint = {"bbot": {"ran": False}, "holehe": {"checked": 0, "results": {}}}
    bbot_emails: set = set()
    if deep and settings.DEEP_TOOLS_ENABLED:
        t0 = time.time()
        if _remaining() > 40:
            bbot_emails, bbot_subs, bbot_stats = bbot_enum(
                domain, timeout=int(min(max(_remaining() - 25, 10), 150)))
            deep_osint["bbot"] = bbot_stats
            for host in bbot_subs:
                if host not in subdomains:
                    subdomains.append(host)
            subdomains.sort()
            timings["bbot"] = int((time.time() - t0) * 1000)
        else:
            deep_osint["bbot"]["message"] = "Scan budget exhausted — BBOT skipped."

    # 7) Merge observed emails (website/mailto/security.txt/docs/subdomain/whois/search)
    observed_map: dict = {}
    for email, source in crawled_emails.items():
        observed_map.setdefault(email, source)
    for email, source in career_emails.items():
        observed_map.setdefault(email, source)
    for email, source in doc_emails.items():
        observed_map.setdefault(email, source)
    for email, source in ocr_emails_map.items():
        observed_map.setdefault(email, source)
    for email, source in wayback_emails.items():
        observed_map.setdefault(email, source)
    for email, source in sub_emails.items():
        observed_map.setdefault(email, source)
    for email in gh_people:
        if is_valid_target_email(email, domain):
            observed_map.setdefault(email, "github")
    for email in ml_people:
        if is_valid_target_email(email, domain):
            observed_map.setdefault(email, "mailing_list")
    for email in security_contacts:
        observed_map.setdefault(email, "security_txt")
    if whois:
        for email in whois["emails"]:
            if is_valid_target_email(email, domain):
                observed_map.setdefault(email, "whois")
    for email in ddg["emails"] + bing["emails"]:
        if is_valid_target_email(email, domain):
            observed_map.setdefault(email, "search")
    bbot_added = 0
    for email in sorted(bbot_emails):
        if bbot_added >= MAX_BBOT_EMAILS:
            break
        if is_valid_target_email(email, domain) and email not in observed_map:
            observed_map[email] = "bbot"
            bbot_added += 1

    # Track the public URL where each observed email was found (redirect icon).
    email_urls: dict = {}
    for mapping in (crawled_email_urls, career_email_urls, doc_email_urls,
                    ocr_email_urls, wayback_email_urls, sub_email_urls,
                    security_txt_urls):
        for e, u in mapping.items():
            if u:
                email_urls.setdefault(e, u)
    for e, u in (ddg.get("urls") or {}).items():
        if u:
            email_urls.setdefault(e, u)
    for e, u in (bing.get("urls") or {}).items():
        if u:
            email_urls.setdefault(e, u)
    for email, p in gh_people.items():
        if email in observed_map and p.get("url"):
            email_urls.setdefault(email, p["url"])
    for email, p in ml_people.items():
        if email in observed_map and p.get("url"):
            email_urls.setdefault(email, p["url"])

    email_list = [
        {"email": e, "source": src, "verified": True,
         "url": email_urls.get(e, "")}
        for e, src in sorted(observed_map.items(),
                             key=lambda kv: (SOURCE_PRIORITY.get(kv[1], 9), kv[0]))
    ][:MAX_EMAILS]

    # 8) SMTP verification (RCPT TO probe — no mail is ever sent)
    mx_hosts = []
    for mx in dns_records.get("MX", []):
        parts = str(mx).split()
        if parts:
            host = parts[-1].rstrip(".").lower()
            if host and host != "." and host not in mx_hosts:
                mx_hosts.append(host)

    smtp_deadline = time.monotonic() + min(SMTP_BUDGET_SECONDS, max(_remaining(), 5))
    if "smtp" in enabled:
        smtp_status, smtp_stats, smtp_meta = verify_emails_smtp(
            [e["email"] for e in email_list], mx_hosts, domain, deadline=smtp_deadline
        )
    else:
        smtp_status = {e["email"]: "unchecked" for e in email_list}
        smtp_stats = {"ok": 0, "rejected": 0, "unknown": 0,
                      "unchecked": len(email_list)}
        smtp_meta = {"enabled": False, "mx": mx_hosts, "catch_all": False,
                     "working_host": None,
                     "message": "Verifikasi SMTP dimatikan (sumber tidak dipilih)."}
    for e in email_list:
        e["smtp"] = smtp_status.get(e["email"], "unchecked")

    # 9) Pattern candidates — ONLY included when SMTP-verified as active.
    #    No MX / unreachable MX / catch-all / anti-enumeration → no patterns
    #    at all (nothing shown unless the mailbox provably exists).
    pattern_verified: list = []
    pattern_names: list = []
    if "patterns" in enabled:
        for p in gh_people.values():
            nm = (p.get("name") or "").strip()
            if nm and nm not in pattern_names:
                pattern_names.append(nm)
        for nm in extract_names_from_texts(team_texts, max_names=MAX_PATTERN_NAMES):
            if nm not in pattern_names:
                pattern_names.append(nm)
        pattern_names = pattern_names[:MAX_PATTERN_NAMES]
    if ("patterns" in enabled and "smtp" in enabled
            and mx_count and smtp_meta.get("working_host")
            and not smtp_meta.get("catch_all")
            and not smtp_meta.get("anti_enumeration")):
        candidates = [p for p in generate_pattern_emails(domain)
                      if p not in observed_map][:MAX_PATTERN_CHECKS]
        for nm in pattern_names:
            for cand in name_patterns(nm, domain):
                if (cand not in observed_map and cand not in candidates
                        and len(candidates) < MAX_PATTERN_CHECKS + MAX_NAME_PATTERN_CHECKS):
                    candidates.append(cand)
        if candidates:
            pat_status, pat_stats, _ = verify_emails_smtp(
                candidates, mx_hosts, domain,
                max_checks=len(candidates),
                working_host=smtp_meta["working_host"],
                deadline=smtp_deadline,
            )
            pattern_verified = [e for e, s in pat_status.items() if s == "ok"]
            for k in ("ok", "rejected", "unknown", "unchecked"):
                smtp_stats[k] = smtp_stats.get(k, 0) + pat_stats[k]

    for email in pattern_verified:
        email_list.append({
            "email": email, "source": "pattern_verified",
            "verified": True, "smtp": "ok",
        })

    # sort: confirmed-active first, rejected last
    smtp_rank = {"ok": 0, "unknown": 1, "unchecked": 2, "rejected": 3}
    email_list.sort(key=lambda e: smtp_rank.get(e["smtp"], 1))

    # 9b) Holehe — account footprint for the top-found emails (deep mode)
    if deep and settings.DEEP_TOOLS_ENABLED and email_list:
        t0 = time.time()
        to_check = [e["email"] for e in email_list[:MAX_HOLEHE_EMAILS]]
        # per-email budget derived from remaining time so we never overshoot
        per_email = max(int((_remaining() - 5) / max(len(to_check), 1)), 10)
        per_email = min(per_email, 40)
        hole_results = holehe_check(to_check, timeout=per_email)
        deep_osint["holehe"] = {
            "checked": len(to_check),
            "results": hole_results,
            "message": (f"{len(hole_results)} email dengan jejak akun publik."
                         if hole_results else "Tidak ada jejak akun terdeteksi."),
        }
        timings["holehe"] = int((time.time() - t0) * 1000)

    # 9c) People & contacts from GitHub + mailing-list archives (Hunter-style)
    people_map: dict = {}
    for email, p in gh_people.items():
        people_map.setdefault(email, p)
    for email, p in ml_people.items():
        people_map.setdefault(email, p)
    people_list = [people_map[k] for k in sorted(people_map)][:MAX_PEOPLE]

    observed = len(observed_map)
    observed = min(observed, MAX_EMAILS)

    # 10) Confidence score
    score = 30
    if mx_count:
        score += 15
    if spf:
        score += 10
    if dmarc:
        score += 10
    if observed:
        score += 15
    if smtp_stats.get("ok"):
        score += 10
    if security_found:
        score += 5
    if whois:
        score += 5
    if subdomains:
        score += 5
    if people_list:
        score += 5
    score = min(score, 100)

    timings["total"] = int((time.time() - started) * 1000)

    return {
        "domain": domain,
        "scan_id": scan_id,
        "status": "completed",
        "duration_ms": timings["total"],
        "results": {
            "emails": email_list,
            "email_stats": {
                "observed": observed,
                "pattern_verified": len(pattern_verified),
                "smtp_ok": smtp_stats.get("ok", 0),
                "smtp_rejected": smtp_stats.get("rejected", 0),
                "smtp_unknown": smtp_stats.get("unknown", 0),
                "smtp_unchecked": smtp_stats.get("unchecked", 0),
            },
            "smtp_check": smtp_meta,
            "dns_records": dns_records,
            "spf": spf,
            "dmarc": dmarc,
            "security_posture": {
                "mx": bool(mx_count),
                "spf": bool(spf),
                "dmarc": bool(dmarc),
            },
            "security_txt": {
                "found": security_found,
                "contacts": security_contacts,
            },
            "crawl_stats": crawl_stats,
            "doc_stats": doc_stats,
            "ocr_stats": ocr_stats,
            "wayback_stats": wayback_stats,
            "subdomains": subdomains,
            "subdomain_stats": sub_stats,
            "whois": whois,
            "search_stats": {
                "duckduckgo_results": ddg["results"],
                "bing_results": bing["results"],
            },
            "github_stats": gh_stats,
            "mailing_stats": ml_stats,
            "career_stats": career_stats,
            "people": people_list,
            "deep_osint": deep_osint,
            "confidence_score": score,
            "timings": timings,
        },
    }
