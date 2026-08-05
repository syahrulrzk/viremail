"use client";

import { useEffect, useRef, useState } from "react";
import {
  Search,
  Mail,
  Shield,
  Database,
  Activity,
  AlertTriangle,
  CheckCircle,
  Copy,
  Check,
  Globe,
  Lock,
  Server,
  Clock,
  ChevronDown,
  X,
  Sparkles,
  Terminal,
  Network,
  RefreshCw,
  History,
  FileText,
  Users,
  Briefcase,
  GitBranch,
  MailOpen,
  ScanText,
  Bot,
  Zap,
  Crosshair,
  ExternalLink,
  FileSpreadsheet,
  FileDown,
  type LucideIcon,
} from "lucide-react";
import Image from "next/image";
import { Button } from "@/components/ui/button";

// Default points at the server's LAN IP so scans work from any device —
// "localhost" would resolve to the visitor's own machine.
const API_BASE =
  process.env.NEXT_PUBLIC_API_URL || "http://172.16.19.235:8000/api/v1";

const SCAN_STEPS = [
  { icon: Network, label: "Fetching DNS records, SPF & DMARC" },
  { icon: Globe, label: "Deep crawling pages, documents & images" },
  { icon: Server, label: "Enumerating subdomains & WHOIS lookup" },
  { icon: Search, label: "Searching search engines (multi-query)" },
  { icon: History, label: "Checking Wayback Machine archives" },
  { icon: FileText, label: "Running OCR on images & scanned PDFs" },
  { icon: Sparkles, label: "Verifying via SMTP & building results" },
];

const SCAN_MODES: { value: string; label: string; desc: string; icon: LucideIcon }[] = [
  {
    value: "standard",
    label: "Standard scan",
    desc: "All 11 engines · fast baseline",
    icon: Zap,
  },
  {
    value: "deep",
    label: "Deep OSINT",
    desc: "BBOT + Holehe · ~2–5 min extra",
    icon: Sparkles,
  },
];

const SOURCE_META: Record<string, { label: string; cls: string; icon: LucideIcon }> = {
  website: { label: "Website", cls: "bg-emerald-500/10 text-emerald-400 border-emerald-500/30", icon: Globe },
  mailto: { label: "mailto", cls: "bg-emerald-500/10 text-emerald-400 border-emerald-500/30", icon: Mail },
  careers: { label: "Careers", cls: "bg-amber-500/10 text-amber-400 border-amber-500/30", icon: Briefcase },
  github: { label: "GitHub", cls: "bg-zinc-400/10 text-zinc-300 border-zinc-400/30", icon: GitBranch },
  mailing_list: { label: "Mailing List", cls: "bg-indigo-500/10 text-indigo-400 border-indigo-500/30", icon: MailOpen },
  security_txt: { label: "security.txt", cls: "bg-amber-500/10 text-amber-400 border-amber-500/30", icon: Shield },
  document: { label: "Document", cls: "bg-teal-500/10 text-teal-400 border-teal-500/30", icon: FileText },
  search: { label: "Search Engine", cls: "bg-sky-500/10 text-sky-400 border-sky-500/30", icon: Search },
  wayback: { label: "Archive", cls: "bg-indigo-500/10 text-indigo-400 border-indigo-500/30", icon: History },
  ocr: { label: "OCR", cls: "bg-violet-500/10 text-violet-400 border-violet-500/30", icon: ScanText },
  subdomain: { label: "Subdomain", cls: "bg-cyan-500/10 text-cyan-400 border-cyan-500/30", icon: Network },
  whois: { label: "WHOIS", cls: "bg-orange-500/10 text-orange-400 border-orange-500/30", icon: Server },
  bbot: { label: "BBOT", cls: "bg-fuchsia-500/10 text-fuchsia-400 border-fuchsia-500/30", icon: Bot },
  pattern_verified: { label: "Pattern (SMTP ✓)", cls: "bg-emerald-500/10 text-emerald-400 border-emerald-500/30", icon: Sparkles },
};

const SOURCE_FALLBACK: { label: string; cls: string; icon: LucideIcon } = {
  label: "Other",
  cls: "bg-zinc-500/10 text-zinc-400 border-zinc-500/30",
  icon: Database,
};

interface EmailResult {
  email: string;
  source: string;
  verified: boolean;
  smtp?: "ok" | "rejected" | "unknown" | "unchecked";
  url?: string;
}

interface Person {
  name: string;
  email: string;
  source: string;
  context?: string;
  url?: string;
}

interface ScanResult {
  domain: string;
  status: string;
  duration_ms?: number;
  task_id?: string;
  message?: string;
  error?: string;
  from_cache?: boolean;
  cached_at?: string;
  cached_hits?: number;
  results?: {
    emails: EmailResult[];
    email_stats: {
      observed: number;
      pattern_verified?: number;
      smtp_ok?: number;
      smtp_rejected?: number;
      smtp_unknown?: number;
      smtp_unchecked?: number;
    };
    smtp_check?: {
      enabled: boolean;
      mx: string[];
      catch_all: boolean;
      anti_enumeration?: boolean;
      message: string;
    };
    dns_records: Record<string, string[]>;
    spf: string | null;
    dmarc: string | null;
    security_posture: { mx: boolean; spf: boolean; dmarc: boolean };
    security_txt: { found: boolean; contacts: string[] };
    crawl_stats: { pages_crawled: number; links_found: number; max_depth?: number };
    doc_stats: { docs_found?: number; docs_parsed?: number; emails_found?: number };
    ocr_stats?: {
      enabled?: boolean;
      images_found?: number;
      images_ocred?: number;
      pdfs_ocred?: number;
      emails_found?: number;
      message?: string;
    };
    wayback_stats: {
      pages_found?: number;
      pages_fetched?: number;
      emails_found?: number;
      skipped?: boolean;
    };
    subdomains: string[];
    subdomain_stats: { subdomains_crawled?: number };
    people?: Person[];
    github_stats?: {
      requests?: number;
      commits_found?: number;
      emails_found?: number;
      message?: string;
    };
    mailing_stats?: {
      sources?: number;
      messages?: number;
      emails_found?: number;
      message?: string;
    };
    career_stats?: { career_pages_fetched?: number; emails_found?: number };
    deep_osint?: {
      bbot: {
        ran?: boolean;
        emails_found?: number;
        emails_valid?: number;
        emails_external?: number;
        subdomains_found?: number;
        message?: string;
      };
      holehe: {
        checked?: number;
        results?: Record<string, string[]>;
        message?: string;
      };
    };
    whois: {
      registrar?: string | string[] | null;
      creation_date?: string | null;
      expiration_date?: string | null;
      updated_date?: string | null;
      name_servers?: string[];
      emails?: string[];
      raw_found?: boolean;
    } | null;
    search_stats: { duckduckgo_results: number; bing_results: number };
    confidence_score: number;
    timings: Record<string, number>;
  };
}

interface RecentSearch {
  domain: string;
  time: number;
}

// Human-readable age for the VIRE Atlas cache badge, e.g. "3h ago".
function cacheAge(cachedAt?: string): string {
  if (!cachedAt) return "cached";
  const t = new Date(cachedAt).getTime();
  if (isNaN(t)) return "cached";
  const mins = Math.max(1, Math.round((Date.now() - t) / 60000));
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.round(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.round(hrs / 24)}d ago`;
}

// Google dork queries — Google blocks automated scraping, so these are meant
// to be run manually by the user in their own browser.
function buildDorks(domain: string): { label: string; q: string }[] {
  return [
    { label: "site:", q: `site:${domain} "@${domain}"` },
    { label: "email:", q: `"@${domain}" email` },
    { label: "contact:", q: `site:${domain} "@${domain}" contact` },
  ];
}

export default function Home() {
  const [query, setQuery] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [step, setStep] = useState(0);
  const [elapsed, setElapsed] = useState(0);
  const [copied, setCopied] = useState<string | null>(null);
  const [deep, setDeep] = useState(false);
  const [recent, setRecent] = useState<RecentSearch[]>([]);
  const [openDns, setOpenDns] = useState(true);
  const [openEmails, setOpenEmails] = useState(true);
  const [modeOpen, setModeOpen] = useState(false);
  const [typewriterText, setTypewriterText] = useState("");
  const [showCursor, setShowCursor] = useState(true);
  const [exporting, setExporting] = useState<"excel" | "pdf" | null>(null);
  const resultsRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const modeRef = useRef<HTMLDivElement>(null);

  // Load recent searches only after hydration (avoid SSR/client mismatch).
  useEffect(() => {
    const t = setTimeout(() => {
      try {
        const raw = localStorage.getItem("osintmail_recent");
        if (raw) setRecent(JSON.parse(raw));
      } catch {}
    }, 0);
    return () => clearTimeout(t);
  }, []);

  // JavaScript-based typewriter effect
  useEffect(() => {
    const targetText = "domain";
    let index = 0;

    const typeNext = () => {
      if (index < targetText.length) {
        setTypewriterText(targetText.slice(0, index + 1));
        index++;
        setTimeout(typeNext, 150);
      } else {
        // Hide cursor after typing completes
        setTimeout(() => setShowCursor(false), 500);
      }
    };

    const t = setTimeout(typeNext, 500);
    return () => {
      clearTimeout(t);
      setShowCursor(true);
      setTypewriterText("");
    };
  }, []);

  useEffect(() => {
    if (!loading) return;
    const stepTimer = setInterval(() => {
      setStep((s) => Math.min(s + 1, SCAN_STEPS.length - 1));
    }, 2600);
    const clockTimer = setInterval(() => setElapsed((e) => e + 1), 1000);
    return () => {
      clearInterval(stepTimer);
      clearInterval(clockTimer);
    };
  }, [loading]);

  // close the scan-mode dropdown on outside click
  useEffect(() => {
    if (!modeOpen) return;
    const handler = (e: MouseEvent) => {
      if (modeRef.current && !modeRef.current.contains(e.target as Node)) {
        setModeOpen(false);
      }
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, [modeOpen]);

  const saveRecent = (domain: string) => {
    const next = [
      { domain, time: Date.now() },
      ...recent.filter((r) => r.domain !== domain),
    ].slice(0, 6);
    setRecent(next);
    try {
      localStorage.setItem("osintmail_recent", JSON.stringify(next));
    } catch {}
  };

  const removeRecent = (domain: string) => {
    const next = recent.filter((r) => r.domain !== domain);
    setRecent(next);
    try {
      localStorage.setItem("osintmail_recent", JSON.stringify(next));
    } catch {}
  };

  const handleSearch = async (domain?: string, force = false) => {
    const value = (domain ?? query).trim().toLowerCase();
    if (!value) return;

    const cleanedBase = value
      .replace(/^https?:\/\//, "")
      .replace(/^www\./, "")
      .split(/[/?#]/)[0] // drop path, query string and hash
      .trim();
    const cleaned = cleanedBase.split("@")[1] || cleanedBase;
    if (!cleaned.includes(".")) {
      setError("Invalid domain format. Example: example.com");
      return;
    }

    setLoading(true);
    setResult(null);
    setError(null);
    setQuery(cleaned);
    setStep(0);
    setElapsed(0);
    saveRecent(cleaned);

    try {
      const res = await fetch(`${API_BASE}/search/domain`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain: cleaned, deep, force }),
      });
      const data = await res.json();
      if (!res.ok) {
        // Surface backend validation/errors (e.g. 422) instead of a blank screen
        const detail = data?.detail;
        setError(
          typeof detail === "string"
            ? detail
            : `Backend error (HTTP ${res.status})`
        );
        return;
      }
      setResult(data);
      setTimeout(() => {
        resultsRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
      }, 150);
    } catch {
      setError(
        "Failed to reach the backend. Make sure the API is running on localhost:8000."
      );
    } finally {
      setLoading(false);
    }
  };

  const copyText = async (text: string, key: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(key);
      setTimeout(() => setCopied(null), 1600);
    } catch {}
  };

  const copyAll = async () => {
    const emails = (result?.results?.emails ?? []).map((e: EmailResult) => e.email);
    if (emails.length) await copyText(emails.join("\n"), "all");
  };

  const handleExport = async (kind: "excel" | "pdf") => {
    if (!result || exporting) return;
    setExporting(kind);
    // Let the spinner paint before the (synchronous) file generation kicks in.
    await new Promise((res) => setTimeout(res, 30));
    try {
      // Dynamic import keeps the heavy export libs out of the initial bundle.
      const mod = await import("@/lib/export");
      if (kind === "excel") mod.exportToExcel(result);
      else mod.exportToPdf(result);
    } catch (err) {
      console.error(`Export ${kind} failed`, err);
      setError(`Failed to export ${kind === "excel" ? "Excel" : "PDF"}. Please try again.`);
    } finally {
      setExporting(null);
    }
  };

  const r = result?.results;
  const emails: EmailResult[] = r?.emails ?? [];
  const emailStats: {
    observed?: number;
    pattern_verified?: number;
    smtp_ok?: number;
    smtp_rejected?: number;
    smtp_unknown?: number;
    smtp_unchecked?: number;
  } = r?.email_stats ?? {};
  const smtpCheck: {
    enabled?: boolean;
    mx?: string[];
    catch_all?: boolean;
    anti_enumeration?: boolean;
    message?: string;
  } = r?.smtp_check ?? {};
  const dns: Record<string, string[]> = r?.dns_records ?? {};
  const posture: { mx?: boolean; spf?: boolean; dmarc?: boolean } =
    r?.security_posture ?? {};
  const hasMx = !!posture.mx;
  const score: number = r?.confidence_score ?? 0;
  const timings: Record<string, number> = r?.timings ?? {};
  const crawlStats: { pages_crawled?: number; links_found?: number } =
    r?.crawl_stats ?? {};
  const searchStats: { duckduckgo_results?: number; bing_results?: number } =
    r?.search_stats ?? {};
  const securityTxt: { found?: boolean; contacts?: string[] } =
    r?.security_txt ?? {};
  const whois: {
    registrar?: string | string[] | null;
    creation_date?: string | null;
    expiration_date?: string | null;
    updated_date?: string | null;
    name_servers?: string[];
    emails?: string[];
    raw_found?: boolean;
  } | null = r?.whois ?? null;
  const subdomains: string[] = r?.subdomains ?? [];
  const people: Person[] = r?.people ?? [];
  const githubStats = r?.github_stats ?? {};
  const mailingStats = r?.mailing_stats ?? {};
  const careerStats = r?.career_stats ?? {};
  const ocrStats: {
    enabled?: boolean;
    images_found?: number;
    images_ocred?: number;
    pdfs_ocred?: number;
    emails_found?: number;
    message?: string;
  } = r?.ocr_stats ?? {};
  const waybackStats: {
    pages_found?: number;
    pages_fetched?: number;
    emails_found?: number;
    skipped?: boolean;
  } = r?.wayback_stats ?? {};
  const docStats: { docs_found?: number; docs_parsed?: number } =
    r?.doc_stats ?? {};
  const deepOsint: {
    bbot?: {
      ran?: boolean;
      emails_found?: number;
      emails_valid?: number;
      emails_external?: number;
      subdomains_found?: number;
      message?: string;
    };
    holehe?: { checked?: number; results?: Record<string, string[]>; message?: string };
  } | null = r?.deep_osint ?? null;
  const processing = result?.status === "processing";
  const failed = result?.status === "error";

  return (
    <div className="min-h-screen bg-background text-foreground relative overflow-x-hidden">
      {/* ambient background */}
      <div className="pointer-events-none fixed inset-0 osint-grid opacity-60" />
      <div className="pointer-events-none fixed -top-40 left-1/2 -translate-x-1/2 h-[500px] w-[900px] rounded-full bg-primary/10 blur-[140px]" />
      <div className="pointer-events-none fixed bottom-0 right-0 h-[400px] w-[500px] rounded-full bg-fuchsia-500/5 blur-[120px]" />

      {/* ================= FIXED TOP BAR ================= */}
      <header className="fixed top-0 left-0 right-0 z-50 border-b border-border/60 bg-background/85 backdrop-blur-xl">
        <div className="max-w-6xl mx-auto px-4 sm:px-5 py-3 sm:py-3.5 flex items-center justify-between">
          <div className="flex items-center gap-2.5 sm:gap-3 min-w-0">
            <Image
              src="/logo2.png"
              alt="VIRE"
              width={546}
              height={98}
              className="h-5 w-auto sm:h-6 shrink-0 object-contain"
            />
          </div>
          <div className="hidden md:flex items-center gap-2 text-xs text-muted-foreground border border-border/70 bg-card/60 rounded-full px-3 py-1.5 backdrop-blur shrink-0">
            <Shield className="w-3.5 h-3.5 text-emerald-400" />
            100% self-built · no third-party APIs
          </div>
        </div>
      </header>

      <main className="relative z-10 max-w-6xl mx-auto px-4 sm:px-5 pt-20 sm:pt-24 pb-28">
        {/* ================= HERO ================= */}
        <section
          className={`text-center ${
            !result && !loading
              ? "min-h-[calc(100dvh_-_7.5rem)] flex flex-col justify-center pt-2 pb-10"
              : "pt-10 md:pt-12"
          }`}
        >
          <Image
            src="/logo2.png"
            alt="VIRE"
            width={546}
            height={98}
            priority
            className="animate-fade-up mx-auto mb-1 h-10 w-auto sm:h-12 md:h-14 object-contain drop-shadow-[0_0_30px_rgba(56,189,248,0.2)]"
          />

          {/* tagline — flush against the logo */}
          <div
            className="animate-fade-up flex items-center justify-center gap-2 sm:gap-3 mb-6 sm:mb-7 px-2"
            style={{ animationDelay: "100ms" }}
          >
            <span className="hidden sm:block h-px w-10 sm:w-14 bg-gradient-to-r from-transparent to-primary/40" />
            <span className="text-[10px] sm:text-[11px] font-semibold uppercase tracking-[0.2em] sm:tracking-[0.25em] text-muted-foreground text-center">
              Verified Intelligence <span className="text-primary">&</span> Recon Engine
            </span>
            <span className="hidden sm:block h-px w-10 sm:w-14 bg-gradient-to-l from-transparent to-primary/40" />
          </div>

          <h1 className="animate-fade-up text-2xl sm:text-3xl md:text-4xl lg:text-5xl font-bold tracking-tight mb-4 text-center leading-tight">
            <span>Discover public emails from any</span>
            <span className="gradient-text ml-1">
              {typewriterText}
              {showCursor && <span className="animate-pulse">|</span>}
            </span>
            <span>.</span>
          </h1>
          <p
            className="animate-fade-up text-xs sm:text-sm md:text-base text-muted-foreground max-w-2xl mx-auto leading-relaxed mb-8 px-1"
            style={{ animationDelay: "80ms" }}
          >
            Enter a domain to discover publicly available email addresses using
            website crawling, DNS records, public documents, certificate
            transparency, and other open-source intelligence sources.
          </p>

          {/* ================= SCAN CONSOLE ================= */}
          <div
            className="animate-fade-up w-full max-w-3xl mx-auto px-2 sm:px-0"
            style={{ animationDelay: "240ms" }}
          >
            <div
              className={`group relative rounded-2xl border bg-card/70 backdrop-blur-xl shadow-2xl shadow-black/40 transition-all duration-300 focus-within:border-primary/60 focus-within:ring-4 focus-within:ring-primary/10 animate-scale-in ${
                deep
                  ? "border-fuchsia-500/50 shadow-fuchsia-500/15"
                  : "border-border/70 hover:border-primary/40"
              }`}
            >
              {/* row 1: target input + scan button */}
              <div className="flex flex-col sm:flex-row items-stretch gap-2 sm:gap-0 p-2">
                <div className="flex items-center flex-1 min-w-0">
                  <div className="flex items-center pl-3 pr-2 text-muted-foreground">
                    <Globe className="w-5 h-5 shrink-0" />
                  </div>
                  <input
                    ref={inputRef}
                    type="text"
                    value={query}
                    onChange={(e) => setQuery(e.target.value)}
                    onKeyDown={(e) => e.key === "Enter" && handleSearch()}
                    placeholder="Enter a domain… e.g. example.com"
                    className="w-full min-w-0 bg-transparent px-3 py-3 sm:py-3.5 text-base sm:text-lg outline-none placeholder:text-muted-foreground/60 font-mono"
                    spellCheck={false}
                    autoFocus
                  />
                </div>
                <Button
                  onClick={() => handleSearch()}
                  disabled={loading || !query.trim()}
                  className="w-full sm:w-auto justify-center px-5 md:px-7 py-3 sm:py-3.5 h-auto rounded-xl text-base font-semibold bg-gradient-to-r from-primary to-fuchsia-500 hover:from-primary/90 hover:to-fuchsia-500/90 shadow-lg shadow-primary/25 disabled:opacity-40 animate-pulse-glow"
                >
                  {loading ? (
                    <span className="flex items-center gap-2">
                      <Activity className="w-5 h-5 animate-spin" /> Scanning…
                    </span>
                  ) : (
                    <span className="flex items-center gap-2">
                      <Search className="w-5 h-5" /> Scan
                    </span>
                  )}
                </Button>
              </div>

              {/* divider */}
              <div className="mx-3 h-px bg-gradient-to-r from-transparent via-border/70 to-transparent" />

              {/* row 2: scan mode dropdown — full-width inside the panel */}
              <div
                className={`flex items-center justify-between gap-3 px-4 sm:px-5 py-3.5 transition-colors duration-200 ${
                  deep ? "bg-fuchsia-500/[0.07]" : "hover:bg-white/[0.02]"
                }`}
              >
                <span className="flex items-center gap-2.5 min-w-0">
                  <span
                    className={`w-8 h-8 shrink-0 rounded-lg flex items-center justify-center transition-colors duration-200 ${
                      deep
                        ? "bg-fuchsia-500/15 text-fuchsia-300"
                        : "bg-white/[0.03] text-muted-foreground"
                    }`}
                  >
                    <Crosshair className="w-4 h-4" />
                  </span>
                  <span className="min-w-0 text-left">
                    <span
                      className={`block text-xs font-semibold transition-colors duration-200 ${
                        deep ? "text-fuchsia-300" : "text-foreground/90"
                      }`}
                    >
                      Scan Mode
                    </span>
                    <span className="block text-[11px] text-muted-foreground/70 truncate">
                      {deep
                        ? "BBOT + Holehe — deeper, but slower (~2–5 min extra)"
                        : "All 11 engines — fast baseline"}
                    </span>
                  </span>
                </span>

                {/* dropdown */}
                <div ref={modeRef} className="relative shrink-0">
                  <button
                    type="button"
                    onClick={() => setModeOpen((v) => !v)}
                    aria-haspopup="listbox"
                    aria-expanded={modeOpen}
                    className={`flex items-center gap-2 rounded-lg border px-3 py-2 text-xs font-semibold transition-all duration-200 ${
                      deep
                        ? "border-fuchsia-500/40 bg-fuchsia-500/10 text-fuchsia-300 hover:bg-fuchsia-500/20"
                        : "border-border/70 bg-black/30 text-foreground hover:border-primary/50"
                    }`}
                  >
                    {deep ? (
                      <Sparkles className="w-3.5 h-3.5" />
                    ) : (
                      <Zap className="w-3.5 h-3.5" />
                    )}
                    {deep ? "Deep OSINT" : "Standard"}
                    <ChevronDown
                      className={`w-3.5 h-3.5 transition-transform duration-200 ${
                        modeOpen ? "rotate-180" : ""
                      }`}
                    />
                  </button>

                  {modeOpen && (
                    <div className="absolute right-0 top-full mt-2 z-30 w-64 rounded-xl border border-border/70 bg-popover shadow-2xl shadow-black/50 overflow-hidden animate-fade-up">
                      {SCAN_MODES.map((m) => {
                        const active = m.value === (deep ? "deep" : "standard");
                        return (
                          <button
                            key={m.value}
                            type="button"
                            onClick={() => {
                              setDeep(m.value === "deep");
                              setModeOpen(false);
                            }}
                            className={`w-full flex items-start gap-2.5 px-3.5 py-3 text-left transition-colors ${
                              active ? "bg-primary/10" : "hover:bg-white/[0.03]"
                            }`}
                          >
                            <m.icon
                              className={`w-4 h-4 mt-0.5 shrink-0 ${
                                active ? "text-primary" : "text-muted-foreground"
                              }`}
                            />
                            <span className="min-w-0 flex-1">
                              <span
                                className={`block text-xs font-semibold ${
                                  active ? "text-primary" : "text-foreground"
                                }`}
                              >
                                {m.label}
                              </span>
                              <span className="block text-[10px] text-muted-foreground/80">
                                {m.desc}
                              </span>
                            </span>
                            {active && (
                              <Check className="w-3.5 h-3.5 text-primary shrink-0 mt-0.5" />
                            )}
                          </button>
                        );
                      })}
                    </div>
                  )}
                </div>
              </div>

              {/* row 3: engine list — differentiates standard vs deep mode */}
              <div className="px-4 sm:px-5 py-2.5 border-t border-border/40 flex flex-wrap items-center justify-between gap-x-3 gap-y-1 text-[10px] text-muted-foreground/50 font-mono">
                <span className="flex items-center gap-2 min-w-0">
                  <span className="flex items-center gap-1 shrink-0">
                    <Database className="w-3 h-3 text-primary/70" />
                    {deep ? 13 : 11} engines
                  </span>
                  <span className="text-muted-foreground/30 shrink-0">·</span>
                  <span className="truncate">
                    dns · web · docs · ocr · subdomains · whois · search · wayback · github · mailing · smtp
                    {deep && (
                      <span className="text-fuchsia-400"> · bbot · holehe</span>
                    )}
                  </span>
                </span>
                <span
                  className={`shrink-0 rounded-full border px-2 py-0.5 uppercase tracking-wider ${
                    deep
                      ? "border-fuchsia-500/40 bg-fuchsia-500/10 text-fuchsia-300"
                      : "border-border/50 bg-black/30 text-muted-foreground/60"
                  }`}
                >
                  {deep ? "deep" : "standard"}
                </span>
              </div>
            </div>

            {/* recent searches */}
            {recent.length > 0 && !loading && (
              <div className="mt-5 flex flex-wrap items-center justify-center gap-2">
                <span className="flex items-center gap-1.5 text-xs text-muted-foreground">
                  <History className="w-3.5 h-3.5" /> Recent:
                </span>
                {recent.map((r) => (
                  <button
                    key={r.domain}
                    onClick={() => handleSearch(r.domain)}
                    className="group/chip flex items-center gap-1.5 font-mono text-xs border border-border/70 bg-card/50 rounded-full px-3 py-1.5 hover:border-primary/50 hover:text-primary transition-all"
                  >
                    {r.domain}
                    <span
                      onClick={(e) => {
                        e.stopPropagation();
                        removeRecent(r.domain);
                      }}
                      className="text-muted-foreground/60 hover:text-red-400 transition-colors"
                    >
                      <X className="w-3 h-3" />
                    </span>
                  </button>
                ))}
              </div>
            )}

            {error && (
              <div className="mt-5 mx-auto max-w-xl flex items-center gap-2 text-sm text-red-400 bg-red-500/10 border border-red-500/30 rounded-xl px-4 py-3">
                <AlertTriangle className="w-4 h-4 shrink-0" /> {error}
              </div>
            )}
          </div>
        </section>

        {/* ================= SCANNING STATE ================= */}
        {loading && (
          <section className="max-w-3xl mx-auto mt-14 animate-fade-up">
            <div className="relative rounded-2xl border border-primary/25 bg-black/50 backdrop-blur overflow-hidden">
              <div className="scan-line" />
              <div className="flex items-center gap-2 px-5 pt-4 pb-2 border-b border-border/50 text-xs text-muted-foreground font-mono">
                <Terminal className="w-3.5 h-3.5 text-primary" />
                vire — reconnaissance in progress
                <span className="ml-auto text-primary">{elapsed}s</span>
              </div>
              <div className="p-5 md:p-6 space-y-3 font-mono text-sm">
                {SCAN_STEPS.map((s, i) => {
                  const done = i < step;
                  const active = i === step;
                  return (
                    <div
                      key={s.label}
                      className={`flex items-center gap-3 transition-all duration-300 ${
                        active ? "text-primary" : done ? "text-muted-foreground/70" : "text-muted-foreground/35"
                      }`}
                    >
                      {done ? (
                        <CheckCircle className="w-4 h-4 text-emerald-400 shrink-0" />
                      ) : active ? (
                        <s.icon className="w-4 h-4 animate-spin shrink-0" />
                      ) : (
                        <s.icon className="w-4 h-4 shrink-0" />
                      )}
                      <span>{s.label}</span>
                      {active && <span className="cursor-blink text-primary">▌</span>}
                    </div>
                  );
                })}
              </div>
              <div className="px-5 pb-4 pt-1 text-xs text-muted-foreground/60 font-mono flex items-center gap-2">
                <span className="relative flex h-2 w-2">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-60" />
                  <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-400" />
                </span>
                scraping public sources — keep this tab open
              </div>
            </div>
          </section>
        )}

        {/* ================= RESULTS ================= */}
        {result && !loading && (
          <div ref={resultsRef} className="mt-14 space-y-8 scroll-mt-28">
            {/* summary card */}
            <div className="animate-fade-up rounded-2xl border border-border/70 bg-card/60 backdrop-blur-xl p-6 md:p-8">
              <div className="flex flex-col md:flex-row md:items-center gap-6 justify-between">
                <div>
                  <div className="flex items-center gap-3 flex-wrap">
                    <Globe className="w-6 h-6 text-primary" />
                    <h2 className="text-2xl md:text-3xl font-bold font-mono break-all">
                      {result.domain}
                    </h2>
                    {result.status === "completed" && (
                      <span className="flex items-center gap-1 text-xs text-emerald-400 bg-emerald-500/10 border border-emerald-500/30 rounded-full px-3 py-1">
                        <CheckCircle className="w-3.5 h-3.5" /> Scan complete
                      </span>
                    )}
                    {result.from_cache && (
                      <span
                        className="flex items-center gap-1 text-xs text-sky-300 bg-sky-500/10 border border-sky-500/40 rounded-full px-3 py-1"
                        title={`Served from VIRE Atlas (cached ${result.cached_at ? new Date(result.cached_at).toLocaleString() : ""})`}
                      >
                        <Database className="w-3.5 h-3.5" />
                        VIRE Atlas · {cacheAge(result.cached_at)}
                        {typeof result.cached_hits === "number" && result.cached_hits > 1 && (
                          <span className="opacity-70">· {result.cached_hits}× served</span>
                        )}
                      </span>
                    )}
                  </div>
                  <div className="mt-3 flex flex-wrap items-center gap-x-5 gap-y-2 text-sm text-muted-foreground">
                    <span className="flex items-center gap-1.5">
                      <Mail className="w-4 h-4 text-primary" />
                      <b className="text-foreground">{emailStats.observed ?? 0}</b> emails found
                    </span>
                    <span className="flex items-center gap-1.5">
                      <CheckCircle className="w-4 h-4 text-emerald-400" />
                      <b className="text-foreground">{emailStats.smtp_ok ?? 0}</b> active (SMTP)
                    </span>
                    {(emailStats.pattern_verified ?? 0) > 0 && (
                      <span className="flex items-center gap-1.5">
                        <Sparkles className="w-4 h-4 text-emerald-400" />
                        <b className="text-foreground">{emailStats.pattern_verified ?? 0}</b> verified patterns
                      </span>
                    )}
                    {(emailStats.smtp_rejected ?? 0) > 0 && (
                      <span className="flex items-center gap-1.5">
                        <AlertTriangle className="w-4 h-4 text-red-400" />
                        <b className="text-foreground">{emailStats.smtp_rejected ?? 0}</b> invalid
                      </span>
                    )}
                    <span className="flex items-center gap-1.5">
                      <Clock className="w-4 h-4" />
                      {(timings.total ?? 0) / 1000}s
                    </span>
                  </div>
                </div>

                {/* confidence gauge */}
                <div className="flex items-center gap-4 shrink-0">
                  <div
                    className="relative w-24 h-24 rounded-full"
                    style={{
                      background: `conic-gradient(var(--primary) ${score * 3.6}deg, oklch(0.3 0.02 258 / 0.4) 0deg)`,
                    }}
                  >
                    <div className="absolute inset-[7px] rounded-full bg-card flex items-center justify-center flex-col">
                      <div className="text-2xl font-black text-primary">{score}</div>
                      <div className="text-[9px] uppercase tracking-wider text-muted-foreground">confidence</div>
                    </div>
                  </div>
                </div>
              </div>

              {/* security posture */}
              <div className="mt-6 grid grid-cols-1 sm:grid-cols-3 gap-3">
                {[
                  { key: "mx", label: "Mail server (MX)", icon: Server, ok: posture.mx },
                  { key: "spf", label: "SPF Record", icon: Shield, ok: posture.spf },
                  { key: "dmarc", label: "DMARC Record", icon: Lock, ok: posture.dmarc },
                ].map((p) => (
                  <div
                    key={p.key}
                    className={`flex items-center gap-3 rounded-xl border px-4 py-3.5 transition-all hover:scale-[1.02] ${
                      p.ok
                        ? "border-emerald-500/30 bg-emerald-500/5"
                        : "border-border/70 bg-black/30"
                    }`}
                  >
                    <p.icon className={`w-5 h-5 shrink-0 ${p.ok ? "text-emerald-400" : "text-muted-foreground/50"}`} />
                    <div className="min-w-0">
                      <div className="text-sm font-medium truncate">{p.label}</div>
                      <div className={`text-xs font-mono ${p.ok ? "text-emerald-400" : "text-muted-foreground/60"}`}>
                        {p.ok ? "detected" : "not found"}
                      </div>
                    </div>
                  </div>
                ))}
              </div>

              {/* google dorking — Google blocks automated scraping, run manually */}
              <div className="mt-6 pt-5 border-t border-border/50">
                <div className="text-xs text-muted-foreground mb-3 flex items-center gap-2">
                  <Search className="w-3.5 h-3.5 text-sky-400" />
                  Google Dorking — click to open in Google (run manually; Google blocks
                  automated scraping). Tip: emails Google shows often live on archived or
                  third-party pages — the scan now also checks the Wayback Machine.
                </div>
                <div className="flex flex-wrap gap-2">
                  {buildDorks(result.domain).map((d) => (
                    <button
                      key={d.q}
                      onClick={() =>
                        window.open(
                          `https://www.google.com/search?q=${encodeURIComponent(d.q)}`,
                          "_blank",
                          "noopener,noreferrer"
                        )
                      }
                      title={d.q}
                      className="group flex items-center gap-2 font-mono text-xs border border-border/70 bg-black/30 rounded-lg px-3 py-2 hover:border-sky-400/50 hover:text-sky-300 hover:bg-sky-500/5 transition-all"
                    >
                      <span className="text-sky-400 shrink-0">{d.label}</span>
                      <span className="text-muted-foreground/70 truncate max-w-[200px] group-hover:text-sky-300/70 transition-colors">
                        {d.q}
                      </span>
                    </button>
                  ))}
                </div>
              </div>
            </div>

            {/* export toolbar */}
            {result.status === "completed" && (
            <div className="animate-fade-up rounded-2xl border border-border/70 bg-card/60 backdrop-blur-xl overflow-hidden">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 px-6 py-5">
                <div className="flex items-center gap-3">
                  <div className="w-9 h-9 rounded-lg bg-emerald-500/10 flex items-center justify-center">
                    <FileDown className="w-5 h-5 text-emerald-400" />
                  </div>
                  <div className="text-left">
                    <h3 className="font-semibold text-lg leading-tight">Export Report</h3>
                    <p className="text-xs text-muted-foreground">
                      Download the full scan log as Excel or a printable PDF report
                    </p>
                  </div>
                </div>
                <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-2.5">
                  <Button
                    variant="outline"
                    size="lg"
                    disabled={exporting !== null}
                    onClick={() => handleExport("excel")}
                    className="justify-center rounded-xl border-emerald-500/40 bg-emerald-500/10 text-emerald-300 hover:bg-emerald-500/20 hover:border-emerald-400/60 hover:text-emerald-200 transition-all"
                  >
                    {exporting === "excel" ? (
                      <Activity className="w-4 h-4 animate-spin" />
                    ) : (
                      <FileSpreadsheet className="w-4 h-4" />
                    )}
                    Export Excel (.xlsx)
                  </Button>
                  <Button
                    variant="outline"
                    size="lg"
                    disabled={exporting !== null}
                    onClick={() => handleExport("pdf")}
                    className="justify-center rounded-xl border-red-500/40 bg-red-500/10 text-red-300 hover:bg-red-500/20 hover:border-red-400/60 hover:text-red-200 transition-all"
                  >
                    {exporting === "pdf" ? (
                      <Activity className="w-4 h-4 animate-spin" />
                    ) : (
                      <FileText className="w-4 h-4" />
                    )}
                    Export PDF Report
                  </Button>
                </div>
              </div>
              <div className="px-6 pb-4 text-[11px] text-muted-foreground/70 flex flex-wrap items-center gap-x-4 gap-y-1">
                <span className="flex items-center gap-1.5">
                  <FileSpreadsheet className="w-3.5 h-3.5 text-emerald-400" />
                  Excel: Summary · Emails · People · DNS · Subdomains · WHOIS · Holehe
                </span>
                <span className="flex items-center gap-1.5">
                  <FileText className="w-3.5 h-3.5 text-red-400" />
                  PDF: formatted A4 report, ready to share
                </span>
              </div>
            </div>
            )}

            {/* emails section */}
            <section className="animate-fade-up rounded-2xl border border-border/70 bg-card/60 backdrop-blur-xl overflow-hidden">
              <div
                role="button"
                tabIndex={0}
                onClick={() => setOpenEmails((v) => !v)}
                onKeyDown={(e) => {
                  if (e.key === "Enter" || e.key === " ") {
                    e.preventDefault();
                    setOpenEmails((v) => !v);
                  }
                }}
                className="w-full flex items-center justify-between px-6 py-5 hover:bg-white/[0.02] transition-colors cursor-pointer outline-none focus-visible:ring-2 focus-visible:ring-ring/40"
              >
                <div className="flex items-center gap-3">
                  <div className="w-9 h-9 rounded-lg bg-primary/10 flex items-center justify-center">
                    <Mail className="w-5 h-5 text-primary" />
                  </div>
                  <div className="text-left">
                    <h3 className="font-semibold text-lg leading-tight">Emails Found</h3>
                    <p className="text-xs text-muted-foreground">
                      {emails.length} results · verified from crawl / search engines
                    </p>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  {emails.length > 0 && (
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={(e) => {
                        e.stopPropagation();
                        copyAll();
                      }}
                    >
                      {copied === "all" ? (
                        <Check className="w-4 h-4 text-emerald-400" />
                      ) : (
                        <Copy className="w-4 h-4" />
                      )}
                      Copy all
                    </Button>
                  )}
                  <ChevronDown
                    className={`w-5 h-5 text-muted-foreground transition-transform ${openEmails ? "rotate-180" : ""}`}
                  />
                </div>
              </div>

              {openEmails && (
                <div className="px-6 pb-6">
                  {smtpCheck.enabled && emails.length > 0 && (
                    <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-[11px] text-muted-foreground mb-4">
                      <span className="flex items-center gap-1.5">
                        <CheckCircle className="w-3.5 h-3.5 text-emerald-400" />
                        {emailStats.smtp_ok ?? 0} active (SMTP confirmed)
                      </span>
                      <span className="flex items-center gap-1.5">
                        <X className="w-3.5 h-3.5 text-red-400" />
                        {emailStats.smtp_rejected ?? 0} mailbox does not exist
                      </span>
                      <span className="flex items-center gap-1.5">
                        <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
                        {emailStats.smtp_unknown ?? 0} inconclusive
                      </span>
                      {smtpCheck.catch_all ? (
                        <span className="text-amber-400/90">Mail server is catch-all — verification is unreliable.</span>
                      ) : smtpCheck.anti_enumeration ? (
                        <span className="text-amber-400/90">Mail server rejects all probes (anti-enumeration) — verification results are unreliable.</span>
                      ) : smtpCheck.message &&
                        (emailStats.smtp_ok ?? 0) + (emailStats.smtp_rejected ?? 0) === 0 ? (
                        <span className="text-zinc-400">{smtpCheck.message}</span>
                      ) : null}
                    </div>
                  )}
                  {emails.length === 0 ? (
                    <div className="rounded-xl border border-dashed border-border/70 p-8 text-center text-sm text-muted-foreground">
                      <AlertTriangle className="w-5 h-5 mx-auto mb-3 text-amber-400" />
                      <p className="text-foreground font-medium mb-1">
                        No public emails found for {result.domain}
                      </p>
                      <p>
                        No address @{result.domain} is published on the website or indexed by
                        search engines.
                      </p>
                      {!hasMx && (
                        <p className="mt-4 inline-block text-xs text-amber-300 bg-amber-500/10 border border-amber-500/30 rounded-lg px-4 py-2.5">
                          This domain has no mail server (MX record) — email @{result.domain} may
                          not be able to receive mail at all.
                        </p>
                      )}
                    </div>
                  ) : (
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                      {emails.map((e: EmailResult, idx: number) => {
                        const meta = SOURCE_META[e.source] ?? SOURCE_FALLBACK;
                        const key = `email-${e.email}`;
                        return (
                          <div
                            key={key}
                            className={`group flex items-center gap-3 rounded-xl border border-border/70 bg-black/30 px-4 py-3.5 hover:border-primary/40 hover:bg-primary/5 transition-all animate-fade-up ${
                              e.smtp === "rejected" ? "opacity-60" : ""
                            }`}
                            style={{ animationDelay: `${Math.min(idx * 40, 400)}ms` }}
                          >
                            <div
                              className={`w-8 h-8 rounded-lg flex items-center justify-center shrink-0 ${
                                e.smtp === "ok"
                                  ? "bg-emerald-500/10 text-emerald-400"
                                  : e.smtp === "rejected"
                                    ? "bg-red-500/10 text-red-400"
                                    : "bg-zinc-500/10 text-zinc-400"
                              }`}
                            >
                              {e.smtp === "ok" ? (
                                <CheckCircle className="w-4 h-4" />
                              ) : e.smtp === "rejected" ? (
                                <X className="w-4 h-4" />
                              ) : (
                                <Mail className="w-4 h-4" />
                              )}
                            </div>
                            <div className="min-w-0 flex-1">
                              <div className="font-mono text-sm text-foreground truncate">{e.email}</div>
                              <div className="flex flex-wrap items-center gap-1 mt-1">
                                {e.url ? (
                                  <a
                                    href={e.url}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    title={`Source: ${e.url}`}
                                    className={`inline-flex items-center gap-1 text-[10px] font-medium border rounded-full px-2 py-0.5 hover:brightness-125 hover:border-primary/50 transition-all ${meta.cls}`}
                                  >
                                    <meta.icon className="w-3 h-3" />
                                    {meta.label}
                                    <ExternalLink className="w-2.5 h-2.5 opacity-70" />
                                  </a>
                                ) : (
                                  <span
                                    className={`inline-flex items-center gap-1 text-[10px] font-medium border rounded-full px-2 py-0.5 ${meta.cls}`}
                                  >
                                    <meta.icon className="w-3 h-3" />
                                    {meta.label}
                                  </span>
                                )}
                                {e.smtp === "ok" && (
                                  <span className="inline-flex items-center gap-1 text-[10px] font-medium border border-emerald-500/40 bg-emerald-500/15 text-emerald-300 rounded-full px-2 py-0.5">
                                    <CheckCircle className="w-3 h-3" /> Active (SMTP)
                                  </span>
                                )}
                                {e.smtp === "rejected" && (
                                  <span className="inline-flex items-center gap-1 text-[10px] font-medium border border-red-500/40 bg-red-500/15 text-red-300 rounded-full px-2 py-0.5">
                                    <X className="w-3 h-3" /> Not found (SMTP)
                                  </span>
                                )}
                                {e.smtp === "unknown" && (
                                  <span className="inline-flex items-center gap-1 text-[10px] font-medium border border-zinc-500/40 bg-zinc-500/10 text-zinc-400 rounded-full px-2 py-0.5">
                                    ? Inconclusive (SMTP)
                                  </span>
                                )}
                              </div>
                            </div>
                            <Button
                              variant="ghost"
                              size="icon"
                              className="opacity-0 group-hover:opacity-100 transition-opacity shrink-0"
                              onClick={() => copyText(e.email, key)}
                            >
                              {copied === key ? (
                                <Check className="w-4 h-4 text-emerald-400" />
                              ) : (
                                <Copy className="w-4 h-4" />
                              )}
                            </Button>
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>
              )}
            </section>

            {/* People & contacts (GitHub + mailing lists) */}
            {people.length > 0 && (
              <section className="animate-fade-up rounded-2xl border border-border/70 bg-card/60 backdrop-blur-xl overflow-hidden">
                <div className="flex items-center gap-3 px-6 py-5 border-b border-border/50">
                  <div className="w-9 h-9 rounded-lg bg-zinc-500/10 flex items-center justify-center">
                    <Users className="w-5 h-5 text-zinc-300" />
                  </div>
                  <div>
                    <h3 className="font-semibold text-lg leading-tight">People & Contacts</h3>
                    <p className="text-xs text-muted-foreground">
                      {people.length} contacts · public git histories & mailing-list archives
                    </p>
                  </div>
                </div>
                <div className="p-6 grid grid-cols-1 md:grid-cols-2 gap-3">
                  {people.map((p) => {
                    const pkey = `person-${p.email}`;
                    const initials = (p.name || p.email)
                      .split(/[\s@.]+/)
                      .filter(Boolean)
                      .slice(0, 2)
                      .map((w) => w[0]?.toUpperCase())
                      .join("");
                    return (
                      <div
                        key={pkey}
                        className="group flex items-center gap-3 rounded-xl border border-border/70 bg-black/30 px-4 py-3.5 hover:border-primary/40 hover:bg-primary/5 transition-all"
                      >
                        <div className="w-9 h-9 rounded-full bg-gradient-to-br from-primary/30 to-fuchsia-500/30 border border-primary/30 flex items-center justify-center text-xs font-bold text-primary shrink-0">
                          {initials || "?"}
                        </div>
                        <div className="min-w-0 flex-1">
                          <div className="text-sm font-medium truncate">{p.name || "Unknown"}</div>
                          <div className="font-mono text-xs text-muted-foreground truncate">{p.email}</div>
                          {p.context && (
                            <div className="text-[10px] text-muted-foreground/60 truncate mt-0.5">
                              {p.source === "github" ? "GitHub" : "Mailing list"} · {p.context}
                            </div>
                          )}
                        </div>
                        {p.url && (
                          <a
                            href={p.url}
                            target="_blank"
                            rel="noopener noreferrer"
                            onClick={(e) => e.stopPropagation()}
                            className="text-muted-foreground/50 hover:text-primary transition-colors shrink-0"
                            title="Open source"
                          >
                            <Globe className="w-4 h-4" />
                          </a>
                        )}
                        <Button
                          variant="ghost"
                          size="icon"
                          className="shrink-0 opacity-0 group-hover:opacity-100 transition-opacity"
                          onClick={() => copyText(p.email, pkey)}
                        >
                          {copied === pkey ? (
                            <Check className="w-4 h-4 text-emerald-400" />
                          ) : (
                            <Copy className="w-4 h-4" />
                          )}
                        </Button>
                      </div>
                    );
                  })}
                </div>
              </section>
            )}

            {/* WHOIS + subdomain intel */}
            {(whois || subdomains.length > 0) && (
              <section className="animate-fade-up rounded-2xl border border-border/70 bg-card/60 backdrop-blur-xl overflow-hidden">
                <div className="flex items-center gap-3 px-6 py-5 border-b border-border/50">
                  <div className="w-9 h-9 rounded-lg bg-cyan-500/10 flex items-center justify-center">
                    <Server className="w-5 h-5 text-cyan-400" />
                  </div>
                  <div>
                    <h3 className="font-semibold text-lg leading-tight">Advanced Recon</h3>
                    <p className="text-xs text-muted-foreground">WHOIS · subdomain enumeration</p>
                  </div>
                </div>
                <div className="p-6 grid grid-cols-1 md:grid-cols-2 gap-6">
                  {whois && (
                    <div className="space-y-3">
                      <div className="flex items-center gap-2 text-sm font-medium text-orange-300">
                        <Globe className="w-4 h-4" /> WHOIS
                      </div>
                      <div className="grid grid-cols-2 gap-x-4 gap-y-2 text-xs">
                        {whois.registrar && (
                          <>
                            <span className="text-muted-foreground">Registrar</span>
                            <span className="font-mono text-foreground break-all">
                              {Array.isArray(whois.registrar) ? whois.registrar.join(", ") : whois.registrar}
                            </span>
                          </>
                        )}
                        {whois.creation_date && (
                          <>
                            <span className="text-muted-foreground">Created</span>
                            <span className="font-mono text-foreground">{whois.creation_date}</span>
                          </>
                        )}
                        {whois.expiration_date && (
                          <>
                            <span className="text-muted-foreground">Expires</span>
                            <span className="font-mono text-foreground">{whois.expiration_date}</span>
                          </>
                        )}
                      </div>
                      {(whois.emails ?? []).length > 0 && (
                        <div className="flex flex-wrap gap-1.5 pt-1">
                          {(whois.emails ?? []).map((em) => (
                            <button
                              key={em}
                              onClick={() => copyText(em, `whois-${em}`)}
                              title={`${em} — click to copy`}
                              className="font-mono text-[11px] border border-orange-500/30 bg-orange-500/10 text-orange-300 rounded-full px-2.5 py-1 hover:border-orange-400/60 transition-all"
                            >
                              {copied === `whois-${em}` ? (
                                <Check className="w-3 h-3 inline mr-1 text-emerald-400" />
                              ) : (
                                <Copy className="w-3 h-3 inline mr-1" />
                              )}
                              {em}
                            </button>
                          ))}
                        </div>
                      )}
                    </div>
                  )}
                  {subdomains.length > 0 && (
                    <div className="space-y-3">
                      <div className="flex items-center gap-2 text-sm font-medium text-cyan-300">
                        <Network className="w-4 h-4" />
                        Subdomain ({subdomains.length})
                        <span className="text-[11px] text-muted-foreground font-normal">
                          · {(r?.subdomain_stats?.subdomains_crawled ?? 0)} crawled
                        </span>
                      </div>
                      <div className="flex flex-wrap gap-1.5">
                        {subdomains.map((s) => (
                          <span
                            key={s}
                            className="font-mono text-[11px] border border-cyan-500/30 bg-cyan-500/10 text-cyan-300 rounded-full px-2.5 py-1"
                          >
                            {s}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              </section>
            )}

            {/* Deep OSINT tools (BBOT + Holehe) */}
            {deepOsint && (
              <section className="animate-fade-up rounded-2xl border border-border/70 bg-card/60 backdrop-blur-xl overflow-hidden">
                <div className="flex items-center gap-3 px-6 py-5 border-b border-border/50">
                  <div className="w-9 h-9 rounded-lg bg-fuchsia-500/10 flex items-center justify-center">
                    <Sparkles className="w-5 h-5 text-fuchsia-400" />
                  </div>
                  <div>
                    <h3 className="font-semibold text-lg leading-tight">Deep OSINT Tools</h3>
                    <p className="text-xs text-muted-foreground">BBOT · Holehe — self-hosted</p>
                  </div>
                </div>
                <div className="p-6 space-y-5">
                  {deepOsint.bbot && (
                    <div className="flex flex-wrap items-center gap-x-6 gap-y-2 text-sm">
                      <span className="flex items-center gap-2 font-medium text-fuchsia-300 shrink-0">
                        <Network className="w-4 h-4" /> BBOT
                      </span>
                      <span className="text-muted-foreground">
                        {deepOsint.bbot.message ?? (deepOsint.bbot.ran ? "Done" : "Skipped")}
                      </span>
                      {deepOsint.bbot.ran &&
                        typeof deepOsint.bbot.emails_valid === "number" && (
                          <span className="flex flex-wrap items-center gap-2">
                            <span className="rounded-md border border-emerald-500/30 bg-emerald-500/10 px-2 py-0.5 text-xs font-medium text-emerald-400">
                              {deepOsint.bbot.emails_valid} valid @domain
                            </span>
                            <span className="rounded-md border border-zinc-500/30 bg-zinc-500/10 px-2 py-0.5 text-xs font-medium text-zinc-400">
                              {deepOsint.bbot.emails_external ?? 0} eksternal dibuang
                            </span>
                          </span>
                        )}
                    </div>
                  )}
                  {deepOsint.holehe?.results &&
                    Object.keys(deepOsint.holehe.results).length > 0 && (
                      <div className="space-y-3">
                        <div className="text-sm font-medium text-fuchsia-300">
                          Holehe — where these emails are registered
                        </div>
                        {Object.entries(deepOsint.holehe.results).map(([em, sites]) => (
                          <div
                            key={em}
                            className="rounded-lg bg-black/30 border border-border/50 p-3.5"
                          >
                            <div className="font-mono text-xs text-foreground mb-2">{em}</div>
                            <div className="flex flex-wrap gap-1.5">
                              {sites.map((s) => (
                                <span
                                  key={s}
                                  className="font-mono text-[11px] border border-fuchsia-500/30 bg-fuchsia-500/10 text-fuchsia-300 rounded-full px-2.5 py-1"
                                >
                                  {s}
                                </span>
                              ))}
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                </div>
              </section>
            )}

            {/* intelligence details */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* DNS */}
              <section className="animate-fade-up rounded-2xl border border-border/70 bg-card/60 backdrop-blur-xl overflow-hidden">
                <button
                  onClick={() => setOpenDns((v) => !v)}
                  className="w-full flex items-center justify-between px-6 py-5 hover:bg-white/[0.02] transition-colors"
                >
                  <div className="flex items-center gap-3">
                    <div className="w-9 h-9 rounded-lg bg-primary/10 flex items-center justify-center">
                      <Database className="w-5 h-5 text-primary" />
                    </div>
                    <div className="text-left">
                      <h3 className="font-semibold text-lg leading-tight">DNS Records</h3>
                      <p className="text-xs text-muted-foreground">
                        A · AAAA · MX · NS · TXT
                      </p>
                    </div>
                  </div>
                  <ChevronDown
                    className={`w-5 h-5 text-muted-foreground transition-transform ${openDns ? "rotate-180" : ""}`}
                  />
                </button>
                {openDns && (
                  <div className="px-6 pb-6 space-y-3">
                    {Object.entries(dns).map(([type, records]) => (
                      <div key={type}>
                        <div className="flex items-center gap-2 mb-1.5">
                          <span className="font-mono text-xs font-bold text-primary bg-primary/10 border border-primary/20 rounded px-2 py-0.5">
                            {type}
                          </span>
                          <span className="text-[11px] text-muted-foreground">
                            {Array.isArray(records) ? records.length : 0} records
                          </span>
                        </div>
                        <div className="rounded-lg bg-black/30 border border-border/50 px-3.5 py-2.5 font-mono text-xs text-muted-foreground break-all leading-relaxed">
                          {Array.isArray(records) && records.length > 0 ? (
                            records.map((r: string, i: number) => (
                              <div key={i} className="truncate hover:text-foreground transition-colors" title={r}>
                                {r}
                              </div>
                            ))
                          ) : (
                            <span className="text-muted-foreground/40">— not found —</span>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </section>

              {/* security & stats */}
              <section className="animate-fade-up space-y-6" style={{ animationDelay: "80ms" }}>
                <div className="rounded-2xl border border-border/70 bg-card/60 backdrop-blur-xl p-6">
                  <div className="flex items-center gap-3 mb-4">
                    <div className="w-9 h-9 rounded-lg bg-emerald-500/10 flex items-center justify-center">
                      <Shield className="w-5 h-5 text-emerald-400" />
                    </div>
                    <h3 className="font-semibold text-lg leading-tight">Email Security</h3>
                  </div>
                  <div className="space-y-3">
                    <div>
                      <div className="text-xs text-muted-foreground mb-1.5 font-mono uppercase tracking-wide">SPF</div>
                      <div className="rounded-lg bg-black/30 border border-border/50 px-3.5 py-2.5 font-mono text-xs break-all">
                        {r?.spf ? (
                          <span className="text-emerald-400">{r.spf}</span>
                        ) : (
                          <span className="text-muted-foreground/40">— not found —</span>
                        )}
                      </div>
                    </div>
                    <div>
                      <div className="text-xs text-muted-foreground mb-1.5 font-mono uppercase tracking-wide">DMARC</div>
                      <div className="rounded-lg bg-black/30 border border-border/50 px-3.5 py-2.5 font-mono text-xs break-all">
                        {r?.dmarc ? (
                          <span className="text-emerald-400">{r.dmarc}</span>
                        ) : (
                          <span className="text-muted-foreground/40">— not found —</span>
                        )}
                      </div>
                    </div>
                    {securityTxt.found && (
                      <div>
                        <div className="text-xs text-muted-foreground mb-1.5 font-mono uppercase tracking-wide">security.txt</div>
                        <div className="rounded-lg bg-black/30 border border-amber-500/30 px-3.5 py-2.5 font-mono text-xs">
                          <span className="text-amber-400">
                            ✓ found — {(securityTxt.contacts ?? []).join(", ") || "no contacts"}
                          </span>
                        </div>
                      </div>
                    )}
                  </div>
                </div>

                <div className="rounded-2xl border border-border/70 bg-card/60 backdrop-blur-xl p-6">
                  <div className="flex items-center gap-3 mb-4">
                    <div className="w-9 h-9 rounded-lg bg-fuchsia-500/10 flex items-center justify-center">
                      <Activity className="w-5 h-5 text-fuchsia-400" />
                    </div>
                    <h3 className="font-semibold text-lg leading-tight">Recon Stats</h3>
                  </div>
                  <div className="grid grid-cols-2 gap-3 text-center">
                    {[
                      { label: "Pages crawled", value: crawlStats.pages_crawled ?? 0 },
                      { label: "Links found", value: crawlStats.links_found ?? 0 },
                      { label: "Subdomains", value: subdomains.length },
                      { label: "Docs parsed", value: docStats.docs_parsed ?? 0 },
                      { label: "Archived pages", value: waybackStats.pages_fetched ?? 0 },
                      { label: "DDG results", value: searchStats.duckduckgo_results ?? 0 },
                      { label: "Bing results", value: searchStats.bing_results ?? 0 },
                      { label: "Archive emails", value: waybackStats.emails_found ?? 0 },
                      { label: "GitHub contacts", value: githubStats.emails_found ?? 0 },
                      { label: "List emails", value: mailingStats.emails_found ?? 0 },
                      { label: "Career emails", value: careerStats.emails_found ?? 0 },
                    ].map((s) => (
                      <div key={s.label} className="rounded-xl border border-border/50 bg-black/30 px-3 py-4 hover:border-primary/40 transition-colors">
                        <div className="text-2xl font-black text-primary">{s.value}</div>
                        <div className="text-[11px] text-muted-foreground mt-1">{s.label}</div>
                      </div>
                    ))}
                  </div>
                  {(ocrStats.images_ocred ?? 0) > 0 || (ocrStats.pdfs_ocred ?? 0) > 0 ? (
                    <div className="mt-4 pt-4 border-t border-border/50 text-[11px] text-violet-300/90 flex items-center gap-2">
                      <FileText className="w-3.5 h-3.5 shrink-0" />
                      OCR: {ocrStats.images_ocred ?? 0} images · {ocrStats.pdfs_ocred ?? 0} scanned PDFs
                      {(ocrStats.emails_found ?? 0) > 0 && (
                        <span className="text-emerald-400">→ {(ocrStats.emails_found ?? 0)} emails found</span>
                      )}
                    </div>
                  ) : null}
                  <div className="mt-4 pt-4 border-t border-border/50 flex items-center justify-between text-xs text-muted-foreground font-mono">
                    <span className="flex items-center gap-1.5">
                      <Clock className="w-3.5 h-3.5" /> DNS {(timings.dns ?? 0) / 1000}s · Crawl{" "}
                      {(timings.crawl ?? 0) / 1000}s · OCR {(timings.ocr ?? 0) / 1000}s · Search{" "}
                      {(timings.search ?? 0) / 1000}s
                    </span>
                    <span className="text-primary">{result.duration_ms} ms total</span>
                  </div>
                </div>
              </section>
            </div>

            {/* status banners */}
            {processing && (
              <div className="rounded-2xl border border-amber-500/30 bg-amber-500/5 p-5 text-sm text-amber-300 flex items-center gap-3">
                <Activity className="w-5 h-5 animate-spin shrink-0" />
                Search is still running in the background (task {result.task_id}). Try scanning again in a few seconds.
              </div>
            )}
            {failed && (
              <div className="rounded-2xl border border-red-500/30 bg-red-500/5 p-5 text-sm text-red-300 flex items-center gap-3">
                <AlertTriangle className="w-5 h-5 shrink-0" />
                {result.message} {result.error ? `(${result.error})` : ""}
              </div>
            )}

            {/* rescan */}
            <div className="flex flex-col sm:flex-row items-center justify-center gap-3 pt-2">
              <Button
                variant="outline"
                size="lg"
                onClick={() => handleSearch(result.domain, true)}
                className="rounded-xl"
              >
                <RefreshCw className="w-4 h-4" />
                {result.from_cache ? "Rescan (fresh data)" : "Rescan this domain"}
              </Button>
              {result.from_cache && (
                <span className="text-[11px] text-muted-foreground/70 flex items-center gap-1.5">
                  <Database className="w-3.5 h-3.5 text-sky-400" />
                  Data from VIRE Atlas — rescan to refresh
                </span>
              )}
            </div>
          </div>
        )}

      </main>

      {/* ================= FIXED BOTTOM BAR ================= */}
      <footer className="fixed bottom-0 left-0 right-0 z-50 border-t border-border/60 bg-background/85 backdrop-blur-xl">
        <div className="max-w-6xl mx-auto px-4 sm:px-5 py-2.5 sm:py-3 flex flex-col sm:flex-row items-center justify-between gap-1 text-[10px] sm:text-xs text-muted-foreground">
          <div className="flex items-center gap-1.5">
            <Image
              src="/logo2.png"
              alt="VIRE"
              width={546}
              height={98}
              className="h-4 w-auto shrink-0 object-contain"
            />
          </div>
          <div className="flex items-center gap-1.5 font-mono">
            <Lock className="w-3 h-3 sm:w-3.5 sm:h-3.5 shrink-0" />
            For legal & educational use only
          </div>
        </div>
      </footer>
    </div>
  );
}
