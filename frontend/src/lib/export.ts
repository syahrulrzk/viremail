"use client";

import * as XLSX from "xlsx-js-style";
import { jsPDF } from "jspdf";
import autoTable from "jspdf-autotable";

/* ------------------------------------------------------------------ */
/* Types — structural mirror of ScanResult in page.tsx                */
/* ------------------------------------------------------------------ */

interface EmailResult {
  email: string;
  source: string;
  verified: boolean;
  smtp?: "ok" | "rejected" | "unknown" | "unchecked";
  url?: string;
  confidence?: number;
}

interface Person {
  name: string;
  email: string;
  source: string;
  context?: string;
  url?: string;
}

interface ExportResult {
  domain: string;
  status: string;
  duration_ms?: number;
  task_id?: string;
  message?: string;
  error?: string;
  mode?: string;
  freshness?: string;
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
    dkim?: { selector?: string; record?: string } | null;
    security_posture: { mx: boolean; spf: boolean; dmarc: boolean; dkim?: boolean };
    security_txt: { found: boolean; contacts: string[] };
    ct_stats?: { requests?: number; certs_found?: number; names_found?: number; message?: string; skipped?: boolean };
    technologies?: { name: string; category: string; evidence: string }[];
    tech_stats?: { scanned?: boolean; found?: number; message?: string; skipped?: boolean };
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
    github_stats?: { requests?: number; commits_found?: number; emails_found?: number; message?: string };
    mailing_stats?: { sources?: number; messages?: number; emails_found?: number; message?: string };
    career_stats?: { career_pages_fetched?: number; emails_found?: number };
    deep_osint?: {
      bbot: { ran?: boolean; emails_found?: number; subdomains_found?: number; message?: string };
      holehe: { checked?: number; results?: Record<string, string[]>; message?: string };
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

/* ------------------------------------------------------------------ */
/* Shared helpers                                                     */
/* ------------------------------------------------------------------ */

const SOURCE_LABELS: Record<string, string> = {
  website: "Website",
  mailto: "mailto",
  careers: "Careers",
  jobportal: "Job Portal",
  github: "GitHub",
  mailing_list: "Mailing List",
  security_txt: "security.txt",
  document: "Document",
  search: "Search Engine",
  wayback: "Archive",
  ocr: "OCR",
  subdomain: "Subdomain",
  whois: "WHOIS",
  bbot: "BBOT",
  pattern_verified: "Pattern (SMTP ✓)",
};

const SMTP_LABELS: Record<string, string> = {
  ok: "Active (SMTP ✓)",
  rejected: "Not found (SMTP ✗)",
  unknown: "Inconclusive (?)",
  unchecked: "Unchecked",
};

function sourceLabel(s: string): string {
  return SOURCE_LABELS[s] ?? (s || "Other");
}

// jsPDF's built-in standard fonts are WinAnsi-encoded — non-WinAnsi glyphs
// like ✓/✗ render as garbage in the PDF, so strip them for the PDF path.
function pdfSafe(s: string): string {
  return s.replace(/\u2713/g, "OK").replace(/\u2717/g, "").trim();
}

function smtpLabel(smtp: string | undefined): string {
  return SMTP_LABELS[smtp ?? "unchecked"] ?? smtp ?? "Unchecked";
}

function safeFileName(s: string): string {
  return s.toLowerCase().replace(/[^a-z0-9.-]+/g, "-").replace(/^-+|-+$/g, "") || "report";
}

function todayStamp(): string {
  const d = new Date();
  const p = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
}

function nowHuman(): string {
  return new Date().toLocaleString("en-GB", {
    day: "2-digit",
    month: "short",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

/* ------------------------------------------------------------------ */
/* Excel export — styled multi-sheet workbook                         */
/* ------------------------------------------------------------------ */

// Brand palette (dark theme, matches the app)
const XL = {
  navy: "0B1220",
  navyLight: "16233A",
  sky: "38BDF8",
  emerald: "10B981",
  red: "EF4444",
  amber: "F59E0B",
  gray: "94A3B8",
  slateRow: "0F1B2E",
  white: "FFFFFF",
};

function cellStyle(opts: {
  bold?: boolean;
  color?: string;
  fill?: string;
  align?: "left" | "center" | "right";
  wrap?: boolean;
  size?: number;
}) {
  const s: Record<string, unknown> = {
    font: { bold: !!opts.bold, sz: opts.size ?? 11, color: { rgb: opts.color ?? XL.white } },
  };
  if (opts.fill) {
    s.fill = { patternType: "solid", fgColor: { rgb: opts.fill } };
  }
  s.alignment = {
    vertical: "center",
    horizontal: opts.align ?? "left",
    wrapText: !!opts.wrap,
  };
  return s as XLSX.CellObject["s"];
}

function styleHeaderRow(ws: XLSX.WorkSheet, cols: number) {
  for (let c = 0; c < cols; c++) {
    const addr = XLSX.utils.encode_cell({ r: 0, c });
    const cell = ws[addr];
    if (cell) cell.s = cellStyle({ bold: true, fill: XL.navyLight, align: "center" });
  }
}

function setWidths(ws: XLSX.WorkSheet, widths: number[]) {
  ws["!cols"] = widths.map((wch) => ({ wch }));
}

export function exportToExcel(result: ExportResult) {
  const wb = XLSX.utils.book_new();
  const r = result.results;

  /* ---- Sheet 1: Summary ---- */
  const stats: (string | number | boolean)[][] = [["VIRE — OSINT Email Reconnaissance Report"], []];
  stats.push(["Domain", result.domain]);
  stats.push(["Scan Date", nowHuman()]);
  stats.push(["Status", result.status === "completed" ? "Completed" : result.status]);
  if (result.mode) stats.push(["Scan Mode", `Atlas ${result.mode}`]);
  if (result.freshness) stats.push(["Atlas Freshness", result.freshness]);
  if (r) stats.push(["Duration", `${((r.timings?.total ?? result.duration_ms ?? 0) / 1000).toFixed(1)}s`]);
  stats.push(["Confidence Score", r ? `${r.confidence_score}/100` : "—"]);
  stats.push([]);
  stats.push(["EMAILS", ""]);
  stats.push(["Total Emails Found", r?.email_stats?.observed ?? 0]);
  if (r?.smtp_check?.enabled) {
    stats.push(["Active (SMTP)", r?.email_stats?.smtp_ok ?? 0]);
    stats.push(["Invalid (SMTP)", r?.email_stats?.smtp_rejected ?? 0]);
    stats.push(["Inconclusive (SMTP)", r?.email_stats?.smtp_unknown ?? 0]);
  }
  stats.push(["Pattern Verified", r?.email_stats?.pattern_verified ?? 0]);
  stats.push([]);
  stats.push(["EMAIL SECURITY", ""]);
  stats.push(["Mail Server (MX)", r?.security_posture?.mx ? "Detected" : "Not found"]);
  stats.push(["SPF Record", r?.security_posture?.spf ? "Detected" : "Not found"]);
  stats.push(["DMARC Record", r?.security_posture?.dmarc ? "Detected" : "Not found"]);
  stats.push(["SPF Value", r?.spf ?? "—"]);
  stats.push(["DMARC Value", r?.dmarc ?? "—"]);
  if (r?.security_txt?.found) {
    stats.push(["security.txt", `Found — ${(r.security_txt.contacts ?? []).join(", ") || "no contacts"}`]);
  }
  stats.push([]);
  stats.push(["RECON STATS", ""]);
  stats.push(["Pages Crawled", r?.crawl_stats?.pages_crawled ?? 0]);
  stats.push(["Links Found", r?.crawl_stats?.links_found ?? 0]);
  stats.push(["Subdomains", r?.subdomains?.length ?? 0]);
  stats.push(["Docs Parsed", r?.doc_stats?.docs_parsed ?? 0]);
  stats.push(["Archived Pages (Wayback)", r?.wayback_stats?.pages_fetched ?? 0]);
  stats.push(["Archive Emails", r?.wayback_stats?.emails_found ?? 0]);
  stats.push(["Search Results (DDG)", r?.search_stats?.duckduckgo_results ?? 0]);
  stats.push(["Search Results (Bing)", r?.search_stats?.bing_results ?? 0]);
  stats.push(["GitHub Contacts", r?.github_stats?.emails_found ?? 0]);
  stats.push(["Mailing List Emails", r?.mailing_stats?.emails_found ?? 0]);
  stats.push(["Career Emails", r?.career_stats?.emails_found ?? 0]);
  if (r?.ocr_stats && ((r.ocr_stats.images_ocred ?? 0) > 0 || (r.ocr_stats.pdfs_ocred ?? 0) > 0)) {
    stats.push(["OCR Images", r.ocr_stats.images_ocred ?? 0]);
    stats.push(["OCR PDFs", r.ocr_stats.pdfs_ocred ?? 0]);
    stats.push(["OCR Emails", r.ocr_stats.emails_found ?? 0]);
  }

  const wsSummary = XLSX.utils.aoa_to_sheet(stats);
  setWidths(wsSummary, [34, 90]);
  // Title row
  const t0 = wsSummary["A1"];
  if (t0) t0.s = cellStyle({ bold: true, size: 14, color: XL.sky, fill: XL.navy });
  // Section headers (col A with value)
  (["EMAILS", "EMAIL SECURITY", "RECON STATS"] as const).forEach((sec) => {
    for (let rr = 0; rr < stats.length; rr++) {
      if (stats[rr][0] === sec) {
        const c = wsSummary[XLSX.utils.encode_cell({ r: rr, c: 0 })];
        if (c) c.s = cellStyle({ bold: true, size: 11, color: XL.sky, fill: XL.slateRow });
      }
    }
  });
  // Label column: dark slate fill + navy text (white-on-white was unreadable)
  for (let rr = 1; rr < stats.length; rr++) {
    const lbl = wsSummary[XLSX.utils.encode_cell({ r: rr, c: 0 })];
    if (lbl && typeof stats[rr][0] === "string" && !["EMAILS", "EMAIL SECURITY", "RECON STATS"].includes(stats[rr][0] as string)) {
      lbl.s = cellStyle({ bold: true, color: XL.navy, fill: XL.slateRow });
    }
  }
  XLSX.utils.book_append_sheet(wb, wsSummary, "Summary");

  /* ---- Sheet 2: Emails ---- */
  const wsEmails = XLSX.utils.aoa_to_sheet([
    ["Email", "Source", "Verified", "SMTP Status", "Confidence", "Source URL"],
    ...(r?.emails ?? []).map((e) => [
      e.email,
      sourceLabel(e.source),
      e.verified ? "Yes" : "No",
      smtpLabel(e.smtp),
      e.confidence ? `${e.confidence}%` : "—",
      e.url ?? "",
    ]),
  ]);
  setWidths(wsEmails, [38, 18, 10, 24, 12, 60]);
  styleHeaderRow(wsEmails, 6);
  if ((r?.emails?.length ?? 0) > 0) {
    // Color the SMTP status column
    for (let rr = 1; rr <= (r?.emails?.length ?? 0); rr++) {
      const st = r?.emails?.[rr - 1]?.smtp;
      const c = wsEmails[XLSX.utils.encode_cell({ r: rr, c: 3 })];
      if (c) {
        const color = st === "ok" ? XL.emerald : st === "rejected" ? XL.red : st === "unknown" ? XL.amber : XL.gray;
        c.s = { ...cellStyle({}), font: { bold: true, sz: 11, color: { rgb: color } }, alignment: { vertical: "center", horizontal: "left" } };
      }
    }
  }
  wsEmails["!autofilter"] = { ref: `A1:E${(r?.emails?.length ?? 0) + 1}` };
  XLSX.utils.book_append_sheet(wb, wsEmails, "Emails");

  /* ---- Sheet 3: People & Contacts ---- */
  if (r?.people?.length) {
    const wsPeople = XLSX.utils.aoa_to_sheet([
      ["Name", "Email", "Source", "Context", "URL"],
      ...r.people.map((p) => [p.name || "Unknown", p.email, p.source === "github" ? "GitHub" : "Mailing list", p.context ?? "", p.url ?? ""]),
    ]);
    setWidths(wsPeople, [26, 34, 14, 40, 50]);
    styleHeaderRow(wsPeople, 5);
    XLSX.utils.book_append_sheet(wb, wsPeople, "People");
  }

  /* ---- Sheet 4: DNS Records ---- */
  const dnsRows: (string | number)[][] = [["Type", "Record"]];
  for (const [type, records] of Object.entries(r?.dns_records ?? {})) {
    const list = Array.isArray(records) ? records : [];
    if (list.length === 0) dnsRows.push([type, "— not found —"]);
    else list.forEach((rec) => dnsRows.push([type, String(rec)]));
  }
  const wsDns = XLSX.utils.aoa_to_sheet(dnsRows);
  setWidths(wsDns, [12, 100]);
  styleHeaderRow(wsDns, 2);
  XLSX.utils.book_append_sheet(wb, wsDns, "DNS Records");

  /* ---- Sheet 5: Subdomains ---- */
  if (r?.subdomains?.length) {
    const wsSub = XLSX.utils.aoa_to_sheet([["Subdomain"], ...r.subdomains.map((s) => [s])]);
    setWidths(wsSub, [60]);
    styleHeaderRow(wsSub, 1);
    XLSX.utils.book_append_sheet(wb, wsSub, "Subdomains");
  }

  /* ---- Sheet 6: WHOIS ---- */
  const w = r?.whois;
  if (w) {
    const whoisRows: (string | undefined)[][] = [
      ["Field", "Value"],
      ["Registrar", Array.isArray(w.registrar) ? w.registrar.join(", ") : (w.registrar ?? undefined)],
      ["Created", w.creation_date ?? undefined],
      ["Expires", w.expiration_date ?? undefined],
      ["Updated", w.updated_date ?? undefined],
      ["Name Servers", w.name_servers?.join("\n")],
      ["Emails", w.emails?.join(", ")],
    ].filter((row) => row[1] !== undefined && row[1] !== "");
    const wsWhois = XLSX.utils.aoa_to_sheet(whoisRows);
    setWidths(wsWhois, [16, 90]);
    styleHeaderRow(wsWhois, 2);
    XLSX.utils.book_append_sheet(wb, wsWhois, "WHOIS");
  }

  /* ---- Sheet 7: Technologies ---- */
  if (r?.technologies?.length) {
    const techRows = [
      ["Technology", "Category", "Evidence"],
      ...r.technologies.map((t) => [t.name, t.category, t.evidence]),
    ];
    const wsTech = XLSX.utils.aoa_to_sheet(techRows);
    setWidths(wsTech, [28, 16, 60]);
    styleHeaderRow(wsTech, 3);
    XLSX.utils.book_append_sheet(wb, wsTech, "Technologies");
  }

  /* ---- Sheet 8: Deep OSINT (Holehe) ---- */
  const holehe = r?.deep_osint?.holehe?.results;
  if (holehe && Object.keys(holehe).length > 0) {
    const holeRows = [
      ["Email", "Registered Sites"],
      ...Object.entries(holehe).map(([em, sites]) => [em, sites.join(", ")]),
    ];
    const wsHole = XLSX.utils.aoa_to_sheet(holeRows);
    setWidths(wsHole, [36, 80]);
    styleHeaderRow(wsHole, 2);
    XLSX.utils.book_append_sheet(wb, wsHole, "Holehe");
  }

  XLSX.writeFile(wb, `vire-${safeFileName(result.domain)}-${todayStamp()}.xlsx`);
}

/* ------------------------------------------------------------------ */
/* PDF export — formatted report                                      */
/* ------------------------------------------------------------------ */

const PDF_NAVY: [number, number, number] = [11, 18, 32];
const PDF_SKY: [number, number, number] = [56, 189, 248];
const PDF_EMERALD: [number, number, number] = [16, 185, 129];
const PDF_RED: [number, number, number] = [239, 68, 68];
const PDF_AMBER: [number, number, number] = [245, 158, 11];
const PDF_SLATE: [number, number, number] = [100, 116, 139];
const PDF_LIGHT: [number, number, number] = [226, 232, 240];
const PDF_TEXT: [number, number, number] = [30, 41, 59];

export function exportToPdf(result: ExportResult) {
  const doc = new jsPDF({ orientation: "portrait", unit: "pt", format: "a4" });
  const W = doc.internal.pageSize.getWidth();
  const M = 40; // margin
  const r = result.results;
  const emails = r?.emails ?? [];

  /* ---------- header band ---------- */
  doc.setFillColor(PDF_NAVY[0], PDF_NAVY[1], PDF_NAVY[2]);
  doc.rect(0, 0, W, 92, "F");
  doc.setFillColor(PDF_SKY[0], PDF_SKY[1], PDF_SKY[2]);
  doc.rect(0, 92, W, 3, "F");

  doc.setTextColor(255, 255, 255);
  doc.setFont("helvetica", "bold");
  doc.setFontSize(16);
  doc.text("VIRE — OSINT Email Reconnaissance Report", M, 34);
  doc.setFont("helvetica", "normal");
  doc.setFontSize(10);
  doc.setTextColor(PDF_LIGHT[0], PDF_LIGHT[1], PDF_LIGHT[2]);
  doc.text(`Generated ${nowHuman()}`, M, 52);
  doc.setFontSize(13);
  doc.setTextColor(PDF_SKY[0], PDF_SKY[1], PDF_SKY[2]);
  doc.setFont("helvetica", "bold");
  doc.text(result.domain, W - M, 34, { align: "right" });
  doc.setFont("helvetica", "normal");
  doc.setFontSize(9);
  doc.setTextColor(PDF_LIGHT[0], PDF_LIGHT[1], PDF_LIGHT[2]);
  doc.text(
    `Status: ${result.status === "completed" ? "Completed" : result.status}  ·  Confidence: ${r ? r.confidence_score : "—"}/100`,
    W - M,
    52,
    { align: "right" }
  );

  /* ---------- stat boxes ---------- */
  const statDefs: { label: string; value: string; color: [number, number, number] }[] = [
    { label: "Emails Found", value: String(r?.email_stats?.observed ?? 0), color: PDF_SKY },
    { label: "Active (SMTP)", value: String(r?.email_stats?.smtp_ok ?? 0), color: PDF_EMERALD },
    { label: "Invalid (SMTP)", value: String(r?.email_stats?.smtp_rejected ?? 0), color: PDF_RED },
    { label: "Duration", value: `${((r?.timings?.total ?? result.duration_ms ?? 0) / 1000).toFixed(1)}s`, color: PDF_AMBER },
  ];
  const boxGap = 10;
  const boxW = (W - 2 * M - boxGap * (statDefs.length - 1)) / statDefs.length;
  const boxH = 58;
  let y = 122;
  statDefs.forEach((s, i) => {
    const x = M + i * (boxW + boxGap);
    doc.setFillColor(15, 27, 46);
    doc.setDrawColor(s.color[0], s.color[1], s.color[2]);
    doc.setLineWidth(1);
    doc.roundedRect(x, y, boxW, boxH, 6, 6, "FD");
    doc.setFillColor(s.color[0], s.color[1], s.color[2]);
    doc.rect(x, y, boxW, 3.5, "F");
    doc.setTextColor(s.color[0], s.color[1], s.color[2]);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(20);
    doc.text(s.value, x + boxW / 2, y + 28, { align: "center" });
    doc.setTextColor(PDF_LIGHT[0], PDF_LIGHT[1], PDF_LIGHT[2]);
    doc.setFont("helvetica", "normal");
    doc.setFontSize(8);
    doc.text(s.label, x + boxW / 2, y + 46, { align: "center" });
  });
  y += boxH + 24;

  /* ---------- security posture ---------- */
  const posture = r?.security_posture ?? { mx: false, spf: false, dmarc: false };
  const postureRows = [
    ["Mail Server (MX)", posture.mx ? "Detected" : "Not found", posture.mx ? PDF_EMERALD : PDF_RED],
    ["SPF Record", posture.spf ? "Detected" : "Not found", posture.spf ? PDF_EMERALD : PDF_RED],
    ["DMARC Record", posture.dmarc ? "Detected" : "Not found", posture.dmarc ? PDF_EMERALD : PDF_RED],
  ];
  const chipW = (W - 2 * M - boxGap * 2) / 3;
  postureRows.forEach(([label, value, color], i) => {
    const x = M + i * (chipW + boxGap);
    const [cr, cg, cb] = color as [number, number, number];
    doc.setFillColor(cr, cg, cb);
    doc.roundedRect(x, y, chipW, 30, 4, 4, "F");
    doc.setTextColor(255, 255, 255);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(8.5);
    doc.text(String(label), x + chipW / 2, y + 12, { align: "center" });
    doc.setFont("helvetica", "normal");
    doc.setFontSize(8);
    doc.text(String(value), x + chipW / 2, y + 23, { align: "center" });
  });
  y += 30 + 28;

  /* ---------- section helper ---------- */
  const sectionTitle = (title: string) => {
    doc.setFillColor(PDF_SKY[0], PDF_SKY[1], PDF_SKY[2]);
    doc.rect(M, y - 9, 26, 3, "F");
    doc.setTextColor(PDF_NAVY[0], PDF_NAVY[1], PDF_NAVY[2]);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(13);
    doc.text(title, M, y);
    y += 14;
  };

  // autotable v5 warns when explicit cellWidths don't sum exactly to the
  // available width — scale proportional widths to fill it precisely.
  const fitWidths = (props: number[]): number[] => {
    const avail = W - 2 * M;
    const sum = props.reduce((a, b) => a + b, 0);
    return props.map((p) => (p / sum) * avail);
  };

  const table = (
    head: string[],
    body: (string | number)[][],
    opts?: { widths?: number[]; cellColor?: (row: unknown[]) => [number, number, number] | null }
  ) => {
    autoTable(doc, {
      startY: y,
      margin: { left: M, right: M },
      head: [head],
      body,
      styles: {
        font: "helvetica",
        fontSize: 8.5,
        cellPadding: 5,
        textColor: PDF_TEXT,
        lineColor: [51, 65, 85],
        lineWidth: 0.5,
      },
      headStyles: {
        fillColor: PDF_NAVY,
        textColor: [255, 255, 255],
        fontStyle: "bold",
        fontSize: 8.5,
      },
      alternateRowStyles: { fillColor: [238, 242, 248] }, // light slate — dark text stays readable
      columnStyles: opts?.widths
        ? Object.fromEntries(fitWidths(opts.widths).map((wpx, i) => [i, { cellWidth: wpx }]))
        : undefined,
      didParseCell: (data) => {
        if (data.section === "body" && opts?.cellColor) {
          const color = opts.cellColor(data.row.raw as unknown[]);
          if (color) {
            data.cell.styles.textColor = color;
            data.cell.styles.fontStyle = "bold";
          }
        }
      },
    });
    const last = (doc as unknown as { lastAutoTable?: { finalY: number } }).lastAutoTable;
    y = (last?.finalY ?? y) + 26;
  };

  /* ---------- emails table ---------- */
  sectionTitle(`Emails Found (${emails.length})`);
  if (emails.length > 0) {
    const smtpByEmail = new Map(emails.map((e) => [e.email, e.smtp]));
    table(
      ["Email", "Source", "Verified", "SMTP Status"],
      emails.map((e) => [
        e.email,
        pdfSafe(sourceLabel(e.source)),
        e.verified ? "Yes" : "No",
        pdfSafe(smtpLabel(e.smtp)),
      ]),
      {
        widths: [190, 90, 55, 120],
        cellColor: (row) => {
          const smtp = smtpByEmail.get(String(row[0]));
          if (smtp === "ok") return PDF_EMERALD;
          if (smtp === "rejected") return PDF_RED;
          if (smtp === "unknown") return PDF_AMBER;
          return null;
        },
      }
    );
  } else {
    doc.setFont("helvetica", "normal");
    doc.setFontSize(9.5);
    doc.setTextColor(PDF_SLATE[0], PDF_SLATE[1], PDF_SLATE[2]);
    doc.text("No public emails found for this domain.", M, y + 4);
    y += 24;
  }

  /* ---------- people table ---------- */
  const people = r?.people ?? [];
  if (people.length > 0) {
    sectionTitle(`People & Contacts (${people.length})`);
    table(
      ["Name", "Email", "Source", "Context"],
      people.map((p) => [p.name || "Unknown", p.email, p.source === "github" ? "GitHub" : "Mailing list", p.context ?? ""]),
      { widths: [110, 150, 80, 115] }
    );
  }

  /* ---------- DNS records ---------- */
  const dnsEntries = Object.entries(r?.dns_records ?? {}).filter(([, recs]) => Array.isArray(recs) && recs.length > 0);
  if (dnsEntries.length > 0) {
    sectionTitle("DNS Records");
    table(
      ["Type", "Records"],
      dnsEntries.map(([type, recs]) => [type, (recs as string[]).join("\n")]),
      { widths: [60, 395] }
    );
  }

  /* ---------- subdomains ---------- */
  const subdomains = r?.subdomains ?? [];
  if (subdomains.length > 0) {
    sectionTitle(`Subdomains (${subdomains.length})`);
    table(["Subdomain"], subdomains.map((s) => [s]), { widths: [455] });
  }

  /* ---------- WHOIS ---------- */
  const w2 = r?.whois;
  if (w2) {
    sectionTitle("WHOIS");
    const whoisRows: (string | number)[][] = [];
    if (w2.registrar) whoisRows.push(["Registrar", Array.isArray(w2.registrar) ? w2.registrar.join(", ") : w2.registrar]);
    if (w2.creation_date) whoisRows.push(["Created", w2.creation_date]);
    if (w2.expiration_date) whoisRows.push(["Expires", w2.expiration_date]);
    if (w2.updated_date) whoisRows.push(["Updated", w2.updated_date]);
    if (w2.name_servers?.length) whoisRows.push(["Name Servers", w2.name_servers.join(", ")]);
    if (w2.emails?.length) whoisRows.push(["Emails", w2.emails.join(", ")]);
    if (whoisRows.length > 0) table(["Field", "Value"], whoisRows, { widths: [110, 345] });
  }

  /* ---------- security records (SPF / DMARC / security.txt) ---------- */
  if (r?.spf || r?.dmarc || r?.security_txt?.found) {
    sectionTitle("Email Security Records");
    const secRows: (string | number)[][] = [];
    if (r.spf) secRows.push(["SPF", r.spf]);
    if (r.dmarc) secRows.push(["DMARC", r.dmarc]);
    if (r.security_txt?.found) {
      secRows.push(["security.txt", `Found — ${(r.security_txt.contacts ?? []).join(", ") || "no contacts"}`]);
    }
    table(["Record", "Value"], secRows, { widths: [110, 345] });
  }

  /* ---------- deep OSINT ---------- */
  const bbot = r?.deep_osint?.bbot;
  const holehe = r?.deep_osint?.holehe;
  if (bbot?.ran || (holehe?.results && Object.keys(holehe.results).length > 0)) {
    sectionTitle("Deep OSINT Tools");
    if (bbot?.ran) {
      table(
        ["Tool", "Emails", "Subdomains", "Message"],
        [["BBOT", bbot.emails_found ?? 0, bbot.subdomains_found ?? 0, bbot.message ?? "Done"]],
        { widths: [70, 90, 110, 185] }
      );
    }
    if (holehe?.results && Object.keys(holehe.results).length > 0) {
      table(
        ["Email", "Registered Sites"],
        Object.entries(holehe.results).map(([em, sites]) => [em, sites.join(", ")]),
        { widths: [170, 285] }
      );
    }
  }

  /* ---------- footer ---------- */
  const pages = doc.getNumberOfPages();
  for (let i = 1; i <= pages; i++) {
    doc.setPage(i);
    doc.setDrawColor(PDF_LIGHT[0], PDF_LIGHT[1], PDF_LIGHT[2]);
    doc.setLineWidth(0.5);
    doc.line(M, doc.internal.pageSize.getHeight() - 40, W - M, doc.internal.pageSize.getHeight() - 40);
    doc.setFont("helvetica", "normal");
    doc.setFontSize(8);
    doc.setTextColor(PDF_SLATE[0], PDF_SLATE[1], PDF_SLATE[2]);
    doc.text("VIRE · For legal & educational use only", M, doc.internal.pageSize.getHeight() - 24);
    doc.text(`Page ${i} of ${pages}`, W - M, doc.internal.pageSize.getHeight() - 24, { align: "right" });
  }

  doc.save(`vire-${safeFileName(result.domain)}-${todayStamp()}.pdf`);
}
