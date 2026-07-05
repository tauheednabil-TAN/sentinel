"use client";

/**
 * Sentinel — PDF report export
 * ---------------------------------------------------------------------------
 * Client-side PDF generation. No API route, no server load — runs entirely in
 * the browser, so it works on Vercel with zero extra infra.
 *
 * Install:  npm install jspdf
 *
 * Usage:
 *   import { DownloadReportButton } from "@/components/ReportExport";
 *   <DownloadReportButton url={scanUrl} findings={findings} />
 *
 * IMPORTANT: adjust the `Finding` interface below to match the exact shape your
 * agents return. If your field names differ (e.g. `remediation` instead of
 * `fix`), rename here in one place and everything downstream just works.
 * ---------------------------------------------------------------------------
 */

import { useState } from "react";
import jsPDF from "jspdf";

/* ── Types (match these to your real finding shape) ───────────────────────── */

export type Severity = "Critical" | "High" | "Medium" | "Low" | "Info";

export interface Finding {
  agent: string;            // which of the 12 agents produced it
  title: string;            // short name of the vulnerability
  severity: Severity;
  impact: string;           // what an attacker could do
  fix: string[] | string;   // step-by-step remediation
  code?: string;            // optional code example / snippet
  resources?: string[];     // optional reference links
}

export interface ScanReport {
  url: string;
  scannedAt?: Date | string;
  findings: Finding[];
}

/* ── Severity config ──────────────────────────────────────────────────────── */

const SEV_ORDER: Severity[] = ["Critical", "High", "Medium", "Low", "Info"];

const SEV_RGB: Record<Severity, [number, number, number]> = {
  Critical: [255, 59, 92],
  High: [255, 138, 61],
  Medium: [235, 175, 40],
  Low: [61, 150, 220],
  Info: [120, 134, 153],
};

/* ── PDF generator ────────────────────────────────────────────────────────── */

export function generateReport({ url, scannedAt, findings }: ScanReport): jsPDF {
  const doc = new jsPDF({ unit: "pt", format: "a4" });

  const M = 40; // margin
  const pageW = doc.internal.pageSize.getWidth();
  const pageH = doc.internal.pageSize.getHeight();
  const contentW = pageW - M * 2;
  const BOTTOM = pageH - 46; // leave room for footer
  let y = 0;

  const when =
    scannedAt instanceof Date
      ? scannedAt
      : scannedAt
      ? new Date(scannedAt)
      : new Date();

  // page-break helper
  const need = (space: number) => {
    if (y + space > BOTTOM) {
      doc.addPage();
      y = M;
    }
  };

  // wrapped-text writer with per-line page breaks
  const writeText = (
    text: string,
    opts: { size?: number; font?: "normal" | "bold" | "italic"; mono?: boolean; color?: [number, number, number]; indent?: number; gap?: number } = {}
  ) => {
    const { size = 10, font = "normal", mono = false, color = [40, 48, 60], indent = 0, gap = 4 } = opts;
    doc.setFont(mono ? "courier" : "helvetica", font);
    doc.setFontSize(size);
    doc.setTextColor(...color);
    const lineH = size * 1.35;
    const lines = doc.splitTextToSize(text || "—", contentW - indent);
    for (const line of lines) {
      need(lineH);
      doc.text(line, M + indent, y);
      y += lineH;
    }
    y += gap;
  };

  const sectionLabel = (label: string, rgb: [number, number, number] = [90, 100, 115]) => {
    need(18);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(8);
    doc.setTextColor(...rgb);
    doc.text(label.toUpperCase(), M, y);
    y += 14;
  };

  /* ── Header band ── */
  doc.setFillColor(7, 11, 20);
  doc.rect(0, 0, pageW, 92, "F");
  doc.setFillColor(61, 214, 255);
  doc.rect(0, 92, pageW, 3, "F");

  doc.setFont("helvetica", "bold");
  doc.setFontSize(22);
  doc.setTextColor(255, 255, 255);
  doc.text("SENTINEL", M, 44);
  doc.setFont("helvetica", "normal");
  doc.setFontSize(10);
  doc.setTextColor(160, 200, 220);
  doc.text("AI-Powered Security Scan Report", M, 62);

  doc.setFontSize(8);
  doc.setTextColor(140, 155, 175);
  const targetLabel = `Target:  ${url}`;
  doc.text(doc.splitTextToSize(targetLabel, contentW), M, 78);
  doc.text(
    `Generated:  ${when.toLocaleString()}`,
    pageW - M,
    44,
    { align: "right" }
  );

  y = 120;

  /* ── Severity summary ── */
  const counts = SEV_ORDER.map((s) => ({
    sev: s,
    n: findings.filter((f) => f.severity === s).length,
  }));
  const total = findings.length;

  sectionLabel(`Summary · ${total} finding${total === 1 ? "" : "s"}`);

  let cx = M;
  const chipW = (contentW - 4 * 8) / 5;
  const chipH = 44;
  need(chipH + 8);
  for (const { sev, n } of counts) {
    const [r, g, b] = SEV_RGB[sev];
    doc.setFillColor(r, g, b, 0.1 as any);
    doc.setDrawColor(r, g, b);
    doc.setLineWidth(0.8);
    doc.roundedRect(cx, y, chipW, chipH, 5, 5, "S");
    doc.setFont("helvetica", "bold");
    doc.setFontSize(18);
    doc.setTextColor(r, g, b);
    doc.text(String(n), cx + chipW / 2, y + 22, { align: "center" });
    doc.setFont("helvetica", "normal");
    doc.setFontSize(7);
    doc.setTextColor(90, 100, 115);
    doc.text(sev.toUpperCase(), cx + chipW / 2, y + 35, { align: "center" });
    cx += chipW + 8;
  }
  y += chipH + 20;

  /* ── Findings (Critical first) ── */
  const ordered = [...findings].sort(
    (a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity)
  );

  sectionLabel("Detailed Findings");

  if (ordered.length === 0) {
    writeText("No findings were returned for this scan.", { color: [120, 130, 145], font: "italic" });
  }

  ordered.forEach((f, i) => {
    const [r, g, b] = SEV_RGB[f.severity];

    // keep a finding from starting at the very bottom of a page
    need(70);

    // severity accent bar + title
    const titleY = y;
    doc.setFillColor(r, g, b);
    doc.rect(M, titleY - 9, 3, 16, "F");
    doc.setFont("helvetica", "bold");
    doc.setFontSize(12);
    doc.setTextColor(25, 32, 45);
    const titleLines = doc.splitTextToSize(`${i + 1}. ${f.title}`, contentW - 12);
    for (const line of titleLines) {
      need(16);
      doc.text(line, M + 12, y);
      y += 16;
    }

    // meta line: severity pill + agent
    need(16);
    doc.setFillColor(r, g, b);
    doc.roundedRect(M + 12, y - 8, doc.getTextWidth(f.severity) + 14, 13, 3, 3, "F");
    doc.setFont("helvetica", "bold");
    doc.setFontSize(7.5);
    doc.setTextColor(255, 255, 255);
    doc.text(f.severity.toUpperCase(), M + 19, y + 1);
    doc.setFont("helvetica", "normal");
    doc.setFontSize(8);
    doc.setTextColor(120, 130, 145);
    doc.text(`Agent: ${f.agent}`, M + 12 + doc.getTextWidth(f.severity) + 24, y + 1);
    y += 18;

    // impact
    sectionLabel("Impact");
    writeText(f.impact, { size: 9.5, color: [55, 62, 74] });

    // remediation
    const steps = Array.isArray(f.fix)
      ? f.fix
      : String(f.fix || "")
          .split("\n")
          .map((s) => s.trim())
          .filter(Boolean);
    sectionLabel("Remediation");
    if (steps.length) {
      steps.forEach((step, s) =>
        writeText(`${s + 1}. ${step}`, { size: 9.5, color: [55, 62, 74], gap: 2 })
      );
      y += 2;
    } else {
      writeText("—", { size: 9.5, color: [120, 130, 145] });
    }

    // code example
    if (f.code && f.code.trim()) {
      sectionLabel("Example");
      const codeLines = doc.splitTextToSize(f.code, contentW - 16);
      doc.setFont("courier", "normal");
      doc.setFontSize(8);
      const codeLineH = 11;
      for (const line of codeLines) {
        need(codeLineH);
        doc.setFillColor(244, 246, 250);
        doc.rect(M, y - 8, contentW, codeLineH, "F");
        doc.setTextColor(50, 60, 75);
        doc.text(line, M + 8, y);
        y += codeLineH;
      }
      y += 6;
    }

    // resources
    if (f.resources && f.resources.length) {
      sectionLabel("Resources");
      for (const link of f.resources) {
        need(13);
        doc.setFont("helvetica", "normal");
        doc.setFontSize(8.5);
        doc.setTextColor(30, 120, 200);
        doc.textWithLink(`• ${link}`, M, y, { url: link });
        y += 13;
      }
      y += 4;
    }

    // divider
    need(16);
    doc.setDrawColor(228, 232, 238);
    doc.setLineWidth(0.5);
    doc.line(M, y, pageW - M, y);
    y += 18;
  });

  /* ── Footer + page numbers ── */
  const pages = doc.getNumberOfPages();
  for (let p = 1; p <= pages; p++) {
    doc.setPage(p);
    doc.setFont("helvetica", "normal");
    doc.setFontSize(7.5);
    doc.setTextColor(150, 158, 170);
    doc.text(
      "Generated by Sentinel · AI security findings are advisory and may include false positives. Verify before acting.",
      M,
      pageH - 24
    );
    doc.text(`Page ${p} of ${pages}`, pageW - M, pageH - 24, { align: "right" });
  }

  return doc;
}

/* ── Download button component ────────────────────────────────────────────── */

export function DownloadReportButton({
  url,
  findings,
  scannedAt,
  disabled,
  className = "",
}: {
  url: string;
  findings: Finding[];
  scannedAt?: Date | string;
  disabled?: boolean;
  className?: string;
}) {
  const [busy, setBusy] = useState(false);
  const isEmpty = !findings || findings.length === 0;

  const handleDownload = async () => {
    if (busy || isEmpty) return;
    setBusy(true);
    try {
      const doc = generateReport({ url, findings, scannedAt });
      let host = "report";
      try {
        host = new URL(url).hostname.replace(/^www\./, "");
      } catch {
        /* url may be bare; keep fallback */
      }
      const stamp = new Date().toISOString().slice(0, 10);
      doc.save(`sentinel-${host}-${stamp}.pdf`);
    } catch (err) {
      console.error("PDF export failed:", err);
    } finally {
      setBusy(false);
    }
  };

  return (
    <button
      type="button"
      onClick={handleDownload}
      disabled={disabled || isEmpty || busy}
      title={isEmpty ? "Run a scan first to export a report" : "Download PDF report"}
      className={
        "inline-flex items-center gap-2 rounded-lg border border-cyan-400/30 bg-cyan-400/10 " +
        "px-4 py-2 text-sm font-medium text-cyan-200 transition " +
        "hover:bg-cyan-400/20 disabled:cursor-not-allowed disabled:opacity-40 " +
        className
      }
    >
      {busy ? (
        <>
          <span className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-cyan-300/40 border-t-cyan-300" />
          Generating…
        </>
      ) : (
        <>
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
            <polyline points="7 10 12 15 17 10" />
            <line x1="12" y1="15" x2="12" y2="3" />
          </svg>
          Download PDF
        </>
      )}
    </button>
  );
}