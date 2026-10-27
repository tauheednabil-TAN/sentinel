// Pure checks used by the scan route. They make no network calls, so they can be
// unit tested on their own (see tests/checks.test.ts).

export type Severity = "critical" | "high" | "medium" | "low" | "info";

// Result of hitting deliberately-random paths to learn how the server behaves
// for URLs that definitely do not exist (soft-404 / SPA catch-all detection).
export type CalibrationResult = {
  catchAll: boolean; // does the site return 200 for garbage paths?
  baselineStatus: number;
  baselineLen: number;
  baselineContentType: string;
  baselineNorm: string; // normalized body prefix for similarity comparison
  samples: number;
};

// =====================================================================
// URL VALIDATION (SSRF guardrail)
// =====================================================================
// allowLocal is for local testing only (ALLOW_LOCAL_TARGETS=true in .env.local).
// It lets a copy running on the author's computer scan test apps such as
// OWASP Juice Shop on http://127.0.0.1. Never set it on Vercel.
export function validateAndNormalizeUrl(input: unknown, allowLocal = false): string | null {
  if (typeof input !== "string" || input.trim().length === 0) return null;
  const trimmed = input.trim();
  try {
    const withProtocol = /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
    const parsed = new URL(withProtocol);

    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return null;
    if (!allowLocal && !parsed.hostname.includes(".")) return null;

    const host = parsed.hostname.toLowerCase();
    const blocked =
      host === "localhost" ||
      host.endsWith(".localhost") ||
      host.endsWith(".local") ||
      host.endsWith(".internal") ||
      /^127\./.test(host) ||
      /^10\./.test(host) ||
      /^192\.168\./.test(host) ||
      /^172\.(1[6-9]|2\d|3[01])\./.test(host) ||
      /^169\.254\./.test(host) ||
      /^0\./.test(host) ||
      host === "0.0.0.0" ||
      host === "::1" ||
      host.startsWith("[");
    if (blocked && !allowLocal) return null;

    return parsed.href;
  } catch {
    return null;
  }
}

export function normalizeBody(body: string): string {
  return body.replace(/\s+/g, " ").trim().toLowerCase().slice(0, 2000);
}

export function isHtmlBody(contentType: string, body: string): boolean {
  return /text\/html/i.test(contentType) || /^\s*(<!doctype html|<html[\s>])/i.test(body);
}

// True when a probed body is really just the site's catch-all page.
export function looksLikeBaseline(body: string, calib: CalibrationResult): boolean {
  if (!calib.catchAll) return false;
  const norm = normalizeBody(body);
  const lenClose = calib.baselineLen > 0 && Math.abs(body.length - calib.baselineLen) <= Math.max(40, calib.baselineLen * 0.15);
  const sameStart = calib.baselineNorm.length > 40 && norm.slice(0, 200) === calib.baselineNorm.slice(0, 200);
  return lenClose && (sameStart || calib.baselineNorm.length <= 40);
}

// ---- Per-file content signatures --------------------------------------------
// A path is only "exposed" if its BODY actually matches that file's real format.
// This is the heart of "read what you got and decide if it is really a threat".
export type SigResult = { matched: boolean; evidence: string; severity: Severity };

export function validateSignature(path: string, contentType: string, body: string): SigResult {
  const p = path.toLowerCase();
  const html = isHtmlBody(contentType, body);
  const t = body.trim();
  const notFile = (what: string): SigResult => ({ matched: false, evidence: `HTTP 200 but the body is not ${what} (looks like the site's normal page / soft-404)`, severity: "info" });

  // .env family — must contain KEY=VALUE lines and not be HTML
  if (/\.env/.test(p)) {
    const envLines = body.match(/^[A-Z][A-Z0-9_]*\s*=.+$/gim) || [];
    if (!html && envLines.length >= 1) {
      const secretish = /(SECRET|PASSWORD|PASSWD|API[_-]?KEY|ACCESS[_-]?KEY|TOKEN|PRIVATE|DB_|DATABASE_URL|AWS)/i.test(body);
      return { matched: true, evidence: `real .env file — ${envLines.length} KEY=VALUE line(s)${secretish ? " including secret-like keys" : ""}`, severity: secretish ? "critical" : "high" };
    }
    return notFile("a .env file");
  }
  // .git/HEAD
  if (/\.git\/head/.test(p)) {
    if (!html && (/^ref:\s*refs\//im.test(t) || /^[0-9a-f]{40}$/im.test(t))) {
      return { matched: true, evidence: "valid Git HEAD ref — the .git repository is downloadable", severity: "high" };
    }
    return notFile("a Git HEAD file ('ref: refs/...')");
  }
  // .git/config
  if (/\.git\/config/.test(p)) {
    if (!html && /\[core\]/i.test(body) && /repositoryformatversion/i.test(body)) {
      return { matched: true, evidence: "valid .git/config — source repository is exposed", severity: "high" };
    }
    return notFile("a .git/config file");
  }
  // .svn/entries
  if (/\.svn\/entries/.test(p)) {
    if (!html && (/^\d+\s*$/m.test((t.split("\n")[0] || "")) || /\bdir\b/.test(t))) {
      return { matched: true, evidence: "SVN metadata exposed", severity: "medium" };
    }
    return notFile("an SVN entries file");
  }
  // SQL dumps
  if (/\.sql$/.test(p)) {
    if (/\b(CREATE TABLE|INSERT INTO|DROP TABLE|ALTER TABLE|MySQL dump|PostgreSQL database dump|mysqldump)\b/i.test(body)) {
      return { matched: true, evidence: "database dump — SQL statements present in body", severity: "critical" };
    }
    return notFile("a SQL dump (no CREATE/INSERT statements)");
  }
  // PHP config backups
  if (/config\.php|wp-config/.test(p)) {
    if (/<\?php/i.test(body) && /(define\s*\(|DB_PASSWORD|DB_USER|password)/i.test(body)) {
      return { matched: true, evidence: "PHP config source with credentials returned as plain text", severity: "critical" };
    }
    return notFile("a PHP config backup");
  }
  // .htaccess
  if (/\.htaccess/.test(p)) {
    if (!html && /(RewriteEngine|RewriteRule|Order\s+(allow|deny)|<Files|AuthType|Require\s)/i.test(body)) {
      return { matched: true, evidence: "Apache .htaccess directives exposed", severity: "medium" };
    }
    return notFile("an .htaccess file");
  }
  // Apache server-status
  if (/server-status/.test(p)) {
    if (/Apache Server Status|Server uptime|Total accesses/i.test(body)) {
      return { matched: true, evidence: "Apache server-status page exposed (live request data)", severity: "medium" };
    }
    return notFile("the Apache server-status page");
  }
  // phpinfo
  if (/phpinfo/.test(p)) {
    if (/phpinfo\(\)/i.test(body) || (/PHP Version/i.test(body) && /(Zend|Configure Command|php\.ini)/i.test(body))) {
      return { matched: true, evidence: "phpinfo() output exposed (full PHP + server environment)", severity: "high" };
    }
    return notFile("phpinfo() output");
  }
  // web.config
  if (/web\.config/.test(p)) {
    if (/<configuration>|<system\.web|<connectionStrings/i.test(body)) {
      return { matched: true, evidence: "web.config exposed (may contain connection strings)", severity: "high" };
    }
    return notFile("a web.config file");
  }
  // crossdomain.xml — only a finding if it wildcards access
  if (/crossdomain\.xml/.test(p)) {
    if (/<cross-domain-policy/i.test(body)) {
      const wildcard = /<allow-access-from\s+domain=["']\*["']/i.test(body);
      return wildcard
        ? { matched: true, evidence: "crossdomain.xml allows access from any domain (*)", severity: "medium" }
        : { matched: false, evidence: "crossdomain.xml present but restrictive — not a finding", severity: "info" };
    }
    return notFile("a crossdomain policy file");
  }
  // security.txt — its PRESENCE is good practice, not a vulnerability
  if (/security\.txt/.test(p)) {
    if (/^\s*Contact\s*:/im.test(body)) {
      return { matched: true, evidence: "security.txt present — this is GOOD practice, informational only", severity: "info" };
    }
    return { matched: false, evidence: "no valid security.txt", severity: "info" };
  }
  // swagger / openapi docs
  if (/swagger|openapi/.test(p)) {
    try {
      const j = JSON.parse(t);
      if (j && (j.swagger || j.openapi || j.paths)) {
        return { matched: true, evidence: "API documentation (Swagger/OpenAPI) is publicly readable", severity: "medium" };
      }
    } catch {
      /* not JSON */
    }
    return notFile("a valid Swagger/OpenAPI document");
  }
  // .DS_Store — binary metadata, never HTML
  if (/\.ds_store/.test(p)) {
    if (!html && (body.includes("\u0000") || /Bud1/.test(body))) {
      return { matched: true, evidence: ".DS_Store binary exposed (leaks directory/file names)", severity: "low" };
    }
    return notFile("a .DS_Store binary");
  }
  // ASP.NET diagnostics
  if (/elmah\.axd|trace\.axd/.test(p)) {
    if (/Error Log|Application Trace|ELMAH|Request Details/i.test(body)) {
      return { matched: true, evidence: "ASP.NET diagnostic log exposed", severity: "high" };
    }
    return notFile("an ASP.NET diagnostic page");
  }
  // .dockerenv — typically empty; only meaningful if reachable and not HTML
  if (/\.dockerenv/.test(p)) {
    if (!html && t.length < 50) return { matched: true, evidence: ".dockerenv reachable (unusual server exposure)", severity: "low" };
    return notFile("a .dockerenv marker");
  }
  // /debug catch — only if it returns non-HTML content
  if (/\/debug$/.test(p)) {
    if (!html && t.length > 0) return { matched: true, evidence: "debug endpoint returns non-HTML content", severity: "medium" };
    return notFile("a debug output page");
  }

  // Fallback: unknown path type. Only flag if it returned real non-HTML content.
  if (!html && t.length > 0) {
    return { matched: true, evidence: "returned non-HTML content at a sensitive path", severity: "low" };
  }
  return notFile("a sensitive file");
}

// =====================================================================
// JS BUNDLE SECRET SCANNING (feeds the Disclosure agent)
// =====================================================================
export const SECRET_PATTERNS: Array<[RegExp, string]> = [
  [/AKIA[0-9A-Z]{16}/g, "AWS Access Key ID"],
  [/(?:aws_secret_access_key|aws\.secret)[^\n]{0,20}['"][A-Za-z0-9/+=]{40}['"]/gi, "AWS Secret Key"],
  [/AIza[0-9A-Za-z\-_]{35}/g, "Google API Key"],
  [/sk-[A-Za-z0-9]{20,}/g, "OpenAI-style Secret Key"],
  [/sk_live_[0-9a-zA-Z]{24,}/g, "Stripe Live Secret Key"],
  [/gh[pousr]_[A-Za-z0-9]{36,}/g, "GitHub Token"],
  [/xox[baprs]-[0-9A-Za-z-]{10,}/g, "Slack Token"],
  [/-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g, "Private Key"],
  [/eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g, "JWT (verify it is not a public token)"],
  [/(?:api[_-]?key|apikey|secret|password|passwd|token)['"]?\s*[:=]\s*['"][^'"\s]{8,}['"]/gi, "Hardcoded credential-like assignment"],
];

export function scanTextForSecrets(text: string): string[] {
  const found = new Set<string>();
  for (const [re, label] of SECRET_PATTERNS) {
    if (re.test(text)) found.add(label);
    re.lastIndex = 0; // reset global regex state
  }
  return [...found];
}
