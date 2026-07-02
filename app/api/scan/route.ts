import { NextRequest } from "next/server";

export const runtime = "nodejs";
export const maxDuration = 60; // Vercel Pro allows up to 60s; Hobby caps at 10s (documented in README).

// =====================================================================
// TYPES
// =====================================================================
type PathProbeResult = {
  path: string;
  status: number;
  contentType: string;
  snippet: string;
  exposed: boolean;
};

type ScriptScanResult = {
  src: string;
  secretsFound: string[];
  sourceMapReferenced: boolean;
  error: string | null;
};

type TechFingerprint = {
  name: string;
  version: string | null;
  source: string;
};

type TargetContext = {
  requestedUrl: string;
  finalUrl: string;
  status: number;
  statusText: string;
  isHttps: boolean;
  headers: Record<string, string>;
  htmlSnippet: string;
  robotsTxt: string | null;
  fetchError: string | null;
  pathProbes: PathProbeResult[];
  scriptScans: ScriptScanResult[];
  techFingerprints: TechFingerprint[];
  formsDetected: number;
  hasLoginForm: boolean;
};

// =====================================================================
// CONFIG
// =====================================================================
const USER_AGENT = "Sentinel-Scanner/2.0 (+educational security research)";
const FETCH_TIMEOUT_MS = 10000;
const PROBE_TIMEOUT_MS = 5000;
const MAX_SCRIPTS_SCANNED = 6;

// =====================================================================
// URL VALIDATION (SSRF guardrail)
// =====================================================================
function validateAndNormalizeUrl(input: unknown): string | null {
  if (typeof input !== "string" || input.trim().length === 0) return null;
  const trimmed = input.trim();
  try {
    const withProtocol = /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
    const parsed = new URL(withProtocol);

    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return null;
    if (!parsed.hostname.includes(".")) return null;

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
    if (blocked) return null;

    return parsed.href;
  } catch {
    return null;
  }
}

// =====================================================================
// HELPERS
// =====================================================================
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function fetchWithTimeout(url: string, timeoutMs: number, init: RequestInit = {}): Promise<Response> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, {
      ...init,
      signal: controller.signal,
      headers: { "User-Agent": USER_AGENT, ...(init.headers || {}) },
    });
  } finally {
    clearTimeout(timeout);
  }
}

// =====================================================================
// PASSIVE FETCH
// =====================================================================
async function fetchTarget(url: string): Promise<TargetContext> {
  const ctx: TargetContext = {
    requestedUrl: url,
    finalUrl: url,
    status: 0,
    statusText: "",
    isHttps: url.startsWith("https://"),
    headers: {},
    htmlSnippet: "",
    robotsTxt: null,
    fetchError: null,
    pathProbes: [],
    scriptScans: [],
    techFingerprints: [],
    formsDetected: 0,
    hasLoginForm: false,
  };

  let fullHtml = "";
  try {
    const res = await fetchWithTimeout(url, FETCH_TIMEOUT_MS, {
      redirect: "follow",
      headers: { Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" },
    });
    ctx.finalUrl = res.url;
    ctx.status = res.status;
    ctx.statusText = res.statusText;
    ctx.isHttps = res.url.startsWith("https://");
    res.headers.forEach((v, k) => {
      ctx.headers[k] = v;
    });
    fullHtml = await res.text();
    ctx.htmlSnippet = fullHtml.slice(0, 3000);
  } catch (err) {
    ctx.fetchError = err instanceof Error ? err.message : "unknown fetch error";
    return ctx;
  }

  // robots.txt (best effort)
  try {
    const robotsUrl = new URL("/robots.txt", ctx.finalUrl || url).href;
    const robotsRes = await fetchWithTimeout(robotsUrl, PROBE_TIMEOUT_MS);
    if (robotsRes.ok) ctx.robotsTxt = (await robotsRes.text()).slice(0, 1500);
  } catch {
    /* optional */
  }

  // Lightweight HTML analysis (no JS execution — passive)
  ctx.formsDetected = (fullHtml.match(/<form\b/gi) || []).length;
  ctx.hasLoginForm =
    /type=["']password["']/i.test(fullHtml) ||
    /\b(login|signin|sign-in|log-in)\b/i.test(fullHtml.slice(0, 5000));

  // Tech fingerprinting from headers + HTML
  ctx.techFingerprints = fingerprintTech(ctx.headers, fullHtml);

  return ctx;
}

// =====================================================================
// TECH FINGERPRINTING (feeds the CVE agent)
// =====================================================================
function fingerprintTech(headers: Record<string, string>, html: string): TechFingerprint[] {
  const fps: TechFingerprint[] = [];
  const add = (name: string, version: string | null, source: string) => {
    if (!fps.some((f) => f.name.toLowerCase() === name.toLowerCase())) {
      fps.push({ name, version, source });
    }
  };

  // Server / X-Powered-By headers
  const server = headers["server"];
  if (server) {
    const m = server.match(/([a-zA-Z-]+)\/?([\d.]+)?/);
    if (m) add(m[1], m[2] || null, "Server header");
  }
  const xpb = headers["x-powered-by"];
  if (xpb) {
    const m = xpb.match(/([a-zA-Z.\- ]+?)\/?([\d.]+)?$/);
    if (m) add(m[1].trim(), m[2] || null, "X-Powered-By header");
  }
  if (headers["x-aspnet-version"]) add("ASP.NET", headers["x-aspnet-version"], "X-AspNet-Version header");
  if (headers["x-generator"]) add(headers["x-generator"], null, "X-Generator header");

  // HTML generator meta tag
  const gen = html.match(/<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']/i);
  if (gen) {
    const parts = gen[1].match(/([a-zA-Z .]+?)\s*([\d.]+)?$/);
    if (parts) add(parts[1].trim(), parts[2] || null, "generator meta tag");
  }

  // Common JS libraries with versions in the script src
  const libPatterns: Array<[RegExp, string]> = [
    [/jquery[.-]?(\d+\.\d+\.\d+)/i, "jQuery"],
    [/angular[.-]?(\d+\.\d+\.\d+)/i, "Angular"],
    [/react[.-]?(\d+\.\d+\.\d+)/i, "React"],
    [/vue[.-]?(\d+\.\d+\.\d+)/i, "Vue"],
    [/bootstrap[.-]?(\d+\.\d+\.\d+)/i, "Bootstrap"],
    [/lodash[.-]?(\d+\.\d+\.\d+)/i, "Lodash"],
  ];
  for (const [re, name] of libPatterns) {
    const m = html.match(re);
    if (m) add(name, m[1], "script src");
  }

  // WordPress / Drupal / Joomla path hints
  if (/wp-content|wp-includes/i.test(html)) add("WordPress", null, "wp-content path");
  if (/sites\/default\/files|drupal/i.test(html)) add("Drupal", null, "Drupal path");
  if (/media\/jui|joomla/i.test(html)) add("Joomla", null, "Joomla path");

  return fps;
}

// =====================================================================
// ACTIVE PATH PROBING (feeds the Files agent)
// =====================================================================
const SENSITIVE_PATHS = [
  "/.env",
  "/.env.local",
  "/.env.backup",
  "/.git/HEAD",
  "/.git/config",
  "/wp-config.php.bak",
  "/wp-config.php~",
  "/.htaccess",
  "/server-status",
  "/phpinfo.php",
  "/.DS_Store",
  "/backup.sql",
  "/database.sql",
  "/dump.sql",
  "/config.php.bak",
  "/web.config",
  "/crossdomain.xml",
  "/.well-known/security.txt",
  "/debug",
  "/api/swagger.json",
  "/swagger.json",
  "/.dockerenv",
  "/elmah.axd",
  "/trace.axd",
  "/.svn/entries",
];

function looksLikeErrorPage(body: string): boolean {
  const lower = body.toLowerCase();
  return (
    lower.includes("not found") ||
    lower.includes("404") ||
    lower.includes("page not found") ||
    lower.includes("does not exist") ||
    body.length > 15000
  );
}

async function probeSensitivePaths(baseUrl: string): Promise<PathProbeResult[]> {
  const origin = new URL(baseUrl).origin;
  const results: PathProbeResult[] = [];

  for (let i = 0; i < SENSITIVE_PATHS.length; i += 5) {
    const batch = SENSITIVE_PATHS.slice(i, i + 5);
    const batchResults = await Promise.all(
      batch.map(async (path): Promise<PathProbeResult> => {
        try {
          const res = await fetchWithTimeout(`${origin}${path}`, PROBE_TIMEOUT_MS, { redirect: "follow" });
          const contentType = res.headers.get("content-type") || "";
          let snippet = "";
          let exposed = false;

          if (res.ok) {
            const body = await res.text();
            if (contentType.includes("text/html")) {
              if (looksLikeErrorPage(body)) {
                snippet = "(HTML error/redirect page)";
                exposed = false;
              } else {
                snippet = body.slice(0, 400);
                exposed = true;
              }
            } else {
              snippet = body.slice(0, 400);
              exposed = true;
            }
          }

          return { path, status: res.status, contentType, snippet, exposed };
        } catch {
          return { path, status: 0, contentType: "", snippet: "(timeout/unreachable)", exposed: false };
        }
      })
    );
    results.push(...batchResults);
  }

  return results;
}

// =====================================================================
// JS BUNDLE SECRET SCANNING (feeds the Disclosure agent)
// =====================================================================
const SECRET_PATTERNS: Array<[RegExp, string]> = [
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

function scanTextForSecrets(text: string): string[] {
  const found = new Set<string>();
  for (const [re, label] of SECRET_PATTERNS) {
    if (re.test(text)) found.add(label);
    re.lastIndex = 0; // reset global regex state
  }
  return [...found];
}

function extractScriptSrcs(html: string, baseUrl: string): string[] {
  const srcs: string[] = [];
  const re = /<script[^>]+src=["']([^"']+)["']/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(html)) !== null) {
    try {
      const abs = new URL(m[1], baseUrl).href;
      // Only scan same-origin scripts (skip CDN libs to save time + they are public)
      if (new URL(abs).origin === new URL(baseUrl).origin) srcs.push(abs);
    } catch {
      /* skip malformed */
    }
  }
  return [...new Set(srcs)].slice(0, MAX_SCRIPTS_SCANNED);
}

async function scanScriptsForSecrets(html: string, baseUrl: string, inlineHtml: string): Promise<ScriptScanResult[]> {
  const results: ScriptScanResult[] = [];

  // 1. Scan inline HTML itself (inline <script> blocks + attributes)
  const inlineSecrets = scanTextForSecrets(inlineHtml);
  if (inlineSecrets.length > 0) {
    results.push({ src: "(inline HTML / inline scripts)", secretsFound: inlineSecrets, sourceMapReferenced: false, error: null });
  }

  // 2. Fetch and scan same-origin external scripts
  const srcs = extractScriptSrcs(html, baseUrl);
  for (const src of srcs) {
    try {
      const res = await fetchWithTimeout(src, PROBE_TIMEOUT_MS);
      if (!res.ok) {
        results.push({ src, secretsFound: [], sourceMapReferenced: false, error: `HTTP ${res.status}` });
        continue;
      }
      const body = await res.text();
      const secrets = scanTextForSecrets(body);
      const sourceMapReferenced = /\/\/[#@]\s*sourceMappingURL=/.test(body);
      results.push({ src, secretsFound: secrets, sourceMapReferenced, error: null });
    } catch {
      results.push({ src, secretsFound: [], sourceMapReferenced: false, error: "fetch failed/timeout" });
    }
  }

  return results;
}

// =====================================================================
// CONTEXT FORMATTERS (injected into prompts)
// =====================================================================
function formatContext(ctx: TargetContext): string {
  if (ctx.fetchError) {
    return `--- OBSERVED DATA ---
Requested URL: ${ctx.requestedUrl}
Fetch error: ${ctx.fetchError}
NOTE: The target could not be reached. Only report findings that can be inferred from this failure (e.g. DNS issues, unreachable host). Do NOT invent vulnerabilities.
--- END DATA ---`;
  }

  const headerLines = Object.entries(ctx.headers)
    .map(([k, v]) => `  ${k}: ${v}`)
    .join("\n");

  return `--- OBSERVED DATA ---
Requested URL: ${ctx.requestedUrl}
Final URL after redirects: ${ctx.finalUrl}
HTTPS: ${ctx.isHttps}
HTTP status: ${ctx.status} ${ctx.statusText}
Forms detected in HTML: ${ctx.formsDetected}
Login form likely present: ${ctx.hasLoginForm}

Response headers:
${headerLines || "  (none captured)"}

robots.txt (first 1500 chars):
${ctx.robotsTxt ?? "(not available)"}

HTML snippet (first 3000 chars):
${ctx.htmlSnippet || "(empty response body)"}
--- END DATA ---`;
}

function formatPathProbes(probes: PathProbeResult[]): string {
  if (probes.length === 0) return "(no path probes run)";
  const exposed = probes.filter((p) => p.exposed);
  const blocked = probes.filter((p) => !p.exposed && p.status > 0);
  const unreachable = probes.filter((p) => p.status === 0);

  let out = `--- ACTIVE PATH PROBE RESULTS ---
Paths probed: ${probes.length}
EXPOSED (200 + real content): ${exposed.length}
Blocked/Not Found: ${blocked.length}
Unreachable/Timeout: ${unreachable.length}

`;
  if (exposed.length > 0) {
    out += "EXPOSED PATHS (these are CONFIRMED findings):\n";
    for (const p of exposed) {
      out += `  ${p.path} -> HTTP ${p.status} (${p.contentType})\n`;
      if (p.snippet && p.snippet !== "(HTML error/redirect page)") {
        out += `    preview: ${p.snippet.slice(0, 180).replace(/\s+/g, " ")}\n`;
      }
    }
    out += "\n";
  }
  if (blocked.length > 0) {
    out += "BLOCKED/NOT FOUND (no issue):\n";
    out += blocked.map((p) => `  ${p.path} -> HTTP ${p.status}`).join("\n") + "\n";
  }
  out += "--- END PATH PROBES ---";
  return out;
}

function formatTechFingerprints(fps: TechFingerprint[]): string {
  if (fps.length === 0) return "(no technology fingerprints identified from observed data)";
  let out = "--- TECHNOLOGY FINGERPRINTS (from headers, meta tags, script paths) ---\n";
  for (const f of fps) {
    out += `  ${f.name}${f.version ? ` v${f.version}` : " (version unknown)"} — detected via ${f.source}\n`;
  }
  out += "--- END FINGERPRINTS ---";
  return out;
}

function formatScriptScans(scans: ScriptScanResult[]): string {
  if (scans.length === 0) return "(no scripts scanned)";
  const withSecrets = scans.filter((s) => s.secretsFound.length > 0);
  const withMaps = scans.filter((s) => s.sourceMapReferenced);

  let out = `--- JAVASCRIPT / INLINE SECRET SCAN ---
Scripts scanned: ${scans.length}
Scripts with potential secrets: ${withSecrets.length}
Scripts referencing source maps: ${withMaps.length}

`;
  if (withSecrets.length > 0) {
    out += "POTENTIAL SECRETS FOUND (CONFIRMED patterns in fetched code):\n";
    for (const s of withSecrets) {
      out += `  ${s.src}\n    patterns: ${s.secretsFound.join(", ")}\n`;
    }
    out += "\n";
  }
  if (withMaps.length > 0) {
    out += "SOURCE MAPS REFERENCED (may expose original source):\n";
    out += withMaps.map((s) => `  ${s.src}`).join("\n") + "\n";
  }
  if (withSecrets.length === 0 && withMaps.length === 0) {
    out += "No obvious secrets or source maps detected in scanned scripts.\n";
  }
  out += "--- END SECRET SCAN ---";
  return out;
}

// =====================================================================
// ANALYSIS RULES (shared)
// =====================================================================
const ANALYSIS_RULES = `
Rules:
- ONLY report findings verifiable from the data provided above.
- CONFIRMED evidence (exposed paths, matched secret patterns, identified versions) should be reported as real findings with appropriate severity.
- If a check needs deeper active testing not covered by the data, include it with severity "info" and description "Requires deeper testing — not verifiable from available data."
- Do NOT hallucinate vulnerabilities that are not visible in the data.
- If nothing is found, return an empty findings array with a summary saying so.
- Keep descriptions concise and actionable.
`;

const JSON_FORMAT = `Respond ONLY in this exact JSON format (no markdown, no code fences, no extra text):
{"findings":[{"title":"Short finding name","severity":"critical|high|medium|low|info","description":"Clear explanation grounded in the data","impact":"What an attacker could do","fix_steps":["Step 1","Step 2","Step 3"],"code_example":"config/code snippet or empty string","resources":["https://link.com"]}],"summary":"One sentence summary"}`;

// =====================================================================
// AGENTS
// =====================================================================
const AGENTS = [
  {
    id: "recon",
    name: "Recon Agent",
    emoji: "🔍",
    description: "Reconnaissance & attack surface",
    prompt: (ctx: TargetContext) => `You are a cybersecurity reconnaissance expert.

${formatContext(ctx)}

${formatTechFingerprints(ctx.techFingerprints)}

Based on the OBSERVED DATA, check for: tech stack fingerprinting, admin panel hints in HTML/robots.txt, sensitive paths disclosed in robots.txt, exposed directory listings, information leaked in the HTML.
${ANALYSIS_RULES}
${JSON_FORMAT}`,
  },
  {
    id: "injection",
    name: "Injection Agent",
    emoji: "💉",
    description: "SQL injection, XSS, SSTI",
    prompt: (ctx: TargetContext) => `You are an injection vulnerability expert.

${formatContext(ctx)}

Based on the OBSERVED DATA: ${ctx.formsDetected} form(s) were detected. Injection testing requires active payload probing, which this passive scan does not perform. Report forms as an "info"-level attack surface note ("requires deeper testing"), and flag any obviously dangerous reflected input or inline eval-style JS visible in the HTML.
${ANALYSIS_RULES}
${JSON_FORMAT}`,
  },
  {
    id: "auth",
    name: "Auth Agent",
    emoji: "🔐",
    description: "Authentication & session security",
    prompt: (ctx: TargetContext) => `You are an authentication security expert.

${formatContext(ctx)}

Based on the OBSERVED DATA: login form likely present = ${ctx.hasLoginForm}. Check: is any login form served over HTTPS, do password fields have autocomplete disabled, are OAuth/SSO hints present. Brute-force, MFA, and password-reset testing require active probing — mark those "info" with "requires deeper testing".
${ANALYSIS_RULES}
${JSON_FORMAT}`,
  },
  {
    id: "api",
    name: "API Agent",
    emoji: "⚡",
    description: "API & endpoint security",
    prompt: (ctx: TargetContext) => `You are an API security expert.

${formatContext(ctx)}

${formatPathProbes(ctx.pathProbes.filter((p) => p.path.includes("swagger") || p.path.includes("api")))}

Based on the OBSERVED DATA and probe results: check for exposed API docs (swagger.json), API endpoints referenced in HTML/JS, CORS headers (is Access-Control-Allow-Origin wildcarded?), and API keys visible in HTML. Endpoint auth testing requires active probing.
${ANALYSIS_RULES}
${JSON_FORMAT}`,
  },
  {
    id: "ssl",
    name: "SSL/TLS Agent",
    emoji: "🔒",
    description: "Certificate & encryption",
    prompt: (ctx: TargetContext) => `You are an SSL/TLS security expert.

${formatContext(ctx)}

Based on the OBSERVED DATA: is the site HTTPS (${ctx.isHttps}), is Strict-Transport-Security present, is there mixed content in the HTML. Cert chain, cipher suites, and TLS versions require an active TLS handshake probe (not performed here) — mark those "info" with "requires deeper testing".
${ANALYSIS_RULES}
${JSON_FORMAT}`,
  },
  {
    id: "headers",
    name: "Headers Agent",
    emoji: "🛡",
    description: "Security headers & CSP",
    prompt: (ctx: TargetContext) => `You are a security headers expert. Response headers are directly observable, so be specific.

${formatContext(ctx)}

Check EACH and report missing/weak: Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, Strict-Transport-Security, Access-Control-Allow-Origin (wildcard?), and server version disclosure in Server / X-Powered-By.
${ANALYSIS_RULES}
${JSON_FORMAT}`,
  },
  {
    id: "session",
    name: "Session Agent",
    emoji: "🍪",
    description: "Cookies & CSRF protection",
    prompt: (ctx: TargetContext) => `You are a session security expert.

${formatContext(ctx)}

Check Set-Cookie headers for missing HttpOnly, Secure, SameSite flags. Check for session IDs in URLs and CSRF token hidden fields in forms. If no cookies were set on this passive request, note the limited view.
${ANALYSIS_RULES}
${JSON_FORMAT}`,
  },
  {
    id: "access",
    name: "Access Control Agent",
    emoji: "🚧",
    description: "IDOR & privilege escalation",
    prompt: (ctx: TargetContext) => `You are an access control security expert.

${formatContext(ctx)}

Check for predictable ID patterns in URLs/links and admin paths in robots.txt/HTML. IDOR and privilege-escalation testing require authenticated active probing — mark those "info" with "requires deeper testing".
${ANALYSIS_RULES}
${JSON_FORMAT}`,
  },
  {
    id: "files",
    name: "File Agent",
    emoji: "📁",
    description: "File exposure & path traversal",
    prompt: (ctx: TargetContext) => `You are a file security expert with ACTIVE PROBE DATA — real results from fetching sensitive paths.

${formatContext(ctx)}

${formatPathProbes(ctx.pathProbes)}

Based on BOTH the page data AND the probe results:
- Every EXPOSED path is a CONFIRMED finding. Severity: critical for .env / DB dumps / private keys; high for .git exposure; medium for config/server-status; low/info for security.txt/sitemap.
- Use each exposed path's content preview to describe what is actually leaked.
- BLOCKED/NOT FOUND paths are NOT findings.
- Also check the HTML for file upload forms.
${ANALYSIS_RULES}
${JSON_FORMAT}`,
  },
  {
    id: "logic",
    name: "Logic Agent",
    emoji: "🧠",
    description: "Business logic & client-side trust",
    prompt: (ctx: TargetContext) => `You are a business logic security expert.

${formatContext(ctx)}

Full business-logic testing (race conditions, workflow bypass, price manipulation) requires interactive, authenticated, multi-step testing with a real browser — this scan does not perform that. Report ONE honest "info" finding stating business-logic testing requires deeper manual/active assessment. ADDITIONALLY, if the HTML clearly shows client-side-only validation of sensitive values (e.g. prices, discounts, roles, or coupon codes hardcoded in JS/HTML), report that as a real finding, since client-side-only trust is verifiable from the source.
${ANALYSIS_RULES}
${JSON_FORMAT}`,
  },
  {
    id: "cve",
    name: "CVE Agent",
    emoji: "⚠️",
    description: "Known vulnerabilities & outdated libs",
    prompt: (ctx: TargetContext) => `You are a CVE and dependency expert with real fingerprint data.

${formatContext(ctx)}

${formatTechFingerprints(ctx.techFingerprints)}

Based on the identified technologies and versions above:
- For any component with a KNOWN version, describe the classes of CVEs that historically affect that version range and whether it is likely end-of-life or outdated. Reference the CVE class, not a fabricated specific CVE ID unless you are certain.
- For components with UNKNOWN version, recommend confirming the version and note that version disclosure itself (e.g. in Server header) aids attackers.
- Do NOT invent CVE numbers. If unsure of a specific ID, describe the vulnerability class instead.
${ANALYSIS_RULES}
${JSON_FORMAT}`,
  },
  {
    id: "disclosure",
    name: "Disclosure Agent",
    emoji: "🕵️",
    description: "Information leakage & secrets",
    prompt: (ctx: TargetContext) => `You are an information disclosure expert with ACTIVE JS-SCAN DATA.

${formatContext(ctx)}

${formatScriptScans(ctx.scriptScans)}

Based on the page data AND the secret-scan results:
- Any script/inline block with matched secret PATTERNS is a potential CONFIRMED finding — report it (severity high/critical for live keys, medium for JWTs that may be public). Advise the user to verify whether each match is a real secret vs a false positive.
- Source maps referenced in production are a low/medium finding (they can expose original source).
- Also check headers/HTML for internal IPs, stack traces, debug output, verbose Server/X-Powered-By headers, and sensitive HTML comments.
${ANALYSIS_RULES}
${JSON_FORMAT}`,
  },
];

// =====================================================================
// CEREBRAS CALL (with retry/backoff)
// =====================================================================
async function callCerebras(prompt: string, attempt = 1): Promise<string> {
  const apiKey = process.env.CEREBRAS_API_KEY;
  if (!apiKey) throw new Error("CEREBRAS_API_KEY not set in environment");

  const res = await fetch("https://api.cerebras.ai/v1/chat/completions", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${apiKey}`,
    },
    body: JSON.stringify({
      model: "gpt-oss-120b",
      messages: [{ role: "user", content: prompt }],
      max_tokens: 3000,
      reasoning_effort: "low",
    }),
  });

  if (res.status === 429 && attempt <= 4) {
    const waitMs = 3000 * Math.pow(2, attempt - 1);
    console.log(`  429 rate-limited, waiting ${waitMs}ms then retrying (attempt ${attempt}/4)`);
    await sleep(waitMs);
    return callCerebras(prompt, attempt + 1);
  }

  if (!res.ok) {
    const err = await res.text();
    throw new Error(`Cerebras API error ${res.status}: ${err.slice(0, 200)}`);
  }

  const data = await res.json();
  const msg = data.choices?.[0]?.message;
  return msg?.content || msg?.reasoning || "";
}

// =====================================================================
// POST HANDLER
// =====================================================================
export async function POST(req: NextRequest) {
  const body = await req.json().catch(() => ({}));
  const validUrl = validateAndNormalizeUrl(body?.url);
  if (!validUrl) {
    return new Response(
      JSON.stringify({
        error: "Please enter a valid public domain (e.g. example.com). Localhost and private IPs are not allowed.",
      }),
      { status: 400, headers: { "Content-Type": "application/json" } }
    );
  }

  const encoder = new TextEncoder();
  const stream = new ReadableStream({
    async start(controller) {
      let closed = false;
      const send = (data: object) => {
        if (closed) return;
        try {
          controller.enqueue(encoder.encode(`data: ${JSON.stringify(data)}\n\n`));
        } catch {
          closed = true;
        }
      };

      send({ type: "start", total: AGENTS.length });

      // ---- Step 1: passive fetch ----
      send({ type: "fetching", url: validUrl });
      const ctx = await fetchTarget(validUrl);
      send({ type: "fetched", status: ctx.status, finalUrl: ctx.finalUrl, error: ctx.fetchError });

      // ---- Step 2 & 3: active recon (only if reachable) ----
      if (!ctx.fetchError) {
        send({ type: "probing", message: `Probing ${SENSITIVE_PATHS.length} sensitive paths...` });
        ctx.pathProbes = await probeSensitivePaths(ctx.finalUrl || validUrl);
        send({
          type: "probed",
          total: ctx.pathProbes.length,
          exposed: ctx.pathProbes.filter((p) => p.exposed).length,
        });

        send({ type: "scanning_scripts", message: "Scanning JavaScript for secrets..." });
        // Re-fetch full HTML once for script extraction (htmlSnippet is truncated)
        let fullHtml = ctx.htmlSnippet;
        try {
          const r = await fetchWithTimeout(ctx.finalUrl || validUrl, FETCH_TIMEOUT_MS, { redirect: "follow" });
          if (r.ok) fullHtml = await r.text();
        } catch {
          /* fall back to snippet */
        }
        ctx.scriptScans = await scanScriptsForSecrets(fullHtml, ctx.finalUrl || validUrl, fullHtml);
        send({
          type: "scripts_scanned",
          total: ctx.scriptScans.length,
          withSecrets: ctx.scriptScans.filter((s) => s.secretsFound.length > 0).length,
        });
      }

      // ---- Step 4: run agents sequentially ----
      const runAgent = async (agent: (typeof AGENTS)[number]) => {
        send({ type: "agent_start", agentId: agent.id, name: agent.name, emoji: agent.emoji });
        try {
          const text = await callCerebras(agent.prompt(ctx));
          let parsed: { findings?: unknown[]; summary?: string };
          try {
            const clean = text.replace(/```json\n?/g, "").replace(/```\n?/g, "").trim();
            const jsonMatch = clean.match(/\{[\s\S]*\}/);
            parsed = JSON.parse(jsonMatch ? jsonMatch[0] : clean);
          } catch {
            parsed = {
              findings: [
                {
                  title: "Analysis completed",
                  severity: "info",
                  description: text.slice(0, 300),
                  impact: "Review manually",
                  fix_steps: ["Manual review needed"],
                  code_example: "",
                  resources: [],
                },
              ],
              summary: "Agent completed",
            };
          }
          send({
            type: "agent_done",
            agentId: agent.id,
            name: agent.name,
            emoji: agent.emoji,
            description: agent.description,
            findings: parsed.findings || [],
            summary: parsed.summary || "",
          });
        } catch (err) {
          console.error(`[${agent.id}]`, err);
          send({
            type: "agent_error",
            agentId: agent.id,
            name: agent.name,
            emoji: agent.emoji,
            error: err instanceof Error ? err.message : "Unknown error",
          });
        }
      };

      for (let i = 0; i < AGENTS.length; i++) {
        await runAgent(AGENTS[i]);
        if (i < AGENTS.length - 1) await sleep(2500);
      }

      send({ type: "done" });
      closed = true;
      controller.close();
    },
  });

  return new Response(stream, {
    headers: {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      Connection: "keep-alive",
    },
  });
}