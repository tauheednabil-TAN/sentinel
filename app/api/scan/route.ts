import { NextRequest } from "next/server";
import {
  type Severity,
  type CalibrationResult,
  validateAndNormalizeUrl,
  normalizeBody,
  looksLikeBaseline,
  validateSignature,
  scanTextForSecrets,
} from "@/lib/checks";

export const runtime = "nodejs";
export const maxDuration = 300; // seconds — max for Hobby w/ Fluid Compute
// =====================================================================
// TYPES
// =====================================================================

type PathProbeResult = {
  path: string;
  status: number;
  contentType: string;
  snippet: string;
  exposed: boolean;
  // Why we decided this — surfaced to the agent so it reasons over evidence,
  // not raw status codes.
  confidence: "confirmed" | "none";
  evidence: string;
  severityHint: Severity;
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
  calibration: CalibrationResult | null;
};

// =====================================================================
// CONFIG
// =====================================================================
const USER_AGENT = "Sentinel-Scanner/2.0 (+educational security research)";
const FETCH_TIMEOUT_MS = 10000;
const PROBE_TIMEOUT_MS = 5000;
const MAX_SCRIPTS_SCANNED = 6;


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
    calibration: null,
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

// ---- Soft-404 / catch-all calibration --------------------------------------
// The core reason old scans lied: many hosts (SPAs, static hosts, custom 404s)
// return HTTP 200 with their normal HTML for EVERY url — including /.env. So a
// 200 proves nothing. We first fetch random non-existent paths to learn the
// server's "this does not exist" response, then compare every real probe to it.
const randToken = () => Math.random().toString(36).slice(2, 12);


async function calibrate(origin: string): Promise<CalibrationResult> {
  const randomPaths = [`/${randToken()}`, `/${randToken()}/${randToken()}.${randToken().slice(0, 3)}`];
  const samples = await Promise.all(
    randomPaths.map(async (rp) => {
      try {
        const res = await fetchWithTimeout(`${origin}${rp}`, PROBE_TIMEOUT_MS, { redirect: "follow" });
        const body = res.ok ? await res.text() : "";
        return { status: res.status, len: body.length, contentType: res.headers.get("content-type") || "", norm: normalizeBody(body) };
      } catch {
        return { status: 0, len: 0, contentType: "", norm: "" };
      }
    })
  );
  const twoHundreds = samples.filter((s) => s.status === 200);
  const base = twoHundreds[0] || samples[0];
  return {
    catchAll: twoHundreds.length > 0,
    baselineStatus: base.status,
    baselineLen: base.len,
    baselineContentType: base.contentType,
    baselineNorm: base.norm,
    samples: samples.length,
  };
}


async function probeSensitivePaths(baseUrl: string, calibration: CalibrationResult): Promise<PathProbeResult[]> {
  const origin = new URL(baseUrl).origin;

  // Fully parallel — all path probes fire at once for speed.
  const results = await Promise.all(
    SENSITIVE_PATHS.map(async (path): Promise<PathProbeResult> => {
      try {
        const res = await fetchWithTimeout(`${origin}${path}`, PROBE_TIMEOUT_MS, { redirect: "follow" });
        const contentType = res.headers.get("content-type") || "";

        // Anything other than 200 is not an exposed file.
        if (!res.ok) {
          return { path, status: res.status, contentType, snippet: "", exposed: false, confidence: "none", evidence: `HTTP ${res.status} — not accessible`, severityHint: "info" };
        }

        const body = await res.text();

        // Is this just the catch-all page the server returns for everything?
        if (looksLikeBaseline(body, calibration)) {
          return { path, status: res.status, contentType, snippet: "(matches soft-404 baseline)", exposed: false, confidence: "none", evidence: "Body is identical to the server's response for random non-existent paths — soft-404, NOT a real file", severityHint: "info" };
        }

        // Does the body actually match this file's real format?
        const sig = validateSignature(path, contentType, body);
        return {
          path,
          status: res.status,
          contentType,
          snippet: body.slice(0, 300).replace(/\s+/g, " ").trim(),
          exposed: sig.matched,
          confidence: sig.matched ? "confirmed" : "none",
          evidence: sig.evidence,
          severityHint: sig.severity,
        };
      } catch {
        return { path, status: 0, contentType: "", snippet: "(timeout/unreachable)", exposed: false, confidence: "none", evidence: "timeout/unreachable", severityHint: "info" };
      }
    })
  );

  return results;
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

  // 2. Fetch and scan same-origin external scripts (in parallel)
  const srcs = extractScriptSrcs(html, baseUrl);
  const scriptResults = await Promise.all(
    srcs.map(async (src): Promise<ScriptScanResult> => {
      try {
        const res = await fetchWithTimeout(src, PROBE_TIMEOUT_MS);
        if (!res.ok) {
          return { src, secretsFound: [], sourceMapReferenced: false, error: `HTTP ${res.status}` };
        }
        const body = await res.text();
        const secrets = scanTextForSecrets(body);
        const sourceMapReferenced = /\/\/[#@]\s*sourceMappingURL=/.test(body);
        return { src, secretsFound: secrets, sourceMapReferenced, error: null };
      } catch {
        return { src, secretsFound: [], sourceMapReferenced: false, error: "fetch failed/timeout" };
      }
    })
  );
  results.push(...scriptResults);

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

function formatCalibration(calib: CalibrationResult | null): string {
  if (!calib) return "";
  if (calib.catchAll) {
    return `--- SOFT-404 CALIBRATION (READ THIS FIRST) ---
Random, definitely-nonexistent paths were requested (${calib.samples} tested) and the server answered HTTP ${calib.baselineStatus} with a ${calib.baselineLen}-byte "${calib.baselineContentType}" page.
=> This server returns 200 for URLs THAT DO NOT EXIST. A 200 status here proves NOTHING.
=> Treat a path as exposed ONLY if its body genuinely contains that file's real contents. The probe results below already applied this rule.
--- END CALIBRATION ---`;
  }
  return `--- SOFT-404 CALIBRATION ---
Random nonexistent paths returned HTTP ${calib.baselineStatus} (not 200), so the server does distinguish real from missing paths. Still, confirm body content before reporting.
--- END CALIBRATION ---`;
}

function formatPathProbes(probes: PathProbeResult[]): string {
  if (probes.length === 0) return "(no path probes run)";
  const exposed = probes.filter((p) => p.exposed);
  const rejected = probes.filter((p) => !p.exposed && p.status === 200);
  const notFound = probes.filter((p) => !p.exposed && p.status > 0 && p.status !== 200);
  const unreachable = probes.filter((p) => p.status === 0);

  let out = `--- ACTIVE PATH PROBE RESULTS (content-validated) ---
Paths probed: ${probes.length}
CONFIRMED exposed (body matched the real file format): ${exposed.length}
Returned 200 but REJECTED (content did NOT match — soft-404 / normal page): ${rejected.length}
Not found / blocked (non-200): ${notFound.length}
Unreachable/Timeout: ${unreachable.length}

`;
  if (exposed.length > 0) {
    out += "CONFIRMED EXPOSED FILES (real findings — body was verified, use the suggested severity):\n";
    for (const p of exposed) {
      out += `  ${p.path} -> HTTP ${p.status} (${p.contentType})\n`;
      out += `    suggested severity: ${p.severityHint}\n`;
      out += `    evidence: ${p.evidence}\n`;
      if (p.snippet) out += `    preview: ${p.snippet.slice(0, 180)}\n`;
    }
    out += "\n";
  } else {
    out += "No paths passed content validation. Report NO file-exposure findings.\n\n";
  }
  if (rejected.length > 0) {
    out += "REJECTED — 200 status but NOT real files (DO NOT report these as findings):\n";
    out += rejected.map((p) => `  ${p.path} -> ${p.evidence}`).join("\n") + "\n";
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
- A 200 HTTP status is NEVER by itself a vulnerability. Judge the actual CONTENT that was returned, not the status code.
- CONFIRMED evidence (content-validated exposed paths, matched secret patterns, identified versions) should be reported as real findings with appropriate severity.
- If a check needs deeper active testing not covered by the data, include it with severity "info" and description "Requires deeper testing — not verifiable from available data."
- Do NOT hallucinate vulnerabilities that are not visible in the data. When in doubt, lower the severity or omit the finding.
- If nothing is found, return an empty findings array with a summary saying so.
- Keep descriptions concise and actionable.
`;

// =====================================================================
// AGENTS
// =====================================================================
const AGENTS = [
  {
    id: "recon", name: "Recon Agent", emoji: "🔍", description: "Reconnaissance & attack surface",
    focus: "Reconnaissance & attack surface: tech-stack fingerprinting, admin-panel hints in HTML/robots.txt, sensitive paths disclosed in robots.txt, exposed directory listings, and information leaked in the HTML.",
  },
  {
    id: "injection", name: "Injection Agent", emoji: "💉", description: "SQL injection, XSS, SSTI",
    focus: "Injection (SQLi/XSS/SSTI): forms are attack surface only — report detected forms as an \"info\" note that active payload testing is required; flag any obviously dangerous reflected input or inline eval-style JS visible in the HTML.",
  },
  {
    id: "auth", name: "Auth Agent", emoji: "🔐", description: "Authentication & session security",
    focus: "Authentication: is a login form served over HTTPS, do password fields disable autocomplete, are OAuth/SSO hints present. Brute-force, MFA and password-reset testing require active probing — mark those \"info\".",
  },
  {
    id: "api", name: "API Agent", emoji: "⚡", description: "API & endpoint security",
    focus: "API security: report exposed API docs (e.g. swagger) ONLY if they appear under CONFIRMED EXPOSED FILES; check API endpoints referenced in HTML/JS, a wildcarded Access-Control-Allow-Origin, and API keys visible in the HTML.",
  },
  {
    id: "ssl", name: "SSL/TLS Agent", emoji: "🔒", description: "Certificate & encryption",
    focus: "SSL/TLS: is the site HTTPS, is Strict-Transport-Security present, is there mixed content in the HTML. Cert chain, cipher suites and TLS versions need an active handshake — mark those \"info\".",
  },
  {
    id: "headers", name: "Headers Agent", emoji: "🛡", description: "Security headers & CSP",
    focus: "Security headers (directly observable in the response — be specific): report each missing/weak Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, Strict-Transport-Security, a wildcard Access-Control-Allow-Origin, and version disclosure in Server / X-Powered-By.",
  },
  {
    id: "session", name: "Session Agent", emoji: "🍪", description: "Cookies & CSRF protection",
    focus: "Sessions & CSRF: check Set-Cookie for missing HttpOnly/Secure/SameSite, session IDs in URLs, and CSRF token fields in forms. If no cookies were set on this passive request, note the limited view.",
  },
  {
    id: "access", name: "Access Control Agent", emoji: "🚧", description: "IDOR & privilege escalation",
    focus: "Access control: predictable ID patterns in URLs/links and admin paths in robots.txt/HTML. IDOR and privilege-escalation testing require authenticated probing — mark those \"info\".",
  },
  {
    id: "files", name: "File Agent", emoji: "📁", description: "File exposure & path traversal",
    focus: "File exposure: report a finding ONLY for paths listed under CONFIRMED EXPOSED FILES (already content-validated) using their stated evidence and severity. Everything under REJECTED is a soft-404 / normal page — NEVER report it, no matter how scary the path name (/.env, /backup.sql) looks. Also flag any file upload form in the HTML as \"info\".",
  },
  {
    id: "logic", name: "Logic Agent", emoji: "🧠", description: "Business logic & client-side trust",
    focus: "Business logic: report ONE \"info\" finding that logic testing (race conditions, workflow/price bypass) requires manual, authenticated, multi-step testing. ADDITIONALLY, if the HTML shows client-side-only validation of sensitive values (prices, discounts, roles, coupons hardcoded in JS/HTML), report that as a real finding.",
  },
  {
    id: "cve", name: "CVE Agent", emoji: "⚠️", description: "Known vulnerabilities & outdated libs",
    focus: "CVEs & outdated components: for any identified technology + version, describe the CLASSES of CVEs that affect that version range and whether it is likely end-of-life — NEVER fabricate specific CVE IDs. For unknown versions, recommend confirming them and note that version disclosure itself aids attackers.",
  },
  {
    id: "disclosure", name: "Disclosure Agent", emoji: "🕵️", description: "Information leakage & secrets",
    focus: "Information disclosure: a matched secret PATTERN is a lead, not proof. High-confidence patterns (AWS/Stripe/GitHub token, private key) → high/critical but say to verify the key is live; noisy ones (JWT, generic credential-like assignment) → \"info\"/\"low\", need manual check. Source maps → low/medium. Also flag internal IPs, stack traces, debug output, verbose Server/X-Powered-By headers, and sensitive HTML comments.",
  },
];

type Agent = (typeof AGENTS)[number];

// One prompt that asks the model to assess several areas at once and tag each
// finding with its area id. This replaces 12 separate LLM calls with a few
// combined ones, which fits free-tier token/request limits and is far faster.
const TEAM_JSON_FORMAT = `Respond ONLY as JSON (no markdown, no code fences, no extra text):
{"findings":[{"agent":"<area id from the list>","title":"Short finding name","severity":"critical|high|medium|low|info","description":"Clear explanation grounded in the data","impact":"What an attacker could do","fix_steps":["Step 1","Step 2"],"code_example":"config/code snippet or empty string","resources":["https://link.com"]}],"summary":"One sentence summary"}
Every finding MUST include an "agent" field equal to one of the area ids listed above. Areas with no finding are simply omitted.`;

function buildTeamPrompt(ctx: TargetContext, agents: Agent[]): string {
  const context = [
    formatContext(ctx),
    formatCalibration(ctx.calibration),
    formatTechFingerprints(ctx.techFingerprints),
    formatPathProbes(ctx.pathProbes),
    formatScriptScans(ctx.scriptScans),
  ]
    .filter(Boolean)
    .join("\n\n");

  const areas = agents.map((a) => `- ${a.id}: ${a.focus}`).join("\n");

  return `You are a team of website security specialists assessing ONE target. All evidence has already been gathered for you below. Assess ONLY the areas listed and report findings grounded strictly in this evidence.

${context}

AREAS TO ASSESS (tag every finding with the matching area id):
${areas}
${ANALYSIS_RULES}
${TEAM_JSON_FORMAT}`;
}

// =====================================================================
// LLM CALL — provider auto-selected by which API key is present.
// Both Groq and Google Gemini expose OpenAI-compatible chat endpoints, so the
// same request shape works for both. Set GEMINI_API_KEY to use Gemini, or
// GROQ_API_KEY (or legacy CEREBRAS_API_KEY) to use Groq.
// =====================================================================
type LLMProvider = { url: string; model: string; key: string; kind: "gemini" | "groq" };

function resolveProvider(): LLMProvider {
  // Groq is the default. With the combined-call design a whole scan is only ~3
  // calls, which fits Groq's limits and finishes in a few seconds (verified).
  // Gemini is a fallback (used when only a Gemini key is set) — its free tier
  // has a tight daily request cap, so it's not the default.
  const groq = process.env.GROQ_API_KEY || process.env.CEREBRAS_API_KEY;
  if (groq) {
    return {
      url: "https://api.groq.com/openai/v1/chat/completions",
      model: process.env.GROQ_MODEL || "openai/gpt-oss-120b",
      key: groq,
      kind: "groq",
    };
  }
  const gemini = process.env.GEMINI_API_KEY;
  if (gemini) {
    return {
      url: "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions",
      model: process.env.GEMINI_MODEL || "gemini-2.5-flash",
      key: gemini,
      kind: "gemini",
    };
  }
  throw new Error("No LLM API key set (GROQ_API_KEY or GEMINI_API_KEY)");
}

async function callLLM(prompt: string, maxTokens = 3000, attempt = 1): Promise<string> {
  const p = resolveProvider();

  const payload: Record<string, unknown> = {
    model: p.model,
    messages: [{ role: "user", content: prompt }],
    max_tokens: maxTokens,
  };
  // reasoning_effort is a gpt-oss (Groq) parameter; Gemini doesn't use it.
  if (p.kind === "groq") payload.reasoning_effort = "low";

  const res = await fetch(p.url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${p.key}`,
    },
    body: JSON.stringify(payload),
  });

  if (res.status === 429 && attempt <= 4) {
    const waitMs = 3000 * Math.pow(2, attempt - 1);
    console.log(`  429 rate-limited, waiting ${waitMs}ms then retrying (attempt ${attempt}/4)`);
    await sleep(waitMs);
    return callLLM(prompt, maxTokens, attempt + 1);
  }

  if (!res.ok) {
    const err = await res.text();
    throw new Error(`LLM API error ${res.status} (${p.kind}): ${err.slice(0, 200)}`);
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
  const validUrl = validateAndNormalizeUrl(body?.url, process.env.ALLOW_LOCAL_TARGETS === "true");

  // Chaos experiments (thesis Section 3.1.3 and Appendix B.2). A fault is injected
  // only when the request carries the secret CHAOS_KEY, so other users are never
  // affected. Modes: "block-model" fails every model call, "fail-one" fails the
  // first combined call, "garble" makes the first call return text that is not JSON.
  const chaosKey = process.env.CHAOS_KEY;
  const chaosMode: string | null =
    chaosKey && body?.chaosKey === chaosKey && ["block-model", "fail-one", "garble"].includes(body?.chaos)
      ? body.chaos
      : null;
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
        const origin = new URL(ctx.finalUrl || validUrl).origin;

        // Calibrate first: learn how the server responds to paths that don't
        // exist, so a catch-all 200 can't masquerade as an exposed file.
        send({ type: "calibrating", message: "Calibrating soft-404 behavior..." });
        ctx.calibration = await calibrate(origin);
        send({ type: "calibrated", catchAll: ctx.calibration.catchAll, baselineStatus: ctx.calibration.baselineStatus });

        send({ type: "probing", message: `Probing ${SENSITIVE_PATHS.length} sensitive paths...` });
        ctx.pathProbes = await probeSensitivePaths(ctx.finalUrl || validUrl, ctx.calibration);
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

      // ---- Step 4: analyze in a few COMBINED calls ----
      // Group the 12 areas into a handful of prompts (default 4 areas/call = 3
      // calls). Far fewer LLM calls keeps us under free-tier token/request
      // limits AND finishes fast; findings are then fanned back out to each card.
      for (const a of AGENTS) {
        send({ type: "agent_start", agentId: a.id, name: a.name, emoji: a.emoji });
      }

      const GROUP_SIZE = Math.max(1, Number(process.env.AGENT_GROUP_SIZE) || 6);
      const groups: Agent[][] = [];
      for (let i = 0; i < AGENTS.length; i += GROUP_SIZE) groups.push(AGENTS.slice(i, i + GROUP_SIZE));

      const findingsByAgent: Record<string, unknown[]> = {};
      const erroredAgents = new Set<string>();

      await Promise.all(
        groups.map(async (group, groupIndex) => {
          try {
            if (chaosMode === "block-model" || (chaosMode === "fail-one" && groupIndex === 0)) {
              throw new Error(`Chaos experiment (${chaosMode}): model call blocked`);
            }
            const text =
              chaosMode === "garble" && groupIndex === 0
                ? "Chaos experiment: this reply is deliberately not JSON."
                : await callLLM(buildTeamPrompt(ctx, group), 4000);
            let parsed: { findings?: Array<{ agent?: unknown } & Record<string, unknown>> };
            try {
              const clean = text.replace(/```json\n?/g, "").replace(/```\n?/g, "").trim();
              const jsonMatch = clean.match(/\{[\s\S]*\}/);
              parsed = JSON.parse(jsonMatch ? jsonMatch[0] : clean);
            } catch {
              parsed = { findings: [] };
            }
            for (const f of parsed.findings || []) {
              const id = typeof f.agent === "string" ? f.agent : "";
              if (!group.some((a) => a.id === id)) continue; // drop mis-tagged findings
              (findingsByAgent[id] ||= []).push(f);
            }
          } catch (err) {
            console.error(`[group ${group.map((a) => a.id).join(",")}]`, err);
            for (const a of group) erroredAgents.add(a.id);
          }
        })
      );

      // Fan results back out to each of the 12 agent cards.
      for (const a of AGENTS) {
        if (erroredAgents.has(a.id)) {
          send({ type: "agent_error", agentId: a.id, name: a.name, emoji: a.emoji, error: "AI service busy (rate limit) — please try again in a moment." });
        } else {
          send({ type: "agent_done", agentId: a.id, name: a.name, emoji: a.emoji, description: a.description, findings: findingsByAgent[a.id] || [], summary: "" });
        }
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
