import { NextRequest } from "next/server";

// ---------- Types ----------
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
};

// ---------- URL validation ----------
function validateAndNormalizeUrl(input: unknown): string | null {
  if (typeof input !== "string" || input.trim().length === 0) return null;
  const trimmed = input.trim();
  try {
    const withProtocol = /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
    const parsed = new URL(withProtocol);
    // Must have a dot in hostname (basic TLD check)
    if (!parsed.hostname.includes(".")) return null;
    // Block localhost, loopback, private ranges (SSRF guardrail)
    const host = parsed.hostname.toLowerCase();
    if (
      host === "localhost" ||
      host.endsWith(".localhost") ||
      /^127\./.test(host) ||
      /^10\./.test(host) ||
      /^192\.168\./.test(host) ||
      /^172\.(1[6-9]|2\d|3[01])\./.test(host) ||
      /^169\.254\./.test(host) ||
      host === "0.0.0.0" ||
      host === "::1"
    ) {
      return null;
    }
    return parsed.href;
  } catch {
    return null;
  }
}

// ---------- Passive target fetch ----------
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
  };

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10000);

  try {
    const res = await fetch(url, {
      signal: controller.signal,
      redirect: "follow",
      headers: {
        "User-Agent": "Sentinel-Scanner/1.0 (educational security research tool)",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      },
    });
    ctx.finalUrl = res.url;
    ctx.status = res.status;
    ctx.statusText = res.statusText;
    ctx.isHttps = res.url.startsWith("https://");
    res.headers.forEach((v, k) => {
      ctx.headers[k] = v;
    });
    const body = await res.text();
    ctx.htmlSnippet = body.slice(0, 3000);
  } catch (err) {
    ctx.fetchError = err instanceof Error ? err.message : "unknown fetch error";
  } finally {
    clearTimeout(timeout);
  }

  // Best-effort robots.txt fetch (small, quick)
  try {
    const robotsController = new AbortController();
    const robotsTimeout = setTimeout(() => robotsController.abort(), 5000);
    const robotsUrl = new URL("/robots.txt", ctx.finalUrl || url).href;
    const robotsRes = await fetch(robotsUrl, {
      signal: robotsController.signal,
      headers: { "User-Agent": "Sentinel-Scanner/1.0" },
    });
    clearTimeout(robotsTimeout);
    if (robotsRes.ok) {
      const t = await robotsRes.text();
      ctx.robotsTxt = t.slice(0, 1500);
    }
  } catch {
    // Ignore robots errors — it's optional context
  }

  return ctx;
}

// ---------- Format target context for prompts ----------
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

Response headers:
${headerLines || "  (none captured)"}

robots.txt (first 1500 chars):
${ctx.robotsTxt ?? "(not available)"}

HTML snippet (first 3000 chars):
${ctx.htmlSnippet || "(empty response body)"}
--- END DATA ---`;
}

// ---------- Common analysis rules injected into every prompt ----------
const ANALYSIS_RULES = `
Rules:
- ONLY report findings that can be verified from the OBSERVED DATA above.
- If a check requires deeper testing (active probing, authentication, source code access) and cannot be verified from a passive HTTP fetch, either omit it OR include it with severity "info" and description "Requires deeper testing — cannot be verified from passive fetch alone."
- Do NOT hallucinate vulnerabilities that are not visible in the response data.
- If no issues are visible, return an empty findings array and a summary saying so.
`;

// ---------- Agents ----------
const AGENTS = [
  {
    id: "recon",
    name: "Recon Agent",
    emoji: "🔍",
    description: "Reconnaissance & attack surface",
    prompt: (ctx: TargetContext) => `You are a cybersecurity reconnaissance expert.

${formatContext(ctx)}

Based on the OBSERVED DATA, check for: tech stack fingerprinting (from Server header, X-Powered-By, HTML meta tags), admin panel hints in HTML/robots.txt, sensitive paths in robots.txt, exposed directory listings, WHOIS/DNS leakage in HTML.
${ANALYSIS_RULES}
Respond ONLY in this exact JSON format (no markdown):
{"findings":[{"title":"Short finding name","severity":"critical|high|medium|low|info","description":"Clear explanation grounded in observed data","impact":"What an attacker could do","fix_steps":["Step 1","Step 2","Step 3"],"code_example":"config snippet or empty string","resources":["https://link.com"]}],"summary":"One sentence summary"}`,
  },

  {
    id: "injection",
    name: "Injection Agent",
    emoji: "💉",
    description: "SQL injection, XSS, SSTI",
    prompt: (ctx: TargetContext) => `You are an injection vulnerability expert.

${formatContext(ctx)}

Based on the OBSERVED DATA, check for: forms present in the HTML (are inputs likely to be sanitized?), URL query parameters visible in the HTML/redirects, obvious reflected input, dangerous inline JS patterns. Injection testing usually requires active probing — most findings here should be "info" with "requires deeper testing" unless something is obviously wrong.
${ANALYSIS_RULES}
Respond ONLY in this exact JSON format (no markdown):
{"findings":[{"title":"Short finding name","severity":"critical|high|medium|low|info","description":"Clear explanation grounded in observed data","impact":"What an attacker could do","fix_steps":["Step 1","Step 2","Step 3"],"code_example":"secure code snippet or empty string","resources":["https://owasp.org"]}],"summary":"One sentence summary"}`,
  },

  {
    id: "auth",
    name: "Auth Agent",
    emoji: "🔐",
    description: "Authentication & session security",
    prompt: (ctx: TargetContext) => `You are an authentication security expert.

${formatContext(ctx)}

Based on the OBSERVED DATA, check for: login forms in HTML (do they use HTTPS?), password field types, autocomplete attributes on password fields, OAuth/SSO hints, exposed auth endpoints. Most auth testing requires active probing — mark those as "info" with "requires deeper testing".
${ANALYSIS_RULES}
Respond ONLY in this exact JSON format (no markdown):
{"findings":[{"title":"Short finding name","severity":"critical|high|medium|low|info","description":"Clear explanation grounded in observed data","impact":"What an attacker could do","fix_steps":["Step 1","Step 2","Step 3"],"code_example":"secure implementation or empty string","resources":["https://owasp.org"]}],"summary":"One sentence summary"}`,
  },

  {
    id: "api",
    name: "API Agent",
    emoji: "⚡",
    description: "API & endpoint security",
    prompt: (ctx: TargetContext) => `You are an API security expert.

${formatContext(ctx)}

Based on the OBSERVED DATA, check for: API endpoints referenced in HTML/JS, Swagger/OpenAPI docs paths in robots.txt, GraphQL endpoints, exposed API keys or tokens in HTML source, CORS headers. Endpoint enumeration and auth testing require active probing.
${ANALYSIS_RULES}
Respond ONLY in this exact JSON format (no markdown):
{"findings":[{"title":"Short finding name","severity":"critical|high|medium|low|info","description":"Clear explanation grounded in observed data","impact":"What an attacker could do","fix_steps":["Step 1","Step 2","Step 3"],"code_example":"secure code or empty string","resources":["https://owasp.org"]}],"summary":"One sentence summary"}`,
  },

  {
    id: "ssl",
    name: "SSL/TLS Agent",
    emoji: "🔒",
    description: "Certificate & encryption",
    prompt: (ctx: TargetContext) => `You are an SSL/TLS security expert.

${formatContext(ctx)}

Based on the OBSERVED DATA, check for: is the site using HTTPS at all, does it redirect HTTP to HTTPS, is HSTS header present (Strict-Transport-Security), mixed content in HTML. Cert validity, cipher suites, and TLS versions require an active TLS probe — mark those as "info" with "requires deeper testing".
${ANALYSIS_RULES}
Respond ONLY in this exact JSON format (no markdown):
{"findings":[{"title":"Short finding name","severity":"critical|high|medium|low|info","description":"Clear explanation grounded in observed data","impact":"What an attacker could do","fix_steps":["Step 1","Step 2","Step 3"],"code_example":"nginx/apache config or empty string","resources":["https://link.com"]}],"summary":"One sentence summary"}`,
  },

  {
    id: "headers",
    name: "Headers Agent",
    emoji: "🛡",
    description: "Security headers & CSP",
    prompt: (ctx: TargetContext) => `You are a security headers expert. This agent can be VERY specific because response headers are directly observable.

${formatContext(ctx)}

Based on the OBSERVED HEADERS, check EACH of these and report which are missing or weak: Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, Strict-Transport-Security, CORS headers (Access-Control-Allow-Origin — is it wildcarded?), server version disclosure in Server / X-Powered-By.
${ANALYSIS_RULES}
Respond ONLY in this exact JSON format (no markdown):
{"findings":[{"title":"Short finding name","severity":"critical|high|medium|low|info","description":"Clear explanation grounded in observed data","impact":"What an attacker could do","fix_steps":["Step 1","Step 2","Step 3"],"code_example":"exact header to add or empty string","resources":["https://link.com"]}],"summary":"One sentence summary"}`,
  },

  {
    id: "session",
    name: "Session Agent",
    emoji: "🍪",
    description: "Cookies & CSRF protection",
    prompt: (ctx: TargetContext) => `You are a session security expert.

${formatContext(ctx)}

Based on the OBSERVED DATA, check Set-Cookie headers for missing flags: HttpOnly, Secure, SameSite. Check for session IDs in URLs. Check HTML forms for CSRF tokens (hidden input fields). If no cookies are set in the response, note that this is a limited passive view.
${ANALYSIS_RULES}
Respond ONLY in this exact JSON format (no markdown):
{"findings":[{"title":"Short finding name","severity":"critical|high|medium|low|info","description":"Clear explanation grounded in observed data","impact":"What an attacker could do","fix_steps":["Step 1","Step 2","Step 3"],"code_example":"secure cookie setup or empty string","resources":["https://link.com"]}],"summary":"One sentence summary"}`,
  },

  {
    id: "access",
    name: "Access Control Agent",
    emoji: "🚧",
    description: "IDOR & privilege escalation",
    prompt: (ctx: TargetContext) => `You are an access control security expert.

${formatContext(ctx)}

Based on the OBSERVED DATA, check for: predictable ID patterns in URLs/HTML links, admin paths visible in robots.txt or HTML. Most access control testing (IDOR, privilege escalation) requires authenticated active probing — mark those as "info" with "requires deeper testing".
${ANALYSIS_RULES}
Respond ONLY in this exact JSON format (no markdown):
{"findings":[{"title":"Short finding name","severity":"critical|high|medium|low|info","description":"Clear explanation grounded in observed data","impact":"What an attacker could do","fix_steps":["Step 1","Step 2","Step 3"],"code_example":"authorization check code or empty string","resources":["https://link.com"]}],"summary":"One sentence summary"}`,
  },

  {
    id: "files",
    name: "File Agent",
    emoji: "📁",
    description: "File upload & path traversal",
    prompt: (ctx: TargetContext) => `You are a file security expert.

${formatContext(ctx)}

Based on the OBSERVED DATA, check for: file upload forms in HTML, sensitive paths in robots.txt (.env, .git, backup files, config paths), links pointing to obvious sensitive files. Actual .env / .git exposure requires active probing of specific paths.
${ANALYSIS_RULES}
Respond ONLY in this exact JSON format (no markdown):
{"findings":[{"title":"Short finding name","severity":"critical|high|medium|low|info","description":"Clear explanation grounded in observed data","impact":"What an attacker could do","fix_steps":["Step 1","Step 2","Step 3"],"code_example":"nginx rule or code snippet or empty string","resources":["https://link.com"]}],"summary":"One sentence summary"}`,
  },

  {
    id: "logic",
    name: "Logic Agent",
    emoji: "🧠",
    description: "Business logic & race conditions",
    prompt: (ctx: TargetContext) => `You are a business logic security expert.

${formatContext(ctx)}

Business logic flaws (race conditions, workflow bypass, price manipulation) cannot be found from a passive fetch. Look ONLY for very obvious hints in the HTML (e.g. client-side price validation visible in JS, coupon codes hardcoded in HTML). Otherwise report a single "info" finding stating that business logic testing requires deeper active probing.
${ANALYSIS_RULES}
Respond ONLY in this exact JSON format (no markdown):
{"findings":[{"title":"Short finding name","severity":"critical|high|medium|low|info","description":"Clear explanation grounded in observed data","impact":"What an attacker could do","fix_steps":["Step 1","Step 2","Step 3"],"code_example":"secure implementation or empty string","resources":["https://link.com"]}],"summary":"One sentence summary"}`,
  },

  {
    id: "cve",
    name: "CVE Agent",
    emoji: "⚠️",
    description: "Known vulnerabilities & outdated libs",
    prompt: (ctx: TargetContext) => `You are a CVE and dependency expert.

${formatContext(ctx)}

Based on the OBSERVED DATA, identify tech stack from: Server header, X-Powered-By, HTML meta generator, script src paths (e.g. /wp-content/, jquery-x.x.x.min.js, angular version comments). If you can identify a version, mention known CVE classes that historically affect that version. If you cannot identify versions, do not speculate.
${ANALYSIS_RULES}
Respond ONLY in this exact JSON format (no markdown):
{"findings":[{"title":"Short finding name","severity":"critical|high|medium|low|info","description":"Clear explanation grounded in observed data","impact":"What an attacker could do","fix_steps":["Step 1","Step 2","Step 3"],"code_example":"update command or empty string","resources":["https://nvd.nist.gov"]}],"summary":"One sentence summary"}`,
  },

  {
    id: "disclosure",
    name: "Disclosure Agent",
    emoji: "🕵️",
    description: "Information leakage & secrets",
    prompt: (ctx: TargetContext) => `You are an information disclosure expert. This agent can be VERY specific because the HTML and headers are directly observable.

${formatContext(ctx)}

Based on the OBSERVED DATA, scan carefully for: API keys / tokens / secrets in HTML or JS, internal IPs in headers or HTML, stack traces or debug output in the response body, verbose Server / X-Powered-By headers, HTML comments containing sensitive info, .env content, source maps referenced.
${ANALYSIS_RULES}
Respond ONLY in this exact JSON format (no markdown):
{"findings":[{"title":"Short finding name","severity":"critical|high|medium|low|info","description":"Clear explanation grounded in observed data","impact":"What an attacker could do","fix_steps":["Step 1","Step 2","Step 3"],"code_example":"config to disable disclosure or empty string","resources":["https://link.com"]}],"summary":"One sentence summary"}`,
  },
];

// ---------- Cerebras API call with retry ----------
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function callCerebras(prompt: string, attempt = 1): Promise<string> {
  const apiKey = process.env.CEREBRAS_API_KEY;
  if (!apiKey) throw new Error("CEREBRAS_API_KEY not set in .env.local");

  const res = await fetch("https://api.cerebras.ai/v1/chat/completions", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${apiKey}`,
    },
    body: JSON.stringify({
      model: "gpt-oss-120b",
      messages: [{ role: "user", content: prompt }],
      max_tokens: 3000,
      reasoning_effort: "low",
    }),
  });

  // Retry on rate limit: 3s, 6s, 12s, 24s
  if (res.status === 429 && attempt <= 4) {
    const waitMs = 3000 * Math.pow(2, attempt - 1);
    console.log(`  429 rate-limited, waiting ${waitMs}ms then retrying (attempt ${attempt}/4)`);
    await sleep(waitMs);
    return callCerebras(prompt, attempt + 1);
  }

  if (!res.ok) {
    const err = await res.text();
    throw new Error(`Cerebras API error ${res.status}: ${err}`);
  }

  const data = await res.json();
  const msg = data.choices?.[0]?.message;
  return msg?.content || msg?.reasoning || "";
}

// ---------- POST handler ----------
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
      const send = (data: object) => {
        controller.enqueue(encoder.encode(`data: ${JSON.stringify(data)}\n\n`));
      };

      send({ type: "start", total: AGENTS.length });

      // Fetch the target ONCE before running agents
      send({ type: "fetching", url: validUrl });
      const ctx = await fetchTarget(validUrl);
      send({
        type: "fetched",
        status: ctx.status,
        finalUrl: ctx.finalUrl,
        error: ctx.fetchError,
      });

      const runAgent = async (agent: typeof AGENTS[0]) => {
        send({ type: "agent_start", agentId: agent.id, name: agent.name, emoji: agent.emoji });
        try {
          const text = await callCerebras(agent.prompt(ctx));
          let parsed;
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

      // Sequential with 2.5s pacing = ~24 RPM (under Cerebras free tier ~30 RPM).
      for (let i = 0; i < AGENTS.length; i++) {
        await runAgent(AGENTS[i]);
        if (i < AGENTS.length - 1) {
          await sleep(2500);
        }
      }

      send({ type: "done" });
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