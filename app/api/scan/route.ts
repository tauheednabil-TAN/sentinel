import { NextRequest } from "next/server";

const AGENTS = [
  { id: "recon", name: "Recon Agent", emoji: "🔍", description: "Reconnaissance & attack surface",
    prompt: (url: string) => `You are a cybersecurity reconnaissance expert. Analyze the website: ${url}

Check for: subdomain enumeration risks, DNS misconfigurations, WHOIS exposure, tech stack fingerprinting, admin panel exposure (/admin, /wp-admin), robots.txt sensitive paths, open directory listing.

Respond ONLY in this exact JSON format (no markdown, no extra text):
{"findings":[{"title":"Short finding name","severity":"critical|high|medium|low|info","description":"Clear explanation","impact":"What attacker could do","fix_steps":["Step 1","Step 2","Step 3"],"code_example":"config snippet or empty string","resources":["https://link.com"]}],"summary":"One sentence summary"}` },

  { id: "injection", name: "Injection Agent", emoji: "💉", description: "SQL injection, XSS, SSTI",
    prompt: (url: string) => `You are an injection vulnerability expert. Analyze: ${url}

Check for: SQL Injection, XSS (reflected/stored/DOM), SSTI, command injection, XXE, NoSQL injection.

Respond ONLY in this exact JSON format (no markdown, no extra text):
{"findings":[{"title":"Short finding name","severity":"critical|high|medium|low|info","description":"Clear explanation","impact":"What attacker could do","fix_steps":["Step 1","Step 2","Step 3"],"code_example":"secure code snippet or empty string","resources":["https://owasp.org"]}],"summary":"One sentence summary"}` },

  { id: "auth", name: "Auth Agent", emoji: "🔐", description: "Authentication & session security",
    prompt: (url: string) => `You are an authentication security expert. Analyze: ${url}

Check for: default credentials, brute force protection, weak passwords, MFA absence, OAuth misconfigs, JWT weaknesses, insecure password reset, username enumeration.

Respond ONLY in this exact JSON format (no markdown, no extra text):
{"findings":[{"title":"Short finding name","severity":"critical|high|medium|low|info","description":"Clear explanation","impact":"What attacker could do","fix_steps":["Step 1","Step 2","Step 3"],"code_example":"secure implementation or empty string","resources":["https://owasp.org"]}],"summary":"One sentence summary"}` },

  { id: "api", name: "API Agent", emoji: "⚡", description: "API & endpoint security",
    prompt: (url: string) => `You are an API security expert. Analyze: ${url}

Check for: unauthenticated endpoints, missing rate limiting, API key exposure in JS, GraphQL introspection, mass assignment, BOLA/IDOR, Swagger docs exposed.

Respond ONLY in this exact JSON format (no markdown, no extra text):
{"findings":[{"title":"Short finding name","severity":"critical|high|medium|low|info","description":"Clear explanation","impact":"What attacker could do","fix_steps":["Step 1","Step 2","Step 3"],"code_example":"secure code or empty string","resources":["https://owasp.org"]}],"summary":"One sentence summary"}` },

  { id: "ssl", name: "SSL/TLS Agent", emoji: "🔒", description: "Certificate & encryption",
    prompt: (url: string) => `You are an SSL/TLS security expert. Analyze: ${url}

Check for: cert validity/expiry, weak ciphers (RC4/DES/3DES), old protocols (SSLv2/3, TLS 1.0/1.1), missing HSTS, mixed content, missing HTTP to HTTPS redirect.

Respond ONLY in this exact JSON format (no markdown, no extra text):
{"findings":[{"title":"Short finding name","severity":"critical|high|medium|low|info","description":"Clear explanation","impact":"What attacker could do","fix_steps":["Step 1","Step 2","Step 3"],"code_example":"nginx/apache config or empty string","resources":["https://link.com"]}],"summary":"One sentence summary"}` },

  { id: "headers", name: "Headers Agent", emoji: "🛡", description: "Security headers & CSP",
    prompt: (url: string) => `You are a security headers expert. Analyze: ${url}

Check for missing/weak: Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, CORS misconfiguration, server version disclosure.

Respond ONLY in this exact JSON format (no markdown, no extra text):
{"findings":[{"title":"Short finding name","severity":"critical|high|medium|low|info","description":"Clear explanation","impact":"What attacker could do","fix_steps":["Step 1","Step 2","Step 3"],"code_example":"exact header to add or empty string","resources":["https://link.com"]}],"summary":"One sentence summary"}` },

  { id: "session", name: "Session Agent", emoji: "🍪", description: "Cookies & CSRF protection",
    prompt: (url: string) => `You are a session security expert. Analyze: ${url}

Check for: missing cookie flags (HttpOnly/Secure/SameSite), session fixation, CSRF token absence, session timeout issues, session ID in URL, predictable session IDs.

Respond ONLY in this exact JSON format (no markdown, no extra text):
{"findings":[{"title":"Short finding name","severity":"critical|high|medium|low|info","description":"Clear explanation","impact":"What attacker could do","fix_steps":["Step 1","Step 2","Step 3"],"code_example":"secure cookie setup or empty string","resources":["https://link.com"]}],"summary":"One sentence summary"}` },

  { id: "access", name: "Access Control Agent", emoji: "🚧", description: "IDOR & privilege escalation",
    prompt: (url: string) => `You are an access control security expert. Analyze: ${url}

Check for: IDOR, horizontal/vertical privilege escalation, forced browsing, missing function-level access control, directory traversal, JWT claims manipulation.

Respond ONLY in this exact JSON format (no markdown, no extra text):
{"findings":[{"title":"Short finding name","severity":"critical|high|medium|low|info","description":"Clear explanation","impact":"What attacker could do","fix_steps":["Step 1","Step 2","Step 3"],"code_example":"authorization check code or empty string","resources":["https://link.com"]}],"summary":"One sentence summary"}` },

  { id: "files", name: "File Agent", emoji: "📁", description: "File upload & path traversal",
    prompt: (url: string) => `You are a file security expert. Analyze: ${url}

Check for: unrestricted file upload, path traversal, exposed .env/config files, .git folder exposure, log file exposure, LFI/RFI vulnerabilities, backup files (.bak/.old).

Respond ONLY in this exact JSON format (no markdown, no extra text):
{"findings":[{"title":"Short finding name","severity":"critical|high|medium|low|info","description":"Clear explanation","impact":"What attacker could do","fix_steps":["Step 1","Step 2","Step 3"],"code_example":"nginx rule or code snippet or empty string","resources":["https://link.com"]}],"summary":"One sentence summary"}` },

  { id: "logic", name: "Logic Agent", emoji: "🧠", description: "Business logic & race conditions",
    prompt: (url: string) => `You are a business logic security expert. Analyze: ${url}

Check for: price manipulation, race conditions, workflow bypass, coupon abuse, insecure password reset, integer overflow in amounts, TOCTOU issues.

Respond ONLY in this exact JSON format (no markdown, no extra text):
{"findings":[{"title":"Short finding name","severity":"critical|high|medium|low|info","description":"Clear explanation","impact":"What attacker could do","fix_steps":["Step 1","Step 2","Step 3"],"code_example":"secure implementation or empty string","resources":["https://link.com"]}],"summary":"One sentence summary"}` },

  { id: "cve", name: "CVE Agent", emoji: "⚠️", description: "Known vulnerabilities & outdated libs",
    prompt: (url: string) => `You are a CVE and dependency expert. Analyze: ${url}

Check for: outdated CMS (WordPress/Drupal/Joomla), old JS frameworks (jQuery/Angular/React), outdated server software, vulnerable plugins, known exploitable misconfigs.

Respond ONLY in this exact JSON format (no markdown, no extra text):
{"findings":[{"title":"Short finding name","severity":"critical|high|medium|low|info","description":"Clear explanation","impact":"What attacker could do","fix_steps":["Step 1","Step 2","Step 3"],"code_example":"update command or empty string","resources":["https://nvd.nist.gov"]}],"summary":"One sentence summary"}` },

  { id: "disclosure", name: "Disclosure Agent", emoji: "🕵️", description: "Information leakage & secrets",
    prompt: (url: string) => `You are an information disclosure expert. Analyze: ${url}

Check for: API keys in client-side JS, internal IPs in responses, stack traces in errors, .env files accessible, debug mode enabled, HTML comments with sensitive info.

Respond ONLY in this exact JSON format (no markdown, no extra text):
{"findings":[{"title":"Short finding name","severity":"critical|high|medium|low|info","description":"Clear explanation","impact":"What attacker could do","fix_steps":["Step 1","Step 2","Step 3"],"code_example":"config to disable disclosure or empty string","resources":["https://link.com"]}],"summary":"One sentence summary"}` },
];

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

  // Retry on rate limit with exponential backoff (max 4 attempts: 3s, 6s, 12s, 24s waits)
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

export async function POST(req: NextRequest) {
  const { url } = await req.json();
  if (!url) return new Response(JSON.stringify({ error: "URL is required" }), { status: 400 });

  const encoder = new TextEncoder();
  const stream = new ReadableStream({
    async start(controller) {
      const send = (data: object) => {
        controller.enqueue(encoder.encode(`data: ${JSON.stringify(data)}\n\n`));
      };

      send({ type: "start", total: AGENTS.length });

      const runAgent = async (agent: typeof AGENTS[0]) => {
        send({ type: "agent_start", agentId: agent.id, name: agent.name, emoji: agent.emoji });
        try {
          const text = await callCerebras(agent.prompt(url));
          let parsed;
          try {
            const clean = text.replace(/```json\n?/g, "").replace(/```\n?/g, "").trim();
            const jsonMatch = clean.match(/\{[\s\S]*\}/);
            parsed = JSON.parse(jsonMatch ? jsonMatch[0] : clean);
          } catch {
            parsed = { findings: [{ title: "Analysis completed", severity: "info", description: text.slice(0, 300), impact: "Review manually", fix_steps: ["Manual review needed"], code_example: "", resources: [] }], summary: "Agent completed" };
          }
          send({ type: "agent_done", agentId: agent.id, name: agent.name, emoji: agent.emoji, description: agent.description, findings: parsed.findings || [], summary: parsed.summary || "" });
        } catch (err) {
          console.error(`[${agent.id}]`, err);
          send({ type: "agent_error", agentId: agent.id, name: agent.name, emoji: agent.emoji, error: err instanceof Error ? err.message : "Unknown error" });
        }
      };

      // Sequential with 2.5s pacing = ~24 RPM, comfortably under Cerebras free tier's 30 RPM.
      // Total scan time: ~30-40s. Trade-off: reliable > fast for free-tier demo.
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
    headers: { "Content-Type": "text/event-stream", "Cache-Control": "no-cache", Connection: "keep-alive" },
  });
}