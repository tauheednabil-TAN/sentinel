"use client";
import { useState, useRef } from "react";

type Severity = "critical" | "high" | "medium" | "low" | "info";

interface Finding {
  title: string;
  severity: Severity;
  description: string;
  impact: string;
  fix_steps: string[];
  code_example: string;
  resources: string[];
}

interface AgentResult {
  agentId: string;
  name: string;
  emoji: string;
  description: string;
  findings: Finding[];
  summary: string;
  status: "waiting" | "running" | "done" | "error";
  error?: string;
}

const SEV: Record<Severity, { label: string; color: string; bg: string; border: string; dot: string }> = {
  critical: { label: "Critical", color: "#fca5a5", bg: "rgba(220,38,38,0.08)", border: "rgba(220,38,38,0.35)", dot: "#dc2626" },
  high:     { label: "High",     color: "#fdba74", bg: "rgba(234,88,12,0.08)",  border: "rgba(234,88,12,0.35)",  dot: "#ea580c" },
  medium:   { label: "Medium",   color: "#fde047", bg: "rgba(202,138,4,0.08)",  border: "rgba(202,138,4,0.35)",  dot: "#ca8a04" },
  low:      { label: "Low",      color: "#86efac", bg: "rgba(22,163,74,0.08)",  border: "rgba(22,163,74,0.35)",  dot: "#16a34a" },
  info:     { label: "Info",     color: "#93c5fd", bg: "rgba(37,99,235,0.08)",  border: "rgba(37,99,235,0.35)",  dot: "#2563eb" },
};


const AGENT_LIST = [
  { id: "recon",      name: "Recon",      emoji: "🔍", tooltip: "Finds hidden pages, admin panels, subdomains and tech stack info that attackers use to map your site before attacking." },
  { id: "injection",  name: "Injection",  emoji: "💉", tooltip: "Tests if attackers can inject malicious code into your search bars, login forms or URLs to steal data or take over your database." },
  { id: "auth",       name: "Auth",       emoji: "🔐", tooltip: "Checks if your login system can be bypassed — weak passwords, no rate limiting, missing 2FA, or broken password reset flows." },
  { id: "api",        name: "API",        emoji: "⚡", tooltip: "Looks for exposed API endpoints that don't require login, leak sensitive data, or have no rate limiting — common in modern web apps." },
  { id: "ssl",        name: "SSL/TLS",    emoji: "🔒", tooltip: "Verifies your HTTPS is properly configured — no expired certs, weak encryption, or missing security that protects data in transit." },
  { id: "headers",    name: "Headers",    emoji: "🛡", tooltip: "Checks security headers your server sends — missing ones allow attackers to hijack pages, steal clicks, or run malicious scripts." },
  { id: "session",    name: "Session",    emoji: "🍪", tooltip: "Examines how your site handles login cookies and sessions — bad settings let attackers steal sessions and log in as your users." },
  { id: "access",     name: "Access",     emoji: "🚧", tooltip: "Tests if users can access other people's data by changing an ID in the URL — one of the most common and damaging vulnerabilities." },
  { id: "files",      name: "Files",      emoji: "📁", tooltip: "Checks for exposed config files (.env, .git), backup files, or file upload features that could let attackers read your source code or upload malware." },
  { id: "logic",      name: "Logic",      emoji: "🧠", tooltip: "Looks for business logic flaws — like buying items for free, skipping payment steps, or exploiting race conditions to duplicate credits." },
  { id: "cve",        name: "CVE",        emoji: "⚠️", tooltip: "Detects outdated software versions with known public vulnerabilities — like an old WordPress plugin or jQuery version hackers can exploit." },
  { id: "disclosure", name: "Disclosure", emoji: "🕵️", tooltip: "Hunts for accidentally exposed secrets — API keys in JavaScript, database passwords in error messages, or server info in response headers." },
];

function FindingCard({ f }: { f: Finding & { agentName?: string; agentEmoji?: string } }) {
  const [open, setOpen] = useState(false);
  const s = SEV[f.severity] || SEV.info;
  return (
    <div style={{ background: s.bg, border: `1px solid ${s.border}`, borderRadius: 12, overflow: "hidden", marginBottom: 10 }}>
      <div onClick={() => setOpen(!open)} style={{ padding: "16px 20px", cursor: "pointer", display: "flex", alignItems: "center", gap: 12, flexWrap: "wrap" }}>
        <span style={{ width: 10, height: 10, borderRadius: "50%", background: s.dot, flexShrink: 0 }} />
        <span style={{ fontWeight: 600, fontSize: 15, color: "#e2e8f0", flex: 1 }}>{f.title}</span>
        <span style={{ fontSize: 11, fontWeight: 700, color: s.dot, padding: "2px 8px", border: `1px solid ${s.border}`, borderRadius: 4, textTransform: "uppercase" as const, letterSpacing: "0.05em" }}>{s.label}</span>
        {f.agentName && <span style={{ fontSize: 12, color: "#475569" }}>{f.agentEmoji} {f.agentName}</span>}
        <span style={{ fontSize: 16, color: "#475569" }}>{open ? "▲" : "▼"}</span>
      </div>
      {open && (
        <div style={{ borderTop: `1px solid ${s.border}`, padding: 20 }}>
          <div style={{ marginBottom: 16 }}>
            <div style={{ fontSize: 11, fontWeight: 700, color: s.color, textTransform: "uppercase" as const, letterSpacing: "0.08em", marginBottom: 8 }}>What was found</div>
            <p style={{ fontSize: 14, color: "#94a3b8", margin: 0, lineHeight: 1.7 }}>{f.description}</p>
          </div>
          {f.impact && (
            <div style={{ marginBottom: 16, padding: "12px 16px", background: "rgba(220,38,38,0.08)", border: "1px solid rgba(220,38,38,0.2)", borderRadius: 8 }}>
              <div style={{ fontSize: 11, fontWeight: 700, color: "#fca5a5", textTransform: "uppercase" as const, letterSpacing: "0.08em", marginBottom: 6 }}>⚠ Attacker impact</div>
              <p style={{ fontSize: 14, color: "#fca5a5", margin: 0, lineHeight: 1.6, opacity: 0.9 }}>{f.impact}</p>
            </div>
          )}
          {f.fix_steps && f.fix_steps.length > 0 && (
            <div style={{ marginBottom: 16 }}>
              <div style={{ fontSize: 11, fontWeight: 700, color: "#86efac", textTransform: "uppercase" as const, letterSpacing: "0.08em", marginBottom: 12 }}>✅ How to fix it</div>
              {f.fix_steps.map((step, i) => (
                <div key={i} style={{ display: "flex", gap: 12, alignItems: "flex-start", marginBottom: 10 }}>
                  <span style={{ width: 24, height: 24, background: "rgba(22,163,74,0.2)", border: "1px solid rgba(22,163,74,0.4)", borderRadius: "50%", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 12, fontWeight: 700, color: "#86efac", flexShrink: 0 }}>{i + 1}</span>
                  <span style={{ fontSize: 14, color: "#cbd5e1", lineHeight: 1.6, paddingTop: 2 }}>{step}</span>
                </div>
              ))}
            </div>
          )}
          {f.code_example && f.code_example.trim() && (
            <div style={{ marginBottom: 16 }}>
              <div style={{ fontSize: 11, fontWeight: 700, color: "#818cf8", textTransform: "uppercase" as const, letterSpacing: "0.08em", marginBottom: 8 }}>{"</>"} Code / config example</div>
              <pre style={{ background: "#0d0d18", border: "1px solid #1e293b", borderRadius: 8, padding: "14px 16px", margin: 0, fontSize: 13, color: "#a5b4fc", overflowX: "auto", lineHeight: 1.6, whiteSpace: "pre-wrap", wordBreak: "break-all" as const }}>{f.code_example}</pre>
            </div>
          )}
          {f.resources && f.resources.length > 0 && (
            <div>
              <div style={{ fontSize: 11, fontWeight: 700, color: "#64748b", textTransform: "uppercase" as const, letterSpacing: "0.08em", marginBottom: 8 }}>📚 Learn more</div>
              {f.resources.map((r, i) => (
                <a key={i} href={r} target="_blank" rel="noopener noreferrer" style={{ display: "block", fontSize: 13, color: "#818cf8", textDecoration: "none", marginBottom: 4 }}>→ {r}</a>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function CyberBg() {
  return (
    <div className="cyber-bg">
      {/* Radial glow */}
      <div className="glow glow-1" />
      <div className="glow glow-2" />

      {/* Animated SVG circuits */}
      <svg className="circuits" viewBox="0 0 1920 1080" preserveAspectRatio="xMidYMid slice" xmlns="http://www.w3.org/2000/svg">
        <defs>
          <radialGradient id="rg" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor="#3b82f6" stopOpacity="0.6"/>
            <stop offset="100%" stopColor="#3b82f6" stopOpacity="0"/>
          </radialGradient>
          <linearGradient id="lg" x1="0" x2="1" y1="0" y2="0">
            <stop offset="0%" stopColor="#3b82f6" stopOpacity="0"/>
            <stop offset="50%" stopColor="#60a5fa" stopOpacity="0.8"/>
            <stop offset="100%" stopColor="#3b82f6" stopOpacity="0"/>
          </linearGradient>
        </defs>

        {/* Hexagon grid (static, low opacity) */}
        <g stroke="#1e3a8a" strokeWidth="0.5" fill="none" opacity="0.25">
          {Array.from({ length: 12 }).map((_, row) =>
            Array.from({ length: 16 }).map((__, col) => {
              const x = col * 130 + (row % 2 ? 65 : 0);
              const y = row * 110;
              return (
                <polygon
                  key={`${row}-${col}`}
                  points={`${x},${y+25} ${x+38},${y} ${x+76},${y+25} ${x+76},${y+75} ${x+38},${y+100} ${x},${y+75}`}
                />
              );
            })
          ).flat()}
        </g>

        {/* Concentric rings (rotating slowly) */}
        <g className="ring-group" transform="translate(960 540)">
          <circle r="200" stroke="#2563eb" strokeWidth="0.8" fill="none" opacity="0.4" strokeDasharray="4 8" />
          <circle r="320" stroke="#3b82f6" strokeWidth="0.6" fill="none" opacity="0.3" strokeDasharray="2 12" />
          <circle r="450" stroke="#60a5fa" strokeWidth="0.5" fill="none" opacity="0.2" strokeDasharray="1 16" />
          <circle r="580" stroke="#3b82f6" strokeWidth="0.4" fill="none" opacity="0.15" strokeDasharray="1 20" />
        </g>

        {/* Reverse-rotating ring */}
        <g className="ring-reverse" transform="translate(960 540)">
          <circle r="260" stroke="#1d4ed8" strokeWidth="0.6" fill="none" opacity="0.3" strokeDasharray="10 30" />
          <circle r="380" stroke="#1d4ed8" strokeWidth="0.5" fill="none" opacity="0.25" strokeDasharray="6 40" />
        </g>

        {/* Center shield glow */}
        <circle cx="960" cy="540" r="80" fill="url(#rg)" opacity="0.6">
          <animate attributeName="r" values="80;100;80" dur="4s" repeatCount="indefinite" />
          <animate attributeName="opacity" values="0.4;0.8;0.4" dur="4s" repeatCount="indefinite" />
        </circle>

        {/* Glowing nodes scattered */}
        <g fill="#60a5fa">
          {[[180,200],[1740,150],[300,800],[1600,900],[960,120],[960,960],[450,500],[1470,500]].map((p, i) => (
            <circle key={i} cx={p[0]} cy={p[1]} r="2">
              <animate attributeName="opacity" values="0.2;1;0.2" dur={`${2 + i * 0.4}s`} repeatCount="indefinite" begin={`${i * 0.3}s`} />
            </circle>
          ))}
        </g>

        {/* Horizontal scanning beam */}
        <rect className="scan-beam" x="0" y="0" width="1920" height="2" fill="url(#lg)" />

        {/* Vertical data lines */}
        <g stroke="#3b82f6" strokeWidth="0.5" opacity="0.4">
          <line x1="200" y1="0" x2="200" y2="1080" strokeDasharray="2 8" />
          <line x1="1720" y1="0" x2="1720" y2="1080" strokeDasharray="2 8" />
        </g>
      </svg>

      {/* Floating binary code particles */}
      <div className="particles">
        {Array.from({ length: 20 }).map((_, i) => (
          <span key={i} className="particle" style={{ left: `${(i * 5.3) % 100}%`, animationDelay: `${i * 0.7}s`, animationDuration: `${15 + (i % 5) * 3}s` }}>
            {i % 2 === 0 ? "01" : "10"}
          </span>
        ))}
      </div>
    </div>
  );
}

export default function Home() {
  const [url, setUrl] = useState("");
  const [scanning, setScanning] = useState(false);
  const [agents, setAgents] = useState<Record<string, AgentResult>>({});
  const [done, setDone] = useState(false);
  const [activeTab, setActiveTab] = useState<"all" | Severity>("all");
  const [error, setError] = useState<string | null>(null);
  const abortRef = useRef<AbortController | null>(null);

  const totalFindings = Object.values(agents).reduce((acc, a) => acc + (a.findings?.length || 0), 0);
  const doneCount = Object.values(agents).filter(a => a.status === "done" || a.status === "error").length;
  const runningCount = Object.values(agents).filter(a => a.status === "running").length;

  const allFindings = Object.values(agents)
    .flatMap(a => (a.findings || []).map(f => ({ ...f, agentName: a.name, agentEmoji: a.emoji })))
    .sort((a, b) => ["critical","high","medium","low","info"].indexOf(a.severity) - ["critical","high","medium","low","info"].indexOf(b.severity));

  const filteredFindings = activeTab === "all" ? allFindings : allFindings.filter(f => f.severity === activeTab);
  const countBySev = (s: Severity) => allFindings.filter(f => f.severity === s).length;

  const startScan = async () => {
    if (!url.trim()) return;
    let scanUrl = url.trim();
    if (!scanUrl.startsWith("http")) scanUrl = "https://" + scanUrl;

    // Show all 12 agents immediately in waiting state
    const initialAgents: Record<string, AgentResult> = {};
    AGENT_LIST.forEach(a => {
      initialAgents[a.id] = { agentId: a.id, name: a.name, emoji: a.emoji, description: "", findings: [], summary: "", status: "waiting" };
    });
    setScanning(true);
    setDone(false);
    setAgents(initialAgents);
    setActiveTab("all");
    setError(null);

    abortRef.current = new AbortController();
    try {
      const res = await fetch("/api/scan", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ url: scanUrl }), signal: abortRef.current.signal });

      // Backend rejected the request (e.g. invalid URL)
      if (!res.ok) {
        const errData = await res.json().catch(() => ({ error: "Something went wrong" }));
        setError(errData.error || `Request failed (${res.status})`);
        setScanning(false);
        setAgents({});
        return;
      }

      const reader = res.body!.getReader();
      const decoder = new TextDecoder();
      let buffer = "";
      while (true) {
        const { done: sd, value } = await reader.read();
        if (sd) break;
        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split("\n");
        buffer = lines.pop() || "";
        for (const line of lines) {
          if (!line.startsWith("data: ")) continue;
          try {
            const ev = JSON.parse(line.slice(6));
            if (ev.type === "agent_start") {
              setAgents(p => ({ ...p, [ev.agentId]: { ...p[ev.agentId], status: "running" } }));
            } else if (ev.type === "agent_done") {
              setAgents(p => ({ ...p, [ev.agentId]: { agentId: ev.agentId, name: ev.name, emoji: ev.emoji, description: ev.description, findings: ev.findings, summary: ev.summary, status: "done" } }));
            } else if (ev.type === "agent_error") {
              setAgents(p => ({ ...p, [ev.agentId]: { ...p[ev.agentId], status: "error", error: ev.error } }));
            } else if (ev.type === "done") {
              setDone(true);
              setScanning(false);
            }
          } catch { /* skip */ }
        }
      }
    } catch (err: unknown) {
      if (err instanceof Error && err.name !== "AbortError") console.error(err);
      setScanning(false);
    }
  };

  const stopScan = () => { abortRef.current?.abort(); setScanning(false); };

  const showAgents = scanning || done;

  return (
    <main style={{ minHeight: "100vh", background: "#050510", color: "#e2e8f0", fontFamily: "-apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif", position: "relative", overflow: "hidden" }}>
      <CyberBg />
      <style>{`
        .cyber-bg { position: fixed; inset: 0; z-index: 0; overflow: hidden; pointer-events: none; }
        .cyber-bg .circuits { position: absolute; inset: 0; width: 100%; height: 100%; }
        .cyber-bg .glow { position: absolute; border-radius: 50%; filter: blur(100px); opacity: 0.4; }
        .cyber-bg .glow-1 { width: 600px; height: 600px; background: radial-gradient(circle, #1d4ed8 0%, transparent 70%); top: -200px; left: -200px; animation: float-glow 20s ease-in-out infinite; }
        .cyber-bg .glow-2 { width: 700px; height: 700px; background: radial-gradient(circle, #4f46e5 0%, transparent 70%); bottom: -250px; right: -250px; animation: float-glow 25s ease-in-out infinite reverse; }
        @keyframes float-glow {
          0%, 100% { transform: translate(0,0); }
          50% { transform: translate(100px, -50px); }
        }
        .ring-group { animation: rotate-slow 80s linear infinite; transform-origin: 960px 540px; }
        .ring-reverse { animation: rotate-slow 60s linear infinite reverse; transform-origin: 960px 540px; }
        @keyframes rotate-slow { to { transform: rotate(360deg) translate(960px, 540px) translate(-960px, -540px); } }
        .ring-group, .ring-reverse { transform-box: fill-box; transform-origin: center; }
        .scan-beam { animation: scan 8s linear infinite; }
        @keyframes scan {
          0% { transform: translateY(0); opacity: 0; }
          5% { opacity: 1; }
          95% { opacity: 1; }
          100% { transform: translateY(1080px); opacity: 0; }
        }
        .particles { position: absolute; inset: 0; pointer-events: none; }
        .particle { position: absolute; top: -30px; color: #60a5fa; font-family: monospace; font-size: 11px; opacity: 0.4; animation: fall linear infinite; }
        @keyframes fall {
          0% { transform: translateY(-30px); opacity: 0; }
          10% { opacity: 0.5; }
          90% { opacity: 0.5; }
          100% { transform: translateY(100vh); opacity: 0; }
        }
        .content-wrap { position: relative; z-index: 1; }

        @keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: 0.3; } }
        .agent-running { animation: pulse 1.4s ease-in-out infinite; }
        .tooltip-wrap { position: relative; display: inline-flex; }
        .tooltip-wrap .tip { display: none; position: absolute; bottom: calc(100% + 8px); right: 0; background: #1e293b; border: 1px solid #334155; color: #cbd5e1; font-size: 12px; line-height: 1.5; padding: 8px 12px; border-radius: 8px; width: 200px; z-index: 99; white-space: normal; box-shadow: 0 4px 16px rgba(0,0,0,0.4); }
        .tooltip-wrap .tip::after { content: ""; position: absolute; top: 100%; right: 10px; border: 6px solid transparent; border-top-color: #334155; }
        .tooltip-wrap:hover .tip { display: block; }
        .q-btn { width: 16px; height: 16px; border-radius: 50%; background: #1e293b; border: 1px solid #334155; color: #64748b; font-size: 10px; font-weight: 700; cursor: default; display: flex; align-items: center; justify-content: center; flex-shrink: 0; }
        .q-btn:hover { background: #6366f1; border-color: #6366f1; color: white; }
      `}</style>

      {/* Header */}
      <div className="content-wrap" style={{ borderBottom: "1px solid rgba(59,130,246,0.2)", padding: "18px 32px", display: "flex", alignItems: "center", gap: 12, background: "rgba(13, 13, 24, 0.6)", backdropFilter: "blur(12px)", WebkitBackdropFilter: "blur(12px)" }}>
        <div style={{ width: 36, height: 36, background: "linear-gradient(135deg, #6366f1, #8b5cf6)", borderRadius: 8, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 18 }}>🛡</div>
        <div>
          <div style={{ fontWeight: 700, fontSize: 18, letterSpacing: "-0.3px" }}>Sentinel</div>
          <div style={{ fontSize: 12, color: "#64748b" }}>AI security scanner — 12 agents in parallel</div>
        </div>
      </div>

      <div className="content-wrap" style={{ maxWidth: 900, margin: "0 auto", padding: "40px 24px", position: "relative", zIndex: 1 }}>

        {/* Hero — only when idle */}
        {!showAgents && (
          <div style={{ textAlign: "center", marginBottom: 48 }}>
            <div style={{ display: "inline-block", background: "rgba(99,102,241,0.1)", border: "1px solid rgba(99,102,241,0.3)", borderRadius: 20, padding: "4px 14px", fontSize: 12, color: "#818cf8", marginBottom: 20, letterSpacing: "0.05em" }}>
              12 AI AGENTS · PARALLEL SCANNING · STEP-BY-STEP FIXES
            </div>
            <h1 style={{ fontSize: 44, fontWeight: 800, letterSpacing: "-1.5px", margin: "0 0 16px", background: "linear-gradient(135deg, #e2e8f0 0%, #94a3b8 100%)", WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent", lineHeight: 1.1 }}>
              Find & fix every vulnerability<br />before attackers do
            </h1>
            <p style={{ color: "#64748b", fontSize: 17, maxWidth: 500, margin: "0 auto", lineHeight: 1.6 }}>
              Paste any URL. Get a full security report with step-by-step fix instructions, code examples, and resources — instantly.
            </p>
          </div>
        )}

        {/* URL Input */}
        <div style={{ display: "flex", gap: 12, maxWidth: 680, margin: "0 auto 32px" }}>
          <input type="text" value={url} onChange={e => setUrl(e.target.value)}
            onKeyDown={e => e.key === "Enter" && !scanning && startScan()}
            placeholder="https://example.com" disabled={scanning}
            style={{ flex: 1, padding: "14px 18px", background: "rgba(17, 24, 39, 0.7)", border: "1px solid rgba(59,130,246,0.3)", borderRadius: 10, color: "#e2e8f0", fontSize: 16, outline: "none", backdropFilter: "blur(10px)", WebkitBackdropFilter: "blur(10px)" }} />
          <button onClick={scanning ? stopScan : startScan}
            style={{ padding: "14px 28px", background: scanning ? "#1e293b" : "linear-gradient(135deg, #6366f1, #8b5cf6)", border: "none", borderRadius: 10, color: scanning ? "#94a3b8" : "white", fontSize: 15, fontWeight: 600, cursor: "pointer", whiteSpace: "nowrap" }}>
            {scanning ? "⏹ Stop" : "Scan now"}
          </button>
        </div>

        {/* Error banner */}
        {error && (
          <div style={{ maxWidth: 680, margin: "0 auto 24px", padding: "12px 18px", background: "rgba(220,38,38,0.1)", border: "1px solid rgba(220,38,38,0.3)", borderRadius: 10, color: "#fca5a5", fontSize: 14, display: "flex", alignItems: "center", gap: 10 }}>
            <span style={{ fontSize: 18 }}>⚠</span>
            <span style={{ flex: 1 }}>{error}</span>
            <button onClick={() => setError(null)} style={{ background: "transparent", border: "none", color: "#fca5a5", cursor: "pointer", fontSize: 18, padding: 0, lineHeight: 1 }}>×</button>
          </div>
        )}

        {/* Progress bar */}
        {scanning && (
          <div style={{ maxWidth: 680, margin: "0 auto 32px" }}>
            <div style={{ display: "flex", justifyContent: "space-between", fontSize: 13, color: "#64748b", marginBottom: 8 }}>
              <span>
                {runningCount > 0 && <span style={{ color: "#818cf8" }}>⟳ {runningCount} scanning · </span>}
                {doneCount} / {AGENT_LIST.length} done
              </span>
              <span style={{ color: totalFindings > 0 ? "#fbbf24" : "#64748b" }}>{totalFindings} findings so far</span>
            </div>
            <div style={{ height: 6, background: "#1e293b", borderRadius: 3, overflow: "hidden" }}>
              <div style={{ height: "100%", width: `${(doneCount / AGENT_LIST.length) * 100}%`, background: "linear-gradient(90deg, #6366f1, #8b5cf6)", borderRadius: 3, transition: "width 0.5s ease" }} />
            </div>
          </div>
        )}

        {/* Agent grid — shows immediately when scan starts */}
        {showAgents && (
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(140px, 1fr))", gap: 10, marginBottom: 36 }}>
            {AGENT_LIST.map(a => {
              const r = agents[a.id];
              const status = r?.status || "waiting";
              const count = r?.findings?.length || 0;
              const hasCrit = r?.findings?.some(f => f.severity === "critical");
              const hasHigh = r?.findings?.some(f => f.severity === "high");

              const borderColor =
                hasCrit ? "#dc2626" :
                hasHigh ? "#ea580c" :
                status === "done" ? "#22c55e" :
                status === "running" ? "#6366f1" :
                "#1e293b";

              const bgColor =
                status === "running" ? "rgba(99,102,241,0.15)" :
                status === "done" && hasCrit ? "rgba(220,38,38,0.15)" :
                status === "done" && hasHigh ? "rgba(234,88,12,0.15)" :
                "rgba(17, 24, 39, 0.6)";

              return (
                <div key={a.id} style={{ background: bgColor, border: `1px solid ${borderColor}`, borderRadius: 10, padding: "12px 14px", transition: "all 0.3s", backdropFilter: "blur(10px)", WebkitBackdropFilter: "blur(10px)", boxShadow: status === "running" ? "0 0 20px rgba(99,102,241,0.3)" : "none" }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 7, marginBottom: 6 }}>
                    <span style={{ fontSize: 18 }}>{a.emoji}</span>
                    <span style={{ fontSize: 12, fontWeight: 600, color: "#cbd5e1", flex: 1 }}>{a.name}</span>
                    <span className="tooltip-wrap">
                      <span className="q-btn">?</span>
                      <span className="tip">{a.tooltip}</span>
                    </span>
                  </div>
                  <div style={{ fontSize: 11, color: status === "running" ? "#818cf8" : status === "done" ? "#94a3b8" : "#334155", display: "flex", alignItems: "center", gap: 5 }}>
                    {status === "waiting" && <span>⏳ Queued</span>}
                    {status === "running" && (
                      <>
                        <span className="agent-running" style={{ width: 6, height: 6, borderRadius: "50%", background: "#6366f1", display: "inline-block" }} />
                        <span>Scanning...</span>
                      </>
                    )}
                    {status === "done" && (
                      <span style={{ color: hasCrit ? "#fca5a5" : hasHigh ? "#fdba74" : "#22c55e" }}>
                        ✓ {count} finding{count !== 1 ? "s" : ""}
                      </span>
                    )}
                    {status === "error" && <span style={{ color: "#f87171" }}>❌ Error</span>}
                  </div>
                </div>
              );
            })}
          </div>
        )}

        {/* Summary bar */}
        {done && totalFindings > 0 && (
          <div style={{ background: "rgba(17, 24, 39, 0.7)", border: "1px solid rgba(59,130,246,0.2)", borderRadius: 12, padding: "18px 24px", marginBottom: 28, display: "flex", gap: 28, alignItems: "center", flexWrap: "wrap", backdropFilter: "blur(10px)", WebkitBackdropFilter: "blur(10px)" }}>
            <div>
              <div style={{ fontSize: 26, fontWeight: 800, color: "#e2e8f0" }}>{totalFindings}</div>
              <div style={{ fontSize: 12, color: "#64748b" }}>Total findings</div>
            </div>
            {(["critical","high","medium","low","info"] as Severity[]).map(s => {
              const c = countBySev(s);
              if (!c) return null;
              return (
                <div key={s}>
                  <div style={{ fontSize: 22, fontWeight: 700, color: SEV[s].dot }}>{c}</div>
                  <div style={{ fontSize: 12, color: "#64748b" }}>{SEV[s].label}</div>
                </div>
              );
            })}
          </div>
        )}

        {/* Filter tabs */}
        {done && totalFindings > 0 && (
          <div style={{ display: "flex", gap: 8, marginBottom: 20, flexWrap: "wrap" }}>
            {(["all","critical","high","medium","low","info"] as const).map(tab => {
              const count = tab === "all" ? totalFindings : countBySev(tab as Severity);
              if (tab !== "all" && !count) return null;
              const active = activeTab === tab;
              const dot = tab === "all" ? "#94a3b8" : SEV[tab as Severity].dot;
              return (
                <button key={tab} onClick={() => setActiveTab(tab)}
                  style={{ padding: "6px 14px", background: active ? "rgba(99,102,241,0.15)" : "transparent", border: `1px solid ${active ? "#6366f1" : "#1e293b"}`, borderRadius: 20, color: active ? "#e2e8f0" : "#64748b", fontSize: 13, cursor: "pointer", display: "flex", alignItems: "center", gap: 6 }}>
                  {tab !== "all" && <span style={{ width: 7, height: 7, borderRadius: "50%", background: dot }} />}
                  {tab === "all" ? "All" : SEV[tab as Severity].label}
                  <span style={{ color: dot, fontWeight: 700 }}>{count}</span>
                </button>
              );
            })}
          </div>
        )}

        {/* Findings */}
        {done && filteredFindings.length > 0 && (
          <div>
            <div style={{ fontSize: 14, color: "#64748b", marginBottom: 16 }}>Click any finding to see the full fix guide ↓</div>
            {filteredFindings.map((f, i) => <FindingCard key={i} f={f} />)}
          </div>
        )}

        {/* No findings */}
        {done && totalFindings === 0 && (
          <div style={{ textAlign: "center", padding: "60px 20px" }}>
            <div style={{ fontSize: 48, marginBottom: 16 }}>✅</div>
            <div style={{ fontSize: 20, fontWeight: 600, color: "#22c55e" }}>No vulnerabilities found</div>
            <div style={{ fontSize: 14, marginTop: 8, color: "#64748b" }}>All 12 agents completed without findings.</div>
          </div>
        )}
      </div>
    </main>
  );
}