# Sentinel v2 — Deployment Guide

## What this version is

Sentinel is a **passive + lightly-active AI-assisted reconnaissance tool** — an honest description that holds up in a security interview. It is *not* a full penetration-testing scanner, and the copy in the UI now says so.

For each target it:

1. Validates the URL (rejects junk input, `localhost`, and private IP ranges to prevent SSRF).
2. Fetches the real HTTP response once (headers, status, HTML, robots.txt).
3. Actively probes 25 common sensitive paths (`/.env`, `/.git/HEAD`, DB dumps, config backups, swagger docs, etc.) and records which return real content.
4. Fetches and scans same-origin JavaScript bundles + inline HTML for secret patterns (AWS/Google/Stripe/GitHub keys, private keys, JWTs, hardcoded credentials) and source-map references.
5. Fingerprints the tech stack (Server header, X-Powered-By, generator meta, JS library versions, CMS path hints).
6. Feeds all of this real, observed evidence to 12 AI agents that produce grounded findings — with explicit "requires deeper testing" notes for anything a passive/active fetch can't verify.

The four checks that were previously pure hallucination are now handled honestly:

| Check | How it works now |
|-------|------------------|
| Files | Active path probing — confirmed 200s become real findings |
| Disclosure | Real JS/inline secret scanning with regex patterns |
| CVE | Real tech fingerprinting → version-aware CVE-class analysis (never fabricates CVE IDs) |
| Logic | Honest "requires manual testing" + flags client-side-only trust visible in source |

## Can it be deployed publicly?

Yes, with one important caveat about **timeouts**.

A full scan runs 12 agents sequentially with 2.5s pacing (to stay under Cerebras' free-tier rate limit), plus fetch + path probing + script scanning. Total wall-clock time is roughly **40–70 seconds**.

- **Vercel Hobby (free): 10s function limit** — a full scan will time out. Not viable for the live scan without changes.
- **Vercel Pro: 60s default, up to 300s configurable** — the included `vercel.json` sets `maxDuration: 60`. Most scans finish in time; very slow targets may still cut it close.
- **Local (`npm run dev`): no limit** — always works.

### Options for a working public deploy

1. **Vercel Pro** + the included `vercel.json` (`maxDuration: 60`). Simplest path.
2. **Reduce agent count** to 4–6 broader agents (halves the time) — fits more comfortably in 60s and is a stronger architectural story anyway.
3. **Fire agents in parallel batches** (e.g. 4 at a time) instead of fully sequential — cuts wall-clock time, but raises rate-limit risk on the free Cerebras tier. Pair with a paid Cerebras tier for headroom.
4. **Split into two requests**: one endpoint does fetch+probe+scan and returns the evidence; a second endpoint runs agents. Keeps each function under the limit.
5. **Deploy on a platform without a hard function timeout** (Render, Railway, Fly.io, a small VPS). Railway is a good fit since you already use it elsewhere.

## Setup

```bash
npm install
```

Create `.env.local` in the project root:

```
CEREBRAS_API_KEY=your_real_key_from_cloud.cerebras.ai
```

Run locally:

```bash
npm run dev
# open http://localhost:3000
```

## Deploying to Vercel

1. Push to GitHub (Vercel auto-deploys on push).
2. In Vercel → Settings → Environment Variables, add `CEREBRAS_API_KEY` for Production, Preview, and Development.
3. Commit `vercel.json` so the function gets the 60s limit (requires Pro for it to take effect).
4. Redeploy.

## Files in this bundle

- `route.ts` → replaces `app/api/scan/route.ts`
- `page.tsx` → replaces `app/page.tsx`
- `.env.example` → documents the required env var (safe to commit)
- `vercel.json` → raises the serverless function timeout

## Verification done before shipping

- `tsc --noEmit` passes clean against the project's own `tsconfig.json`.
- `next build` (the exact command Vercel runs) compiles successfully; `/api/scan` registers as a dynamic route.
- 19 isolated unit tests pass for URL validation (SSRF blocks) and secret-pattern scanning.
- Live network test confirms fetch, header capture, fingerprinting, and path probing work against a real public site.

## Legal / ethical note

Active path probing sends real requests to the target. Only scan sites you own or have explicit permission to test. The tool sends an identifying `User-Agent` and does not attempt exploitation, but scanning third-party sites without authorization can still violate their terms of service or local law. Keep this framing in your portfolio: it signals security maturity.