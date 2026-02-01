# Project Context: URL Security Scanner v2

> This document captures the full vision, decisions, and approach for this project.
> Read this first if you're new to the project or starting a fresh session.

---

## The Vision

**One sentence:** A security scanning tool that helps you build genuine connections with vibe coders on X/Twitter by providing free, valuable security feedback on their projects.

**The insight:** Thousands of indie developers ("vibe coders") post their projects on X. Each URL is a free lead. By scanning their site and offering helpful security feedback, you provide genuine value and open a conversation — no cold pitch, no spam.

**The end goal:** Build a network of developer contacts by being the person who helped them fix their security before someone malicious found it.

---

## The Workflow

### Step 1: Find a Lead
- Vibe coder posts their project on X
- You have their public URL

### Step 2: Run the Scan
```bash
node dist/index.js https://their-site.com --outreach
```

### Step 3: Start the Conversation (No Link Yet)
First DM — deliver value directly, no link required:
```
Hey! Love what you're building with [project name].

Quick heads up - I ran a security check (I do this for fun)
and noticed a couple things:

• Anyone can send emails pretending to be you@domain.com
  (no email authentication set up)

• Missing a header that stops your site being put in fake frames

Both are 5-min fixes. Happy to share how if useful!
```

### Step 4: If They Respond Positively
Send the GitHub gist with the full report:
```
Here's the full report with copy-paste fixes: [gist-url]

There's a prompt at the bottom you can paste into
Cursor/Claude to fix everything automatically.
```

### Step 5: Optional Upsell (With Permission)
If they want deeper testing:
```
I also do authorized security testing — where I actually
try to find ways in, with your permission. Like hiring
someone to pick your locks before a real burglar does.
Let me know if that's ever useful.
```

**Key principle:** No ask, no pressure. Value first. Link only after rapport.

---

## The Outputs

The tool generates four files:

| File | Purpose | Audience |
|------|---------|----------|
| `dm-intro.txt` | First DM message — findings in plain English, no link | Human (the dev) |
| `dm-followup.txt` | Second DM — includes gist link | Human (the dev) |
| `report-human.md` | Beginner-friendly report with analogies | Human (the dev) |
| `report-agent.md` | Super technical, detailed prompts for AI agents | AI (Cursor, Claude, ChatGPT) |

The human report and agent report are both uploaded to a public GitHub gist for easy sharing.

---

## Core Philosophy

These principles emerged from extensive red-teaming exercises:

### 1. Signal Over Noise
- Only report what we're confident about
- Fewer findings > more findings
- No crying wolf

### 2. Honesty Over Authority
- Explicit about what we can't check
- "Surface-level checkup, not a full audit"
- Confidence levels on every finding

### 3. Friend Tone, Not Auditor Tone
- Explain like texting a friend
- Use analogies ("like leaving your house key under the doormat")
- Never condescending or scary

### 4. Action Over Anxiety
- Every finding has a simple fix
- If the fix is too complex, don't report the issue
- They should feel empowered, not overwhelmed

### 5. Maximum 5 Findings
- More than 5 = they close the tab
- Prioritize ruthlessly
- Lead with the most impactful/verifiable issue

---

## What We Check (v2)

### High-Confidence Checks (Keep)

| Check | Confidence | Why |
|-------|------------|-----|
| API keys in JavaScript | 95% | The "best friend forever" check — if we find their OpenAI key, they'll love us |
| Security headers | 100% | Easy to verify, easy to fix |
| SSL/TLS certificate | 100% | Expiry date, validity |
| DNS email auth (SPF/DKIM/DMARC) | 100% | Most vibe coders forget this completely |
| Source maps exposed | 90% | Reveals original code, real risk |
| Exposed .env/.git | 70%+ | Must validate content, not just 200 status |

### Removed (Too Noisy)

| Check | Why Removed |
|-------|-------------|
| Admin path enumeration | SPAs return 200 for everything — massive false positives |
| Subdomain brute force | Slow, noisy, incomplete |
| Deprecated headers (X-XSS-Protection) | Browsers handle this now |
| Rate limiting detection | Would require aggressive testing |

### Content Validation Required

The v1 scanner had a critical flaw: it only checked HTTP status codes. SPAs return 200 for every route, causing false positives.

**New rule:** Every "exposed file" check must validate content:

| File | Must Contain |
|------|-------------|
| `.env` | Lines matching `KEY=value` pattern |
| `.git/config` | `[core]` or `[remote "origin"]` |
| `backup.sql` | `CREATE TABLE` or `INSERT INTO` |
| `.map` files | `"sources":` or `"mappings":` (valid source map JSON) |

---

## Security Grade System

Simple A/B/C grading:

**Calculation:**
- Start at 100 points
- Critical issue: -30 (max 2 counted)
- High issue: -15
- Medium issue: -8
- Low issue: -3
- Bonuses: +5 each for (valid long SSL, Cloudflare detected, etc.)

**Grades:**
- A: 90-100
- B: 75-89
- C: 60-74
- D: 40-59
- F: <40

**Important:** This is a "surface grade" not a "security grade" — we're explicit that it only reflects what's publicly visible.

---

## Confidence Levels

Every finding has a confidence level that affects how it's presented:

| Confidence | How We Present It |
|------------|-------------------|
| HIGH (90%+) | "🔴 FOUND: [issue]" — state it as fact |
| MEDIUM (70-89%) | "🟡 POSSIBLE: [issue] — worth checking manually" |
| LOW (<70%) | "ℹ️ NOTE: [observation] — might be nothing" |

Low-confidence findings are excluded from the DM intro entirely.

---

## Report Formats

### Human Report (`report-human.md`)

Designed for developers who don't know security:

```markdown
# Security Checkup: yoursite.dev
**Grade: B**

## What's Looking Good ✅
- Your SSL certificate is valid (good for 8 more months)
- No exposed .env or .git files
- Cloudflare protection detected

## Things to Fix

### 🔴 Anyone Can Send Emails As You
**What this means:** Someone could send emails pretending to be you@yoursite.dev.
It's like having no caller ID on your phone — anyone can claim to be you.

**The fix (5 minutes):**
Add this DNS record at your domain registrar:
```
Type: TXT
Name: @
Value: v=spf1 include:_spf.google.com ~all
```

[More issues...]

## What This Didn't Check
This was a surface-level checkup. It doesn't test:
- Server-side vulnerabilities
- Database security
- Login/authentication logic
- Your backend code

Think of it like checking tire pressure — useful, but doesn't mean you won't get a flat.
```

### Agent Report (`report-agent.md`)

Designed for AI coding assistants (Cursor, Claude, ChatGPT):

```markdown
# Security Remediation Instructions

Target: https://yoursite.dev
Scan Date: 2025-02-01
Scanner Version: 2.0.0

## Environment Detection
- Framework: Next.js 14.x (detected via /_next/ paths)
- Hosting: Vercel (detected via x-vercel-id header)
- CDN: Cloudflare (detected via cf-ray header)

## Issue 1: Missing SPF Record
- Severity: MEDIUM
- Confidence: HIGH (100%)
- Evidence: DNS TXT query returned no SPF record

### Remediation
Add SPF record via Vercel Dashboard or DNS provider:
```
TXT @ "v=spf1 include:_spf.google.com ~all"
```

For Vercel-managed domains, this can be added at:
Settings > Domains > [domain] > DNS Records

### Verification
After adding, verify with:
```bash
dig +short TXT yoursite.dev | grep spf
```

## Issue 2: Missing Content-Security-Policy Header
- Severity: MEDIUM
- Confidence: HIGH (100%)
- Evidence: Response headers do not include Content-Security-Policy

### Remediation
For Next.js on Vercel, add to `next.config.js`:
```javascript
const securityHeaders = [
  {
    key: 'Content-Security-Policy',
    value: "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline';"
  }
];

module.exports = {
  async headers() {
    return [{ source: '/:path*', headers: securityHeaders }];
  }
};
```

### Verification
After deploying, verify with:
```bash
curl -I https://yoursite.dev | grep -i content-security-policy
```

[More issues with same level of detail...]
```

---

## Abuse Prevention

The tool could be misused for reconnaissance. Mitigations:

| Risk | Mitigation |
|------|------------|
| Attacker recon | Rate limit, one URL at a time |
| Credential exposure | Mask found keys: `sk-proj-****...****xyz` |
| Competitive intel | No batch scanning mode |
| Extortion | Positive framing, link to fixes not exploits |

---

## What We Learned (Red-Teaming Exercises)

### The Embarrassment Test
Top issues vibe coders get embarrassed about:
1. API key leaked in JavaScript (most common, most detectable)
2. Database credentials in GitHub (can't detect from URL)
3. No rate limiting (risky to test)
4. Firebase/Supabase wide open (partially detectable)

**Insight:** #1 is both most common AND most detectable. This is our killer feature.

### The False Positive Problem
The v1 scanner flagged 59 "issues" on a site that were all false positives. SPAs return 200 for everything.

**Insight:** One false positive destroys all credibility. Better to report 3 real issues than 30 questionable ones.

### The Trust Threshold
Maximum findings on first scan: 3-5

**Insight:** More than 5 = overwhelming. Less than 3 = useless. Sweet spot is 3-5 prioritized items.

### The North Star
If a vibe coder fixes only ONE thing after using this tool, what should it be?

**Answer:** Move API keys from client-side JavaScript to server-side environment variables.

If our tool's #1 recommendation ever drifts from this, something's wrong.

---

## Technical Architecture

```
src/
├── index.ts              # CLI entry point
├── scanner.ts            # Orchestrates all checks
├── types.ts              # TypeScript interfaces
├── checks/
│   ├── headers.ts        # Security headers (existing)
│   ├── ssl.ts            # SSL/TLS (existing)
│   ├── cookies.ts        # Cookie security (existing)
│   ├── cors.ts           # CORS config (existing)
│   ├── exposed-files.ts  # .env, .git, etc. (needs content validation)
│   ├── server-info.ts    # Server version disclosure (existing)
│   ├── robots.ts         # robots.txt analysis (existing)
│   ├── dns-security.ts   # SPF/DKIM/DMARC (NEW)
│   ├── api-keys.ts       # Keys in JavaScript (NEW)
│   ├── source-maps.ts    # Exposed .map files (NEW)
│   └── tech-detect.ts    # Framework/hosting detection (NEW)
├── report/
│   ├── score.ts          # A/B/C grade calculation (NEW)
│   ├── human.ts          # Beginner-friendly report (NEW)
│   ├── agent.ts          # Technical AI-focused report (NEW)
│   └── dm.ts             # DM message generation (NEW)
├── integrations/
│   └── gist.ts           # GitHub gist upload (NEW)
└── data/
    └── api-key-patterns.json  # Regex patterns for key detection (NEW)
```

---

## CLI Usage (v2)

```bash
# Standard scan (current behavior)
node dist/index.js https://example.com

# Outreach mode — generates DM messages + human/agent reports
node dist/index.js https://example.com --outreach

# Outreach mode + auto-upload to GitHub gist
node dist/index.js https://example.com --outreach --gist

# Quick scan (headers + SSL only, fastest)
node dist/index.js https://example.com --quick
```

**Outreach mode outputs:**
```
outputs/
├── dm-intro.txt         # First DM (no link)
├── dm-followup.txt      # Second DM (with gist link)
├── report-human.md      # Beginner-friendly report
└── report-agent.md      # Technical AI report
```

---

## Build Order

1. **Fix false positives** — Add content validation to exposed-files check
2. **DNS security check** — SPF/DKIM/DMARC detection
3. **API key detection** — Scan JavaScript for exposed keys
4. **Tech detection** — Identify framework/hosting for tailored advice
5. **Human report format** — Beginner-friendly with analogies
6. **Agent report format** — Super technical for AI assistants
7. **DM message generation** — Short messages for X outreach
8. **Security grade** — A/B/C scoring system
9. **Gist integration** — Auto-upload via `gh gist create`
10. **Source map detection** — Check for exposed .map files

---

## What Success Looks Like

1. **Zero false positives** — Every finding is real and verifiable
2. **Immediate value** — DM message alone is useful, no link needed
3. **Actionable fixes** — Every issue has a <15 min fix
4. **Trust building** — Leads to real conversations and connections
5. **Optional upsell** — Opens door to paid security work (with permission)

---

## Reminders for Future Sessions

- The target audience is "vibe coders" — indie devs who ship fast, often AI-assisted
- Tone should be helpful friend, not scary auditor
- Fewer findings with high confidence beats many findings with uncertainty
- The killer feature is API key detection in JavaScript
- Always validate file contents, not just HTTP status codes
- The human reads `report-human.md`, the AI reads `report-agent.md`
- No link in first DM — establish rapport first

---

*Last updated: 2025-02-01*
