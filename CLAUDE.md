# URL Security Scanner

> **Start here.** Read this file at the beginning of each session.

## What This Tool Does

Scans websites for security issues and generates friendly outreach messages. Built for connecting with indie developers ("vibe coders") on X/Twitter.

**The workflow:**
1. You give me a URL to scan
2. I run a two-phase security check
3. I generate reports + a DM you can send
4. We discuss the findings so you learn

## Quick Start

```bash
# Scan with gist link (recommended)
node dist/index.js https://example.com --outreach --gist

# Without gist (local files only)
node dist/index.js https://example.com --outreach
```

**Output:** One gist link you can share, containing:
- DM message (ready to copy)
- Executive Summary (for the person)
- Agent Report (for their AI to fix issues)

## What Gets Checked

| Check | What It Finds | Why It Matters |
|-------|---------------|----------------|
| **SPF/DMARC** | Missing email auth | Anyone can send emails pretending to be them |
| **API Keys** | Exposed secrets in JS | Attackers can steal their OpenAI/Stripe/AWS credits |
| **Security Headers** | Missing CSP, HSTS, etc. | Browser protections not enabled |
| **SSL Certificate** | Expiry, weak config | Data not encrypted properly |
| **Exposed Files** | .env, .git, source maps | Secrets/code leaked publicly |

## Two-Phase Scan

```
PHASE 1: Our Internal Checks
├── Security headers, SSL, DNS
├── API key scanning in JavaScript
├── Exposed files and paths
└── Tech stack detection

PHASE 2: External Validation
├── Mozilla Observatory (header grades)
├── Nuclei vulnerability scanner
└── Links to SSL Labs, SecurityHeaders.com
```

External tools add credibility - if Observatory also flags headers, our finding is more trustworthy.

## Core Principle: Evidence-Based Reporting

**Every claim must be provable.** When cold-DMing someone, credibility is everything.

Each issue in the report includes:
- **Query:** What we checked
- **Response:** What we found (the proof)
- **Verify command:** How they can check themselves

If the scanner detects issues without evidence, it warns you before sending. Never DM a claim you can't back up.

See `LESSONS_LEARNED.md` for full implementation details.

## Understanding the Results

**Severity levels:**
- **CRITICAL** - Active security breach risk (exposed API keys, open .env)
- **HIGH** - Significant vulnerability (missing HSTS, no SPF)
- **MEDIUM** - Best practice gap (missing CSP, no X-Frame-Options)
- **LOW** - Hardening opportunity (missing Referrer-Policy)

**Grades:**
- **A** (90-100) - Excellent security posture
- **B** (80-89) - Good, minor improvements possible
- **C** (70-79) - Fair, some gaps to address
- **D** (50-69) - Needs attention
- **F** (<50) - Critical issues present

## Common Issues Explained

### No SPF Record (Most Common - 80%+ of sites)
**What it is:** SPF tells email servers which IPs can send email for a domain.
**The risk:** Without it, anyone can send emails that appear to come from their domain. Phishing attacks become trivial.
**The fix:** One DNS TXT record: `v=spf1 include:_spf.google.com ~all` (adjust for their email provider)

### Missing HSTS
**What it is:** Forces browsers to always use HTTPS.
**The risk:** Attacker on same network can intercept first HTTP request before redirect.
**The fix:** Add header: `Strict-Transport-Security: max-age=31536000; includeSubDomains`

### Exposed API Keys
**What it is:** Secret keys visible in client-side JavaScript.
**The risk:** Anyone can use their API quota, rack up charges, access their data.
**The fix:** Move keys to server-side, use environment variables.

## DM Tone That Works

The goal is helping, not selling. We're fellow developers sharing knowledge.

**Good:** "Ran a quick security check (I do this for fun). Found something worth mentioning..."
**Bad:** "Your site has 7 vulnerabilities. Here's my security consulting service..."

Keep it casual. One main issue. Explain the actual risk in plain English.

## Project Status

- **Version:** 2.5 (Evidence-based reporting)
- **Scans completed:** 5+
- **Key docs:** `LESSONS_LEARNED.md`, `V3_IDEAS.md`

## File Structure

```
CLAUDE.md          <- You are here (read first)
LESSONS_LEARNED.md <- Quality rules and past mistakes
V3_IDEAS.md        <- Roadmap and backlog
src/               <- Source code
outputs/           <- Generated reports (per scan)
scans/             <- Scan history JSON
tools/             <- Nuclei binary (local)
```

---

*When you're ready, give me a URL and I'll run the scan.*
