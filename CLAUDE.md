# URL Security Scanner

> **Start here.** Read this file at the beginning of each session.

## What This Tool Does

Scans websites for security issues and generates friendly outreach messages. Built for connecting with indie developers ("vibe coders") on X/Twitter.

**The workflow:**
1. You give me a URL to scan
2. I run a two-phase security check
3. I generate reports + a DM you can send
4. We discuss the findings so you learn

## Quick Start (Copy-Paste)

```bash
# Build first (if not already built)
npm run build

# Scan a site with full reports
node dist/index.js https://example.com --outreach --verbose
```

This creates three files in `outputs/`:
- `dm-{domain}.txt` - Message to send them
- `executive-summary-{domain}.md` - Human-readable report
- `agent-report-{domain}.md` - Technical report for their AI assistant

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

- **Version:** 2.2
- **Scans completed:** 2
- **Next priority:** Landing page for legitimacy

## File Structure

```
CLAUDE.md          <- You are here (read first)
V3_IDEAS.md        <- Roadmap and backlog
src/               <- Source code
outputs/           <- Generated reports (per scan)
scans/             <- Scan history JSON
tools/             <- Nuclei binary (local)
```

---

*When you're ready, give me a URL and I'll run the scan.*
