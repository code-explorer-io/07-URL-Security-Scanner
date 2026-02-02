# URL Security Scanner - Context for Claude

> Read this file at the start of each session to get up to speed quickly.

## What This Is

Security scanner for vibe coders. Scan websites, find issues, DM the developer, make connections.

**The play:** Vibe coder posts project on X → You scan it → DM them with findings → They're grateful → You've made a friend.

## Current State

- **Version:** 2.0 (fully working)
- **Scans completed:** 2 (GlowHub, CodeExplorer)
- **Connections made:** 1 (GlowHub responded positively)

## Quick Commands

```bash
# Scan a site with outreach mode + auto-upload to gist
node dist/index.js https://example.com --outreach --gist

# View stats from all scans
node dist/index.js stats
```

## What It Checks

| Check | Why It Matters |
|-------|----------------|
| **SPF/DMARC** | No SPF = anyone can send emails as them (TOP ISSUE - 80%+ miss this) |
| **API Keys** | Exposed OpenAI/Stripe/AWS keys in JavaScript |
| **Security Headers** | CSP, HSTS, X-Frame-Options |
| **SSL Certificate** | Expiry, validity |
| **Exposed Files** | .env, .git, source maps |

## Key Principles

1. **Explain ACTUAL RISK** - "anyone can send emails as you" not "missing SPF record"
2. **One strong issue > list of weak ones** - Lead with impact
3. **False positives = trust killer** - Better to miss than cry wolf
4. **Friend tone, not auditor** - "us vibe coders gotta look out for each other"

## DM Format That Works

```
Yo, so on your [Project] project.

I ran a quick security check (I do this for fun). Found something worth mentioning:

- No SPF record - this means anyone can send emails pretending to be you (@domain.com).
  It's a one-line DNS fix but basically as your website stands, someone could email
  your users "from you" with phishing links.

Also a couple of minor header things, but the email one is the main one.

Got a detailed report here if you want it: [gist-url]

The fix is literally adding one TXT record to your DNS.

Happy to help if you have questions - us vibe coders have gotta look out for each other!
```

## Current Priorities

1. **Scan history** - Save every scan for pattern analysis ("80% miss SPF")
2. **Landing page** - Give project legitimacy, let people connect via X
3. **X content** - Use scan data to create posts

## File Structure

```
CLAUDE.md          ← You are here (read first)
README.md          ← Quick start for users
V3_IDEAS.md        ← Full roadmap (read if planning features)
src/               ← Source code
scans/             ← Scan history (for pattern analysis)
outputs/           ← Generated reports (per-scan)
archive/           ← Old planning docs (historical only)
```

## Scan History Format

Each scan saves to `scans/[domain].json`:

```json
{
  "domain": "glowhub.space",
  "scannedAt": "2026-02-02T10:30:00Z",
  "grade": "D",
  "score": 54,
  "issues": [
    { "title": "No SPF record", "severity": "high", "category": "Email Security" },
    { "title": "Missing CSP", "severity": "medium", "category": "Security Headers" }
  ],
  "topIssue": "No SPF record",
  "techStack": ["Next.js", "Vercel"],
  "gistUrl": "https://gist.github.com/..."
}
```

This lets us run `stats` and see patterns across all scans.

## What NOT To Do

- No batch scanning - one at a time is more personal
- No link in cold DMs if you can't DM yet - reply publicly first
- No jargon without explanation
- No overwhelming with issues - max 3 in DM

---

*Last updated: 2026-02-02*
