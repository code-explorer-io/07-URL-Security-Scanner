# URL Security Scanner - Context for Claude

> Read this file at the start of each session to get up to speed quickly.

## What This Is

Security scanner for vibe coders. Scan websites, find issues, DM the developer, make connections.

**The play:** Vibe coder posts project on X → You scan it → DM them with findings → They're grateful → You've made a friend.

## Current State

- **Version:** 2.2 (two-phase scan, red-teamed 4x)
- **Scans completed:** 2 (GlowHub, CodeExplorer)
- **Connections made:** 1 (GlowHub responded positively)

### Recent Improvements (v2.1 → v2.2)
- Fixed LOW severity handling - DMs now mention minor issues positively
- Smart email severity - domains without MX records get lower-priority SPF/DMARC warnings
- Reduced CSP severity (high → medium) - less noise for typical vibe coder sites
- Fixed Stripe/Clerk key overlap detection
- Added external scanner integration module (Mozilla Observatory)
- **Nuclei v3.7.0 integrated** - 21k+ star vuln scanner with YAML templates
- **TWO-PHASE SCAN** - Our scan + External validation + Combined reports

## Quick Commands

```bash
# Full two-phase scan with outreach reports + gist upload
node dist/index.js https://example.com --outreach --gist

# View stats from all scans
node dist/index.js stats
```

## Two-Phase Scan Flow

```
┌─────────────────────────────────────────────────────────────────┐
│  PHASE 1: Internal Scan                                         │
│  - Security headers, SSL, DNS, API keys, exposed files          │
│  - Tech stack detection                                         │
│  - Our custom checks with human-friendly risk explanations     │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│  PHASE 2: External Validation                                   │
│  - Mozilla Observatory (header grades)                          │
│  - Nuclei (21k+ vulnerability templates)                        │
│  - Links to SSL Labs, SecurityHeaders.com                       │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│  OUTPUT FILES                                                   │
│  - executive-summary-{domain}.md → For the person (human)       │
│  - agent-report-{domain}.md → For their AI assistant            │
│  - dm-{domain}.txt → Initial outreach message                   │
└─────────────────────────────────────────────────────────────────┘
```

**Tell the vibe coder:** "The Executive Summary is for you. The Agent Report is for your AI assistant to fix the issues."

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

## Competitive Landscape

**No direct competitors** for vibe coder-focused security outreach.

| Existing Tool | What They Do | Our Advantage |
|---------------|--------------|---------------|
| [Sucuri SiteCheck](https://sitecheck.sucuri.net/) | Malware/blacklist scanning | We explain RISK in plain English |
| [UpGuard WebScan](https://www.upguard.com/webscan) | Data leak detection | We generate friendly DMs |
| [Snyk](https://snyk.io/website-scanner/) | Code dependency scanning | We focus on shipped sites, not repos |
| [SecurityHeaders.com](https://securityheaders.com/) | Header analysis only | We cover email, API keys, files too |

**Our unique value:** Human-friendly risk explanations + DM generation for genuine outreach.

## Current Priorities

1. **Scan history** - Save every scan for pattern analysis ("80% miss SPF")
2. **Landing page** - Give project legitimacy, let people connect via X
3. **X content** - Use scan data to create posts

## External Validation (Second-Level)

Cross-check our findings with trusted external tools:

| Tool | Status | What It Does |
|------|--------|--------------|
| [Mozilla Observatory](https://developer.mozilla.org/en-US/observatory) | ✅ Integrated | Industry-standard header grades (free API) |
| [Nuclei](https://github.com/projectdiscovery/nuclei) | ✅ Installed | 21k+ stars, YAML vuln templates (local in tools/) |
| [SSL Labs](https://www.ssllabs.com/ssltest/) | 🔗 Manual link | Deep SSL analysis (web UI only) |
| [SecurityHeaders.com](https://securityheaders.com/) | 🔗 Manual link | Quick header check (API discontinued) |

### Nuclei Integration (Working!)

Nuclei v3.7.0 is installed locally in `tools/nuclei.exe`. Uses YAML templates to detect specific vulnerabilities.

**Features:**
- Runs targeted scans based on detected tech stack (WordPress, Next.js, etc.)
- Focus on high/critical severity by default
- Tags: exposure, misconfig, token, api

```typescript
// Quick scan (high/critical only, 1 min timeout)
import { quickNucleiScan } from './integrations/nuclei';
const result = await quickNucleiScan('https://example.com');

// Full scan with tech stack awareness
import { runNucleiScan } from './integrations/nuclei';
const result = await runNucleiScan('https://example.com', {
  techStack: ['Next.js', 'Vercel'],
  severity: ['medium', 'high', 'critical'],
  verbose: true
});
```

### External Scanners Code

```typescript
// Run Observatory + Nuclei together
import { runExternalScans } from './integrations/external-scanners';

const { results, links, nucleiAvailable } = await runExternalScans('example.com', {
  observatory: true,
  nuclei: true,
  verbose: true
});
```

## File Structure

```
CLAUDE.md          ← You are here (read first)
README.md          ← Quick start for users
V3_IDEAS.md        ← Full roadmap (read if planning features)
src/               ← Source code
  integrations/    ← Gist + External scanner integrations (Observatory, Nuclei)
tools/             ← Local tools (nuclei.exe v3.7.0)
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

*Last updated: 2026-02-02 (v2.2 + Two-phase scan + Combined reports)*
