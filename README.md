# URL Security Scanner v2

Security scanner for vibe coders. Scan any website, get friendly reports, make connections.

## Quick Start

```bash
npm install
npm run build
node dist/index.js https://example.com --outreach --gist
```

## What It Does

Scans websites for common security issues and generates:
- **Human report** - Beginner-friendly with analogies
- **Agent report** - Technical, for AI assistants to fix
- **DM message** - Ready to copy-paste for X outreach

## Usage

```bash
# Basic scan
node dist/index.js https://example.com

# Outreach mode (generates reports + DM)
node dist/index.js https://example.com --outreach

# Outreach + auto-upload to GitHub Gist
node dist/index.js https://example.com --outreach --gist
```

## What It Checks

| Check | Description |
|-------|-------------|
| **DNS Security** | SPF, DKIM, DMARC (email spoofing protection) |
| **API Keys** | Exposed keys in JavaScript (OpenAI, Stripe, AWS, etc.) |
| **Security Headers** | CSP, HSTS, X-Frame-Options, etc. |
| **SSL/TLS** | Certificate validity, expiration |
| **Exposed Files** | .env, .git, source maps (with content validation) |
| **Tech Stack** | Framework and hosting detection |

## Grading System

- **A** (90-100): Looking solid
- **B** (75-89): Good with minor issues
- **C** (60-74): Needs attention
- **D** (40-59): Several issues
- **F** (<40): Serious problems

## Example Output

```
🎯 Outreach Package Ready for: glowhub.space

   Grade: D (54/100)
   Issues: 0 critical, 1 high, 4 medium

📨 DM Message (copy this):
────────────────────────────────────────
Hey! Saw your site in the chat - looks great.

Ran a quick security check (I do this for fun). Found something worth mentioning:

No SPF record - anyone can send emails pretending to be you (@glowhub.space).
Someone could email your users "from you" with phishing links. One-line DNS fix.

Got a detailed report here if you want it: [gist-url]
────────────────────────────────────────
```

## Project Structure

```
src/
├── index.ts          # CLI entry point
├── scanner.ts        # Orchestrates checks
├── checks/           # Individual security checks
├── report/           # Report generators (human, agent, DM)
└── integrations/     # GitHub Gist upload

outputs/              # Generated reports
archive/              # Old planning docs
```

## Requirements

- Node.js 18+
- GitHub CLI (`gh`) for gist uploads

## License

MIT
