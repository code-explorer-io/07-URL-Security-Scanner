# URL Security Scanner

Fast, lightweight security scanner for any website URL. Perfect for quick security assessments when you only have a URL.

## Quick Start

```bash
# Install dependencies
npm install

# Build
npm run build

# Scan a URL
npm run scan -- https://example.com
```

## Usage

```bash
# Basic scan
url-scanner https://example.com

# Verbose output (see progress)
url-scanner https://example.com --verbose

# Save report to file
url-scanner https://example.com --output report.md

# Compact report (for quick sharing)
url-scanner https://example.com --compact
```

## What It Checks

| Check | Description |
|-------|-------------|
| **Security Headers** | CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy |
| **SSL/TLS** | Certificate validity, expiration, TLS version |
| **Exposed Files** | .env, .git, config files, backups, source maps, debug files |
| **Cookie Security** | HttpOnly, Secure, SameSite flags |
| **CORS** | Misconfigured cross-origin policies |
| **Server Info** | Version disclosure in headers |
| **Admin Paths** | Common admin panels, login pages, debug endpoints |
| **robots.txt** | Sensitive paths revealed in robots.txt |

## Report Format

The report includes:

1. **Friendly Summary** - Plain English explanation of findings
2. **Detailed Issues** - Each issue with severity and description
3. **AI Agent Section** - Copy-paste instructions for Claude/ChatGPT to fix issues
4. **Technical Details** - Raw data for debugging

## Exit Codes

- `0` - No critical or high issues
- `1` - High-priority issues found
- `2` - Critical issues found
- `3` - Scan failed (network error, etc.)

## Example Output

```
# Security Scan Report

**Website:** https://example.com
**Scanned:** 1/31/2025, 10:30:00 AM
**Duration:** 5.2s

## Quick Summary

🔴 **Issues Found:** 3 high-priority issues you should fix soon.

| Check | Result |
|-------|--------|
| Security Headers | ❌ 4 issues |
| SSL/TLS | ✅ Pass |
| Exposed Files | ✅ Pass |
| Cookie Security | ❌ 2 issues |
| CORS Configuration | ✅ Pass |
| Server Information | ❌ 1 issue |
| Admin Paths | ✅ Pass |
| robots.txt Analysis | ✅ Pass |

## 🤖 Paste This To Your AI Agent

Copy everything below and paste it to Claude, ChatGPT, or your AI coding assistant to fix these issues:

[Fix instructions here...]
```

## Development

```bash
# Install dependencies
npm install

# Build TypeScript
npm run build

# Run directly with ts-node (for development)
npx ts-node src/index.ts https://example.com
```

## License

MIT
