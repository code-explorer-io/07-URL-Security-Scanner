# Web Scanner - Quick Reference

> TL;DR for the agent building this

## What We're Building

Free security scanner at `codeexplorer.io/security` → leads to full audits via X DM

## Core Checks (Must complete in <5 seconds total)

| Check | How | Library/Method |
|-------|-----|----------------|
| Security Headers | `fetch(url)` → read headers | Native fetch |
| SSL Certificate | `tls.connect()` → get cert | Node.js tls module |
| SPF Record | DNS TXT lookup for domain | `dns.resolveTxt()` |
| DMARC Record | DNS TXT lookup for `_dmarc.domain` | `dns.resolveTxt()` |
| Tech Detection | Parse `x-powered-by`, `server`, cookies | From header response |

## Grade Calculation

```
100 points total:
- Headers: 50 points (10 per major header)
- SSL Valid: 20 points
- SPF Present: 15 points
- DMARC Present: 15 points

A: 90-100 | B: 80-89 | C: 70-79 | D: 50-69 | F: <50
```

## Rate Limiting

5 scans per IP per hour. Use Vercel KV or in-memory Map.

## Key UX Points

1. Show results immediately (no email required)
2. Platform-specific fixes (Vercel, Netlify config snippets)
3. Be honest about what's NOT checked
4. Clear CTA: "DM me on X for full scan"

## The Upsell Gap

**Free finds:** "Missing CSP header"
**Full audit finds:** "Your OpenAI key is exposed: sk-proj-abc..."

The scary stuff is what converts.

## Files to Create

```
app/security/page.tsx         # UI
app/api/security-scan/route.ts # Backend
lib/security-scanner/*.ts      # Check logic
```

## Don't Forget

- [ ] Terms of service / disclaimer
- [ ] "Only scan sites you own"
- [ ] Timeout individual checks (don't fail entire scan)
- [ ] Mobile responsive
- [ ] Loading state during scan
- [ ] Error handling for invalid URLs
