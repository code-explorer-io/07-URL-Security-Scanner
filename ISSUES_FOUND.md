# Issues Found

> Running log of scans and findings. Helps us track patterns and improve the tool.

## Summary

| Total Scans | Avg Grade | Most Common Issue |
|-------------|-----------|-------------------|
| 1 | F | Missing DMARC |

---

## Scan History

### clenvor.com
**Date:** 2026-02-02
**Grade:** F (35/100)
**Observatory:** F (10/100)

| Severity | Count | Issues |
|----------|-------|--------|
| Critical | 0 | - |
| High | 1 | No DMARC record |
| Medium | 6 | Missing CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy |
| Low | 4 | Cookie flags, server info exposed |

**Notes:** Standard Next.js app missing security headers. No API keys exposed.

---

## Issue Frequency

Track which issues appear most often:

| Issue | Times Seen | % of Scans |
|-------|------------|------------|
| No DMARC record | 1 | 100% |
| Missing CSP | 1 | 100% |
| Missing HSTS | 1 | 100% |
| Cookie missing Secure flag | 1 | 100% |

---

## Patterns Noticed

- Next.js apps often missing security headers (framework doesn't add them by default)
- Most indie sites lack DMARC (email security not on their radar)

---

*Update this file after each scan to track patterns.*
