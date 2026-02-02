# URL Security Scanner - Roadmap

## What's Done (v2.2)

- [x] Two-phase scanning (internal + external validation)
- [x] Mozilla Observatory API integration
- [x] Nuclei v3.7.0 vulnerability scanner
- [x] Split reports: Executive Summary (human) + Agent Report (AI)
- [x] DM generator with ACTUAL RISK explanations
- [x] Scan history + stats command
- [x] Red-teamed 4x, false positives minimized

---

## Next Priority: Landing Page

**Status:** Draft created in `site/index.html`

**To deploy:**
1. Host on Vercel/Netlify/GitHub Pages
2. Scan our own site - must get Grade A
3. Add proper security headers in hosting config

**Features:**
- Single page, dark theme, mobile responsive
- Personal tone - "one developer helping another"
- Explains checks in beginner language
- CTA: DM on X (@CodeExplorerHQ)

---

## Success Metrics

- [ ] 20 sites scanned
- [ ] 5 connections made
- [ ] Landing page live (Grade A)
- [ ] First X thread from scan data

---

## Future Ideas

| Feature | Value | Effort |
|---------|-------|--------|
| Subdomain takeover detection | Medium | Low |
| Supabase/Firebase open RLS checks | High | Medium |
| More API key patterns (Twilio, SendGrid) | Medium | Low |
| Re-scan tracking (show improvements) | Medium | Medium |
| Web form for URL submission | Low | Medium |

---

## Known Limitations (from red teaming)

1. **Obfuscated API keys** - Can't detect `atob()` or string concatenation
2. **Client-side XSS** - Would need headless browser
3. **Auth/business logic** - Can't test without credentials
4. **CDN masking** - We see edge, not origin

These are fundamental to "outside-in" scanning. Be honest about scope.

---

## Code Quality Backlog

From 2026-02-02 audit (24 issues found):

**Critical (fix soon):**
- Timeout cleanup race conditions in scanner.ts
- Nuclei findings validation logic in combined.ts
- Socket leak potential in ssl.ts

**High:**
- Missing timeout on CORS preflight requests
- Unsafe type casting in cookies.ts
- JSON parsing without size limits

See full audit in session history.

---

*Last updated: 2026-02-02*
