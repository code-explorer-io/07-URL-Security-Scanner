# URL Security Scanner - Roadmap

## What's Done (v2.3)

### Core Features
- [x] Two-phase scanning (internal + external validation)
- [x] Split reports: Executive Summary (human) + Agent Report (AI)
- [x] DM generator with beginner-friendly explanations
- [x] Scan history + stats command

### External Integrations
- [x] Mozilla Observatory API
- [x] Nuclei v3.7.0 vulnerability scanner
- [x] SSL Labs API (cached results)
- [x] crt.sh Certificate Transparency (subdomain discovery)
- [x] URLScan.io (malware/reputation check)
- [x] Google PageSpeed (optional, slow)
- [x] Manual check links: VirusTotal, Shodan, SecurityHeaders.com

### Quality Improvements (v2.3 - this session)
- [x] **Severity recalibration** - HSTS downgraded to MEDIUM (honest about real-world impact)
- [x] **"Not Checked" disclaimers** - Prominent section explaining what we can't test
- [x] **Tech detection accuracy** - Fixed false positives (WordPress/Webflow/Ghost on tool sites)
- [x] **Parallel external scans** - All APIs run concurrently for speed
- [x] **DM honesty** - Adds "(mostly best-practice headers)" when only finding header issues

---

## Future Ideas

### High Value / Low Effort
| Feature | Why |
|---------|-----|
| **More API key patterns** | Twilio, SendGrid, Mailgun, Postmark - common for vibe coders |
| **Subdomain takeover check** | crt.sh gives us subdomains, check if they resolve to dangling CNAMEs |
| **Re-scan comparison** | "Last scan: Grade D → This scan: Grade C - improved!" |

### High Value / Medium Effort
| Feature | Why |
|---------|-----|
| **VirusTotal API** | Free tier available, automated reputation scoring |
| **Supabase RLS detection** | Huge for vibe coders - detect open anon policies |
| **Form detection → CSP priority** | If site has forms, bump CSP to HIGH severity |

### Lower Priority
| Feature | Why Lower |
|---------|-----------|
| Web form for URL submission | CLI is fine for now |
| X thread auto-generator | Nice-to-have, manual works |
| Headless browser scanning | Complex, limited value for header checks |

---

## Exercises to Run Periodically

From the quality framework:

1. **One-Fix Optimization** (#12) - "If they could only fix ONE thing, what should it be?"
2. **False Reassurance Check** (#6) - "Does anything imply the app is 'safe' when unknowns remain?"
3. **Confidence Calibration** (#3) - "Are severity levels honest given available evidence?"
4. **User Comprehension** (#5) - "What would confuse a non-security developer?"

---

## Known Limitations

Fundamental to "outside-in" URL-only scanning:

1. **Obfuscated API keys** - Can't detect `atob()` or string concatenation
2. **Client-side XSS** - Would need headless browser + input testing
3. **Auth/business logic** - Can't test without credentials
4. **Rate limiting** - Can't test without making many requests
5. **CDN masking** - We see edge servers, not origin

**We're explicit about these in reports.** The "Not Checked" section tells users what matters more than headers.

---

## Code Quality Backlog

From previous audit:

**High Priority:**
- Timeout cleanup race conditions in scanner.ts
- Socket leak potential in ssl.ts
- Missing timeout on CORS preflight requests

**Medium:**
- Unsafe type casting in cookies.ts
- JSON parsing without size limits

---

*Last updated: 2026-02-02*
