# Web Security Scanner - Project Specification

> A free security scanning tool for codeexplorer.io/security that serves as a lead magnet for deeper security audits.

**Goal:** Provide maximum value to users on the free scan (without costing money) → funnel them to contact you on X for full scans.

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Target Audience](#target-audience)
3. [Red Team Analysis](#red-team-analysis)
4. [Opportunities](#opportunities)
5. [Feature Specification](#feature-specification)
6. [Technical Architecture](#technical-architecture)
7. [UX & Copy](#ux--copy)
8. [Funnel Flow](#funnel-flow)
9. [Success Metrics](#success-metrics)
10. [Implementation Checklist](#implementation-checklist)
11. [Future Ideas](#future-ideas)

---

## Executive Summary

### What It Is
A free, instant security scanner at `codeexplorer.io/security` that checks basic security configurations and funnels users toward full security audits.

### Why It Works
- **For users:** Instant value, no signup required, educational
- **For you:** Lead generation, brand building, positions you as security expert
- **Synergy:** Your course teaches people to build apps → this helps them secure what they built

### Core Principle
The free scan must be genuinely useful. If users feel it's a gimmick, they won't trust the upsell. Value first, funnel second.

---

## Target Audience

### Primary: Vibe Coders / Beginners
- Built their first app with AI (Cursor, Bolt, Replit)
- Don't know about security
- Deployed to Vercel/Netlify/Railway
- Want validation that their app is "okay"

**What they're thinking:**
> "I built this thing, it works, but is it actually safe to share?"

### Secondary: Indie Hackers
- Shipping fast, security is afterthought
- Know security matters but haven't prioritized it
- Would pay for a proper audit if convinced

### Tertiary: Your Course Students
- Already trust you
- Built projects from your course
- Natural next step: "Is my project secure?"

---

## Red Team Analysis

### Risk 1: Low Perceived Value
**Problem:** Basic checks (headers, SSL, DNS) don't create urgency. User sees "Missing CSP header" and thinks "so what?"

**Mitigations:**
- Frame results in terms of real consequences ("Attackers can inject code into your site")
- Show what COULD be checked with full scan (tease the scary stuff)
- Add educational context that makes them care

### Risk 2: Competition Already Exists
**Problem:** SecurityHeaders.com, SSL Labs, Observatory all exist and are free.

**Mitigations:**
- Differentiate through UX (simpler, friendlier, built for beginners)
- Combine multiple checks in one place
- Add platform-specific fix instructions (Vercel, Netlify)
- Position as "for vibe coders" not "for security professionals"

### Risk 3: False Sense of Security
**Problem:** User gets "Grade: A" on basic checks but has exposed API keys.

**Mitigations:**
- Clear disclaimer: "This checks configuration, not code vulnerabilities"
- Explicitly state what's NOT checked
- "Want to check for exposed API keys? Get a full scan"

### Risk 4: Abuse Potential
**Problem:** Bad actors could use it to find vulnerable targets.

**Mitigations:**
- Rate limiting (5 scans per IP per hour)
- Only show results to the person scanning (no public database)
- Log scans for abuse monitoring
- Terms of service requiring you own/have permission for the URL

### Risk 5: Legal Concerns
**Problem:** Even passive scanning could theoretically be seen as unauthorized access.

**Mitigations:**
- Only perform passive checks (reading HTTP responses, DNS lookups)
- No active probing (no Nuclei, no path fuzzing)
- Terms of service: "Only scan sites you own or have permission to test"
- Disclaimer: "This tool only reads publicly available information"

### Risk 6: Support Burden
**Problem:** Users will ask "how do I fix this?" - creates unpaid support work.

**Mitigations:**
- Link to fix guides (blog posts, documentation)
- Platform-specific instructions in results
- "Need help? Book a consultation" as natural upsell

### Risk 7: Vercel Timeout
**Problem:** Vercel free tier has 10-second function timeout.

**Mitigations:**
- Keep checks fast (target 5-6 seconds total)
- Fail gracefully if individual check times out
- Consider streaming results as they complete

### Risk 8: CDN Masking
**Problem:** Cloudflare/Vercel Edge might mask real server headers.

**Mitigations:**
- Detect CDN and note it in results
- Explain that some headers come from CDN, not origin
- Still valuable to check what's actually served to browsers

### Risk 9: Low Conversion
**Problem:** What if people scan but never contact you?

**Mitigations:**
- Optional email capture: "Get your report emailed"
- Clear CTA: "DM me on X for a full scan"
- Show teaser of what full scan finds
- Follow up content: "5 Security Mistakes Vibe Coders Make" (blog/X thread)

### Risk 10: Scope Creep
**Problem:** Temptation to add more checks, complexity grows, costs increase.

**Mitigations:**
- Hard rule: Only add checks that complete in <2 seconds
- Document the line between free and paid clearly
- Resist feature requests that require compute-heavy scanning

---

## Opportunities

### High Value, Zero Cost Additions

#### 1. Platform-Specific Fix Instructions
Instead of: "Missing Strict-Transport-Security header"
Show: "Missing HSTS header. **For Vercel**, add this to your `vercel.json`:"
```json
{
  "headers": [
    {
      "source": "/(.*)",
      "headers": [
        { "key": "Strict-Transport-Security", "value": "max-age=31536000" }
      ]
    }
  ]
}
```

**Why it works:** Actionable > Educational. Users can fix it in 2 minutes.

**Platforms to support:** Vercel, Netlify, Railway, Render, Cloudflare Pages

#### 2. Tech Stack Detection
Detect and display: "We detected: Next.js + Vercel + Cloudflare"

**Why it works:**
- Shows sophistication ("they actually understand my setup")
- Enables platform-specific instructions
- No extra API calls needed (parse headers)

#### 3. Quick Wins Section
"3 things you can fix in 5 minutes:"
1. Add HSTS header (copy this config)
2. Add X-Frame-Options (copy this config)
3. Add CSP header (here's a starter policy)

**Why it works:** Immediate value, builds trust, demonstrates expertise.

#### 4. Severity Framing
Instead of: "Missing CSP header"
Show: "Missing CSP header - **MEDIUM RISK** - Without this, if an attacker finds any way to inject code, your visitors' browsers will run it. This is how data gets stolen."

**Why it works:** Consequences > Technical jargon

#### 5. Comparison Stats
"Your site scored **C (65/100)**. 73% of sites we've scanned score B or higher."

**Why it works:** Social proof, competitive motivation

#### 6. Shareable Results
"Share your security grade:" [Twitter] [LinkedIn] [Copy Link]

Badge/image: "🔒 My app scored B on codeexplorer.io/security"

**Why it works:** Free marketing, viral potential, developers love sharing badges

#### 7. Before/After Rescanning
"Fixed something? [Scan Again] to see your new score"

**Why it works:** Engagement loop, satisfaction of improvement

#### 8. Educational Tooltips
Hover/click on any finding to see:
- What it means (plain English)
- Why it matters (real consequence)
- How to fix it (platform-specific)

**Why it works:** Builds trust, positions you as teacher not salesman

#### 9. "What We Can't Check" Section
"This free scan checks your configuration. Here's what requires a full audit:"
- Exposed API keys in your JavaScript
- Leaked secrets in public repos
- Vulnerable dependencies
- Actual vulnerabilities (SQL injection, XSS)
- Exposed .env files

**Why it works:** Honest about limitations, natural upsell, no bait-and-switch feeling

#### 10. Email Capture (Optional)
"Want your report emailed? [Email] [Send]"
- Non-blocking (they get results regardless)
- Captures lead for follow-up

**Why it works:** Lead capture without friction

---

## Feature Specification

### Free Scan (codeexplorer.io/security)

| Check | Time | What It Finds | User Value |
|-------|------|---------------|------------|
| Security Headers | ~1s | Missing CSP, HSTS, X-Frame-Options, etc. | Medium - "Here's what to configure" |
| SSL Certificate | ~1s | Valid, expiry date, issuer | Medium - "Your SSL is fine" or "Expires soon!" |
| SPF Record | ~1s | Email spoofing protection | High - "Anyone can send emails as you" |
| DMARC Record | ~1s | Email policy enforcement | Medium - Works with SPF explanation |
| Tech Stack | ~0.5s | Framework, CDN, server detection | Low - But enables platform-specific tips |
| **Total** | ~5s | | |

### What's NOT in Free Scan (Paid/Full Audit)

| Check | Why Not Free | User Impact |
|-------|--------------|-------------|
| API Key Scanning | Requires fetching all JS files | HIGH - This is the "oh shit" moment |
| Exposed Files (.env, .git) | Active probing, potential legal issues | HIGH - Direct breach |
| Nuclei Vulnerability Scan | 30+ seconds, compute heavy | HIGH - Real vulnerabilities |
| Source Map Analysis | Compute heavy | MEDIUM - Code exposure |
| Subdomain Enumeration | Time consuming | LOW - Larger attack surface |
| Full Header Analysis | Already covered basics | LOW |

### The Upsell Gap

**Free scan tells them:** "Your configuration has some gaps"
**Full scan tells them:** "Your API key is exposed and here it is: sk-..."

The gap between "configuration issues" and "actual breach" is the conversion driver.

---

## Technical Architecture

### Stack

```
codeexplorer.io (existing Next.js on Vercel)
├── app/
│   ├── security/
│   │   └── page.tsx          ← Scanner UI
│   └── api/
│       └── security-scan/
│           └── route.ts      ← Scanning logic
├── lib/
│   └── security-scanner/
│       ├── headers.ts        ← Header checks
│       ├── ssl.ts            ← SSL checks
│       ├── dns.ts            ← SPF/DMARC checks
│       ├── tech-detect.ts    ← Stack detection
│       └── types.ts          ← TypeScript types
```

### API Route: `/api/security-scan`

**Request:**
```typescript
POST /api/security-scan
{
  "url": "https://example.com"
}
```

**Response:**
```typescript
{
  "url": "https://example.com",
  "scannedAt": "2024-01-15T10:30:00Z",
  "grade": "C",
  "score": 65,
  "techStack": {
    "framework": "Next.js",
    "cdn": "Cloudflare",
    "hosting": "Vercel"
  },
  "checks": {
    "headers": {
      "score": 50,
      "findings": [
        {
          "id": "missing-csp",
          "title": "Missing Content-Security-Policy",
          "severity": "medium",
          "description": "...",
          "howToFix": {
            "vercel": "Add to vercel.json...",
            "netlify": "Add to netlify.toml...",
            "general": "Add header..."
          }
        }
      ]
    },
    "ssl": { ... },
    "spf": { ... },
    "dmarc": { ... }
  },
  "quickWins": [...],
  "notChecked": [
    "API key exposure",
    "Exposed .env files",
    "Vulnerability scanning"
  ]
}
```

### Rate Limiting

**Option 1: Vercel KV (Recommended)**
- Free tier: 30k requests/month
- Store: `scan:{ip}` → count + timestamp
- Limit: 5 scans per IP per hour

**Option 2: In-Memory (Simpler, less reliable)**
- Map of IP → timestamps
- Resets on cold start
- Good enough for MVP

### Error Handling

```typescript
// Timeout individual checks, don't fail entire scan
const headerCheck = await Promise.race([
  checkHeaders(url),
  timeout(3000).then(() => ({ error: 'timeout', partial: true }))
]);
```

---

## UX & Copy

### Page Structure

```
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│   🔒 Is Your App Secure?                                        │
│                                                                 │
│   Built something with AI? Let's make sure it's                 │
│   safe to share with the world.                                 │
│                                                                 │
│   [https://your-app.vercel.app         ] [Check Security]       │
│                                                                 │
│   ✓ Free  ✓ Instant  ✓ No signup                               │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘

        ↓ After scan ↓

┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│   Security Score: C (65/100)                                    │
│   ████████████░░░░░░░░                                          │
│                                                                 │
│   ─────────────────────────────────────────────────────────    │
│                                                                 │
│   📋 What We Found                                              │
│                                                                 │
│   ⚠️  Missing Content-Security-Policy          MEDIUM           │
│      Without this, injected scripts will run freely.            │
│      [How to fix on Vercel ↓]                                  │
│                                                                 │
│   ⚠️  Missing HSTS Header                       MEDIUM           │
│      First-time visitors might not use HTTPS.                   │
│      [How to fix on Vercel ↓]                                  │
│                                                                 │
│   ✅  SSL Certificate Valid                                      │
│      Expires in 45 days (auto-renews)                           │
│                                                                 │
│   ✅  SPF Record Found                                           │
│      Email spoofing protection enabled                          │
│                                                                 │
│   ─────────────────────────────────────────────────────────    │
│                                                                 │
│   🎯 Quick Wins (fix in 5 minutes)                              │
│                                                                 │
│   1. Add these headers to your vercel.json:                     │
│      [Copy Code]                                                │
│                                                                 │
│   ─────────────────────────────────────────────────────────    │
│                                                                 │
│   🔍 What This Scan Doesn't Check                               │
│                                                                 │
│   This free scan checks your configuration.                     │
│   A full security audit also checks:                            │
│                                                                 │
│   • Exposed API keys in your JavaScript                         │
│   • Leaked secrets (.env files, .git folders)                   │
│   • Known vulnerabilities in your stack                         │
│   • Source code exposure via source maps                        │
│                                                                 │
│   ─────────────────────────────────────────────────────────    │
│                                                                 │
│   Want a full security audit?                                   │
│                                                                 │
│   I manually review your app for exposed secrets,               │
│   vulnerabilities, and security misconfigurations.              │
│                                                                 │
│   [DM me on X →]                                                │
│                                                                 │
│   ─────────────────────────────────────────────────────────    │
│                                                                 │
│   [🔄 Scan Again]    [Share Results]    [Get Report via Email]  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Copy Guidelines

**DO:**
- Use plain English ("browsers" not "user agents")
- Explain consequences ("attackers can..." not "vulnerability exists")
- Be specific ("add this to vercel.json" not "configure your server")
- Acknowledge limitations honestly

**DON'T:**
- Use fear-mongering ("YOUR SITE IS AT RISK!!!")
- Oversell the free scan
- Hide what's not checked
- Use security jargon without explanation

### Tone
- Helpful friend, not security salesman
- Teacher explaining concepts
- Fellow developer who's been there

---

## Funnel Flow

```
                    ┌─────────────────────┐
                    │   Traffic Sources   │
                    └──────────┬──────────┘
                               │
        ┌──────────────────────┼──────────────────────┐
        │                      │                      │
        ▼                      ▼                      ▼
┌───────────────┐    ┌─────────────────┐    ┌───────────────┐
│ Course Alumni │    │   X/Twitter     │    │  Organic SEO  │
│ "Check your   │    │  "Free security │    │ "free security│
│  project"     │    │   scanner for   │    │  scanner"     │
│               │    │   vibe coders"  │    │               │
└───────┬───────┘    └────────┬────────┘    └───────┬───────┘
        │                     │                     │
        └─────────────────────┼─────────────────────┘
                              │
                              ▼
                ┌─────────────────────────┐
                │  codeexplorer.io/security │
                │                         │
                │  [Enter URL] [Scan]     │
                └────────────┬────────────┘
                             │
                             ▼
                ┌─────────────────────────┐
                │   FREE SCAN RESULTS     │
                │                         │
                │   • Grade + Score       │
                │   • What's wrong        │
                │   • How to fix it       │
                │   • What's NOT checked  │
                └────────────┬────────────┘
                             │
           ┌─────────────────┼─────────────────┐
           │                 │                 │
           ▼                 ▼                 ▼
    ┌─────────────┐  ┌──────────────┐  ┌─────────────┐
    │  Fix it     │  │ Share score  │  │  Want more  │
    │  themselves │  │ on X         │  │             │
    │             │  │ (free promo) │  │             │
    └──────┬──────┘  └──────────────┘  └──────┬──────┘
           │                                  │
           ▼                                  ▼
    ┌─────────────┐                   ┌──────────────┐
    │  Rescan     │                   │  DM on X     │
    │  (engagement│                   │              │
    │   loop)     │                   │  "Hey, I     │
    └─────────────┘                   │   scanned my │
                                      │   site..."   │
                                      └──────┬───────┘
                                             │
                                             ▼
                                      ┌──────────────┐
                                      │  FULL SCAN   │
                                      │  (manual)    │
                                      │              │
                                      │  You run CLI │
                                      │  tool, send  │
                                      │  full report │
                                      └──────────────┘
```

---

## Success Metrics

### Leading Indicators (track immediately)
- Scans per day/week
- Unique IPs scanning
- Rescan rate (engagement)
- Share button clicks
- Email captures
- Time on page

### Lagging Indicators (track over time)
- DMs received mentioning the scanner
- Full scans requested
- Course sales attributed to /security
- Backlinks to the tool
- SEO rankings for "free security scanner"

### Target Goals (first 3 months)

| Metric | Month 1 | Month 2 | Month 3 |
|--------|---------|---------|---------|
| Scans | 100 | 300 | 500 |
| DM inquiries | 5 | 15 | 25 |
| Email captures | 20 | 60 | 100 |

---

## Implementation Checklist

### Phase 1: MVP (Week 1)
- [ ] Create `/app/security/page.tsx` - basic UI
- [ ] Create `/app/api/security-scan/route.ts` - scanning endpoint
- [ ] Implement header checks
- [ ] Implement SSL check
- [ ] Implement SPF/DMARC check
- [ ] Basic rate limiting (in-memory)
- [ ] Display results with grade
- [ ] "DM me on X" CTA
- [ ] Deploy and test

### Phase 2: Polish (Week 2)
- [ ] Tech stack detection
- [ ] Platform-specific fix instructions (Vercel, Netlify)
- [ ] Quick wins section
- [ ] "What we don't check" section
- [ ] Shareable results / social cards
- [ ] Rescan button
- [ ] Loading states and error handling

### Phase 3: Optimization (Week 3+)
- [ ] Email capture (optional)
- [ ] Vercel KV rate limiting
- [ ] Analytics tracking
- [ ] SEO optimization (meta tags, structured data)
- [ ] Blog post: "5 Security Mistakes Vibe Coders Make"
- [ ] X thread announcing the tool

---

## Future Ideas

### If It Works Well

**Tier System:**
- Free: Basic scan (current plan)
- Pro ($5/scan): API keys + exposed files
- Audit ($50): Full manual review + report + call

**API Access:**
- Let developers integrate scans into their CI/CD
- $10/month for 100 scans

**Leaderboard:**
- "Most secure vibe-coded apps"
- Gamification, badges

**Course Integration:**
- Add security module to the course
- "After building, scan with our tool"

### If It Doesn't Work

**Pivot options:**
- Keep as personal tool for outreach (current CLI)
- Open source it (goodwill, backlinks)
- Write about the learnings (content)

---

## Files to Create

When building, create these files:

```
codeexplorer.io/
├── app/
│   ├── security/
│   │   ├── page.tsx              # Main scanner page
│   │   └── components/
│   │       ├── ScanForm.tsx      # URL input form
│   │       ├── ResultsCard.tsx   # Score display
│   │       ├── FindingsList.tsx  # Issues list
│   │       ├── QuickWins.tsx     # Fix suggestions
│   │       └── FullScanCTA.tsx   # Upsell section
│   └── api/
│       └── security-scan/
│           └── route.ts          # API endpoint
├── lib/
│   └── security-scanner/
│       ├── index.ts              # Main scanner logic
│       ├── checks/
│       │   ├── headers.ts        # Security headers
│       │   ├── ssl.ts            # Certificate check
│       │   ├── dns.ts            # SPF/DMARC
│       │   └── tech-detect.ts    # Stack detection
│       ├── utils/
│       │   ├── rate-limit.ts     # Rate limiting
│       │   └── grade.ts          # Score calculation
│       └── types.ts              # TypeScript types
```

---

## Summary

**The tool will work if:**
1. Free scan provides genuine value (actionable fixes, not just "you have problems")
2. Clear differentiation from existing tools (beginner-friendly, platform-specific)
3. Honest about limitations (builds trust)
4. Low-friction path to full audit (DM, not sales call)

**The tool will fail if:**
1. Free scan feels like a gimmick
2. No clear value over SecurityHeaders.com
3. Users don't understand why they should care
4. Conversion path is unclear or pushy

**Recommendation:** Build the MVP in a week, launch to your course alumni first, iterate based on feedback before public launch.

---

*Document created: 2024-02-03*
*For: Code Explorer security scanner web integration*
