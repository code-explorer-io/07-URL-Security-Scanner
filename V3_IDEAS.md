# URL Security Scanner v3 - Roadmap

## What's Done (v2)

- [x] Scanner with SPF/DMARC, API keys, headers, SSL checks
- [x] DM generator with ACTUAL RISK explanations
- [x] Human-friendly reports with analogies
- [x] Technical agent reports for AI assistants
- [x] GitHub Gist integration
- [x] Scan history saving for pattern analysis
- [x] Stats command for X content generation

**First outreach: SUCCESS** - GlowHub connection made.

---

## Current Priorities

### 1. Landing Page (TOP)

Simple site to give the project legitimacy.

**Requirements:**
- Single page, clean design
- Explains what we do in plain English
- "Get a free security check" → Connect via X
- MUST pass our own scanner with Grade A

**Content:**
1. Hero: "Free Security Checks for Vibe Coders"
2. What we check (SPF, API keys, headers)
3. How it works (Drop URL → We scan → Friendly report)
4. Connect on X: @[handle]

### 2. Collect More Scans

Goal: 20+ scans to generate meaningful stats.

Use `node dist/index.js stats` to see patterns and generate X content.

### 3. X Content from Data

Once we have 20+ scans:
- "Scanned 20 vibe coder sites. 80% are missing SPF records..."
- "The #1 security issue I see on indie sites..."
- Weekly tips based on most common issues

---

## Future Ideas

| Feature | Value | Notes |
|---------|-------|-------|
| Supabase/Firebase checks | High | Detect open RLS, exposed configs |
| More API key patterns | Medium | Twilio, SendGrid, etc. |
| Re-scan tracking | Medium | Show improvements over time |
| Landing page form | Low | Let people submit URLs directly |

---

## Lessons Learned

1. **Explain the RISK** - "anyone can send emails as you" > "missing SPF"
2. **One strong issue > list** - Lead with impact
3. **Human touch matters** - "us vibe coders gotta look out for each other"
4. **False positives = trust killer** - Be conservative

---

## Success Metrics

- [ ] 20 sites scanned
- [ ] 5 connections made
- [ ] Landing page live
- [ ] First X thread from scan data
- [ ] Grade A on our own landing page

---

*Last updated: 2026-02-02*
