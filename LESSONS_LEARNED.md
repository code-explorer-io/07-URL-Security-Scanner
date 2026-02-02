# Lessons Learned

> Review this before adding new detection patterns or making changes.

## False Positive Incidents

### 1. Postmark UUID Pattern (2026-02-02)

**What happened:** Added a generic UUID pattern to detect Postmark tokens. Flagged webpack debug IDs as "exposed API tokens."

**The bad pattern:**
```regex
/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}/g
```

**Why it failed:** UUIDs are everywhere in modern JS:
- Webpack/Next.js debug IDs (`debugId=xxx`)
- React component keys
- Analytics session IDs
- Any library using UUIDs internally

**The fix:** Removed the pattern. Postmark detection would need context-awareness (UUID near "postmark" string).

**Lesson:** Never use generic formats (UUIDs, base64, hex strings) without a unique prefix or context check.

---

## Pattern Confidence Tiers

### HIGH Confidence (safe to report)
Patterns with unique, service-specific prefixes:

| Service | Prefix | Example |
|---------|--------|---------|
| OpenAI | `sk-` or `sk-proj-` | `sk-proj-abc123...` |
| Stripe | `sk_live_`, `sk_test_` | `sk_live_abc123...` |
| AWS | `AKIA` | `AKIAIOSFODNN7EXAMPLE` |
| Google | `AIza` | `AIzaSyDaGmWKa4JsXZ...` |
| GitHub | `ghp_`, `gho_` | `ghp_xxxxxxxxxxxx...` |
| Slack | `xoxb-` | `xoxb-123-456-abc...` |
| Anthropic | `sk-ant-` | `sk-ant-abc123...` |
| SendGrid | `SG.xxx.xxx` | `SG.xxxxx.yyyyy` |
| Resend | `re_` | `re_123abc...` |
| Vercel | `vercel_` | `vercel_abc123...` |

### MEDIUM Confidence (may false positive)
Patterns that could match non-secrets:

| Service | Pattern | Risk |
|---------|---------|------|
| Twilio | `SK` + 32 hex | Could match hash fragments |
| Mailgun | `key-` + 32 chars | Generic prefix |
| Convex | `prod:xxx\|xxx` | Unusual but not unique |

### DO NOT USE (high false positive)
- Generic UUIDs
- Generic base64 strings
- Generic hex strings without prefix
- Common words like "token", "secret", "key" without context

---

## Quality Checklist

Before adding a new API key pattern:

1. [ ] Does it have a **unique prefix** specific to that service?
2. [ ] Test against 5+ real websites - any false positives?
3. [ ] Check if the pattern matches common dev artifacts (debug IDs, hashes, etc.)
4. [ ] If confidence is MEDIUM, add a note in the description
5. [ ] Document the pattern source (official docs, real examples)

Before releasing changes:

1. [ ] Run against previously scanned sites - any new false positives?
2. [ ] Compare our findings with Mozilla Observatory - do they align?
3. [ ] Would you be comfortable sending a DM based on this finding?

---

## Red Flags in Detection

If you see these, the pattern is probably too generic:

- Matches 3+ times in a single JS file
- Matches in minified code without clear context
- Pattern is just "letters + numbers" without prefix
- Found in `debugId`, `_debugIds`, `sourceMap`, `chunk` contexts

---

## DM Tone Guidelines

### Closing Lines

**Current:** "Happy to help if you have questions - us vibe coders gotta look out for each other!"

**Issue:** Assumes the recipient identifies as a "vibe coder" - might feel presumptuous.

**Better alternatives:**
- "Happy to help if you have questions!" (simple, universal)
- "Let me know if you want help fixing any of these." (action-oriented)
- "Feel free to reach out if you want a hand with any of this." (warm, no labels)
- Just end after the report link (shortest, lets findings speak)

**When to use "vibe coder":** Only in communities where that term is established (e.g., specific X/Twitter groups).

### General DM Principles

1. **No jargon** - If recipient might not know the term, don't use it (SPF, DMARC → "email spoofing protection")
2. **One main issue** - Lead with the most impactful finding
3. **Explain the risk** - "What this means: anyone can send emails as you"
4. **Offer help, don't sell** - We're sharing knowledge, not pitching services

---

## Standard DM Structure

This is the template for all DM messages. Follow this format exactly for consistency across 50-250+ scans.

### Template

```
Hey! Saw your site in the chat - looks great.

Ran a quick security check (I do this for fun). Found something worth mentioning:

1. [Issue Name]
What this means: [plain English explanation of the risk]

2. [Issue Name]
What this means: [plain English explanation of the risk]

Plus some smaller things ([brief list of minor issues]).

Got a detailed report on GitHub Gist: [gist URL]

Let me know if you need anything else!
```

### Key Rules

1. **Every numbered issue gets "What this means:"** - No exceptions. Don't use dashes or inline explanations.
2. **Maximum 2-3 numbered issues** - More than that overwhelms people. Bundle extras into "Plus some smaller things"
3. **High-impact issues first** - DMARC, exposed API keys, missing CSP come before HSTS, Referrer-Policy
4. **Plain English only** - "anyone can send emails pretending to be you" not "SPF/DKIM validation fails"
5. **Include gist link** - Always use `--gist` flag so recipients have a detailed report

### Example (Real Output)

```
1. No DMARC record
What this means: anyone can send emails pretending to be from your domain. One DNS record fixes this.

2. Missing Content Security Policy
What this means: if someone injects bad code, visitors' browsers will run it (this is how data gets stolen)
```

### What NOT to Do

❌ `2. Missing CSP - if someone injects bad code...` (dash instead of "What this means:")
❌ `2. Missing Content-Security-Policy header` (jargon, no explanation)
❌ Four numbered issues (overwhelming)
❌ Closing with assumptions about recipient ("us vibe coders")
