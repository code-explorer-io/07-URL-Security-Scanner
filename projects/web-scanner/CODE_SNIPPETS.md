# Code Snippets for Implementation

> Copy-paste these into your implementation

## API Route: `/app/api/security-scan/route.ts`

```typescript
import { NextRequest, NextResponse } from 'next/server';

// Rate limiting (simple in-memory version)
const scanCounts = new Map<string, { count: number; resetAt: number }>();

function isRateLimited(ip: string): boolean {
  const now = Date.now();
  const record = scanCounts.get(ip);

  if (!record || now > record.resetAt) {
    scanCounts.set(ip, { count: 1, resetAt: now + 3600000 }); // 1 hour
    return false;
  }

  if (record.count >= 5) return true;

  record.count++;
  return false;
}

export async function POST(request: NextRequest) {
  const ip = request.headers.get('x-forwarded-for') || 'unknown';

  if (isRateLimited(ip)) {
    return NextResponse.json(
      { error: 'Rate limit exceeded. Try again in an hour.' },
      { status: 429 }
    );
  }

  const { url } = await request.json();

  // Validate URL
  try {
    new URL(url);
  } catch {
    return NextResponse.json(
      { error: 'Invalid URL' },
      { status: 400 }
    );
  }

  try {
    const results = await runSecurityScan(url);
    return NextResponse.json(results);
  } catch (error) {
    return NextResponse.json(
      { error: 'Scan failed. Please try again.' },
      { status: 500 }
    );
  }
}
```

## Header Check

```typescript
interface HeaderCheck {
  name: string;
  present: boolean;
  value?: string;
  severity: 'high' | 'medium' | 'low';
  description: string;
  howToFix: {
    vercel?: string;
    netlify?: string;
    general: string;
  };
}

async function checkHeaders(url: string): Promise<HeaderCheck[]> {
  const response = await fetch(url, {
    method: 'HEAD',
    redirect: 'follow'
  });

  const headers = response.headers;

  const checks: HeaderCheck[] = [
    {
      name: 'Content-Security-Policy',
      present: headers.has('content-security-policy'),
      value: headers.get('content-security-policy') || undefined,
      severity: 'medium',
      description: 'Controls which scripts can run on your site. Without it, injected malicious code will execute freely.',
      howToFix: {
        vercel: `Add to vercel.json:
{
  "headers": [{
    "source": "/(.*)",
    "headers": [{
      "key": "Content-Security-Policy",
      "value": "default-src 'self'; script-src 'self' 'unsafe-inline'"
    }]
  }]
}`,
        netlify: `Add to netlify.toml:
[[headers]]
  for = "/*"
  [headers.values]
    Content-Security-Policy = "default-src 'self'; script-src 'self' 'unsafe-inline'"`,
        general: "Add Content-Security-Policy header to your server configuration"
      }
    },
    {
      name: 'Strict-Transport-Security',
      present: headers.has('strict-transport-security'),
      value: headers.get('strict-transport-security') || undefined,
      severity: 'medium',
      description: 'Forces browsers to always use HTTPS. Without it, first-time visitors might connect insecurely.',
      howToFix: {
        vercel: `Add to vercel.json:
{
  "headers": [{
    "source": "/(.*)",
    "headers": [{
      "key": "Strict-Transport-Security",
      "value": "max-age=31536000; includeSubDomains"
    }]
  }]
}`,
        netlify: `Add to netlify.toml:
[[headers]]
  for = "/*"
  [headers.values]
    Strict-Transport-Security = "max-age=31536000; includeSubDomains"`,
        general: "Add Strict-Transport-Security: max-age=31536000; includeSubDomains"
      }
    },
    {
      name: 'X-Frame-Options',
      present: headers.has('x-frame-options'),
      value: headers.get('x-frame-options') || undefined,
      severity: 'low',
      description: 'Prevents your site from being embedded in iframes on malicious sites (clickjacking protection).',
      howToFix: {
        general: "Add X-Frame-Options: DENY header"
      }
    },
    {
      name: 'X-Content-Type-Options',
      present: headers.has('x-content-type-options'),
      value: headers.get('x-content-type-options') || undefined,
      severity: 'low',
      description: 'Prevents browsers from guessing file types, which can cause security issues.',
      howToFix: {
        general: "Add X-Content-Type-Options: nosniff header"
      }
    }
  ];

  return checks;
}
```

## SSL Check

```typescript
import * as tls from 'tls';

interface SSLResult {
  valid: boolean;
  expiresAt?: Date;
  daysUntilExpiry?: number;
  issuer?: string;
  error?: string;
}

async function checkSSL(hostname: string): Promise<SSLResult> {
  return new Promise((resolve) => {
    const socket = tls.connect({
      host: hostname,
      port: 443,
      servername: hostname,
      timeout: 5000
    }, () => {
      const cert = socket.getPeerCertificate();

      if (!cert || !cert.valid_to) {
        socket.destroy();
        resolve({ valid: false, error: 'Could not retrieve certificate' });
        return;
      }

      const expiresAt = new Date(cert.valid_to);
      const now = new Date();
      const daysUntilExpiry = Math.ceil((expiresAt.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));

      socket.destroy();
      resolve({
        valid: daysUntilExpiry > 0,
        expiresAt,
        daysUntilExpiry,
        issuer: cert.issuer?.O || cert.issuer?.CN || 'Unknown'
      });
    });

    socket.on('error', (err) => {
      socket.destroy();
      resolve({ valid: false, error: err.message });
    });

    socket.on('timeout', () => {
      socket.destroy();
      resolve({ valid: false, error: 'Connection timeout' });
    });
  });
}
```

## DNS Check (SPF/DMARC)

```typescript
import { resolveTxt } from 'dns/promises';

interface DNSResult {
  spf: {
    present: boolean;
    record?: string;
  };
  dmarc: {
    present: boolean;
    record?: string;
    policy?: 'none' | 'quarantine' | 'reject';
  };
}

async function checkDNS(domain: string): Promise<DNSResult> {
  const result: DNSResult = {
    spf: { present: false },
    dmarc: { present: false }
  };

  // Check SPF
  try {
    const spfRecords = await resolveTxt(domain);
    const spfRecord = spfRecords.flat().find(r => r.startsWith('v=spf1'));
    if (spfRecord) {
      result.spf = { present: true, record: spfRecord };
    }
  } catch {
    // No SPF record
  }

  // Check DMARC
  try {
    const dmarcRecords = await resolveTxt(`_dmarc.${domain}`);
    const dmarcRecord = dmarcRecords.flat().find(r => r.startsWith('v=DMARC1'));
    if (dmarcRecord) {
      const policyMatch = dmarcRecord.match(/p=(none|quarantine|reject)/);
      result.dmarc = {
        present: true,
        record: dmarcRecord,
        policy: policyMatch ? policyMatch[1] as 'none' | 'quarantine' | 'reject' : undefined
      };
    }
  } catch {
    // No DMARC record
  }

  return result;
}
```

## Tech Stack Detection

```typescript
interface TechStack {
  framework?: string;
  cdn?: string;
  hosting?: string;
  server?: string;
}

function detectTechStack(headers: Headers): TechStack {
  const stack: TechStack = {};

  // Framework detection
  const poweredBy = headers.get('x-powered-by');
  if (poweredBy) {
    if (poweredBy.includes('Next.js')) stack.framework = 'Next.js';
    else if (poweredBy.includes('Express')) stack.framework = 'Express';
    else if (poweredBy.includes('PHP')) stack.framework = 'PHP';
  }

  // CDN detection
  const server = headers.get('server');
  const via = headers.get('via');
  const cfRay = headers.get('cf-ray');

  if (cfRay) stack.cdn = 'Cloudflare';
  else if (server?.includes('cloudflare')) stack.cdn = 'Cloudflare';
  else if (headers.has('x-vercel-id')) stack.cdn = 'Vercel Edge';
  else if (headers.has('x-nf-request-id')) stack.cdn = 'Netlify';

  // Hosting detection
  if (headers.has('x-vercel-id')) stack.hosting = 'Vercel';
  else if (headers.has('x-nf-request-id')) stack.hosting = 'Netlify';
  else if (server?.includes('railway')) stack.hosting = 'Railway';

  // Server
  if (server && !stack.cdn) stack.server = server;

  return stack;
}
```

## Grade Calculation

```typescript
interface ScanResults {
  headers: HeaderCheck[];
  ssl: SSLResult;
  dns: DNSResult;
}

function calculateGrade(results: ScanResults): { grade: string; score: number } {
  let score = 0;

  // Headers (50 points)
  const criticalHeaders = ['content-security-policy', 'strict-transport-security'];
  const importantHeaders = ['x-frame-options', 'x-content-type-options'];

  for (const header of results.headers) {
    if (header.present) {
      if (criticalHeaders.includes(header.name.toLowerCase())) {
        score += 15;
      } else if (importantHeaders.includes(header.name.toLowerCase())) {
        score += 10;
      }
    }
  }

  // SSL (20 points)
  if (results.ssl.valid) {
    score += 20;
    // Bonus deduction if expiring soon
    if (results.ssl.daysUntilExpiry && results.ssl.daysUntilExpiry < 30) {
      score -= 5;
    }
  }

  // SPF (15 points)
  if (results.dns.spf.present) {
    score += 15;
  }

  // DMARC (15 points)
  if (results.dns.dmarc.present) {
    if (results.dns.dmarc.policy === 'reject') score += 15;
    else if (results.dns.dmarc.policy === 'quarantine') score += 12;
    else score += 8; // p=none
  }

  // Calculate grade
  let grade: string;
  if (score >= 90) grade = 'A';
  else if (score >= 80) grade = 'B';
  else if (score >= 70) grade = 'C';
  else if (score >= 50) grade = 'D';
  else grade = 'F';

  return { grade, score };
}
```

## React Component: Scan Form

```tsx
'use client';

import { useState } from 'react';

export function ScanForm({ onResults }: { onResults: (data: any) => void }) {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      const response = await fetch('/api/security-scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || 'Scan failed');
      }

      onResults(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Something went wrong');
    } finally {
      setLoading(false);
    }
  };

  return (
    <form onSubmit={handleScan} className="flex gap-2">
      <input
        type="url"
        value={url}
        onChange={(e) => setUrl(e.target.value)}
        placeholder="https://your-app.vercel.app"
        required
        className="flex-1 px-4 py-2 border rounded-lg"
      />
      <button
        type="submit"
        disabled={loading}
        className="px-6 py-2 bg-blue-600 text-white rounded-lg disabled:opacity-50"
      >
        {loading ? 'Scanning...' : 'Check Security'}
      </button>
      {error && <p className="text-red-500 mt-2">{error}</p>}
    </form>
  );
}
```

## Full Scan CTA Component

```tsx
export function FullScanCTA() {
  return (
    <div className="border-t pt-6 mt-6">
      <h3 className="text-lg font-semibold mb-2">Want a Full Security Audit?</h3>
      <p className="text-gray-600 mb-4">
        I manually review your app for exposed API keys, leaked secrets,
        and real vulnerabilities. The scary stuff this free scan can't catch.
      </p>
      <a
        href="https://x.com/YOUR_HANDLE"
        target="_blank"
        rel="noopener noreferrer"
        className="inline-block px-6 py-3 bg-black text-white rounded-lg hover:bg-gray-800"
      >
        DM me on X
      </a>
    </div>
  );
}
```
