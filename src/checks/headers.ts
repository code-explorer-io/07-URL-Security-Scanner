import { CheckResult, SecurityIssue } from '../types';

interface HeaderCheck {
  name: string;
  header: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  description: string;
  fix: string;
  validate?: (value: string) => boolean;
}

/**
 * Security headers ranked by REAL-WORLD IMPACT for typical indie/vibe coder sites.
 *
 * Calibration notes (Exercise #12 - One-Fix Optimization):
 * - CSP: Actually prevents XSS attacks. Most impactful for sites with user input.
 * - HSTS: Good practice, but modern browsers/hosts already prefer HTTPS. Downgraded to MEDIUM.
 * - X-Frame-Options: Prevents clickjacking. Medium risk for most sites.
 * - X-Content-Type-Options: Low-effort fix, prevents MIME confusion. Keep at MEDIUM.
 *
 * NOTE: The things we CAN'T check (rate limiting, input sanitization, auth flow)
 * are often MORE impactful than header issues. We're explicit about this in reports.
 */
const SECURITY_HEADERS: HeaderCheck[] = [
  {
    name: 'Content-Security-Policy',
    header: 'content-security-policy',
    severity: 'medium',  // Would be HIGH if we could detect user input forms
    description: 'CSP prevents XSS attacks by controlling which resources can be loaded. This is your main defense if malicious code ever gets injected.',
    fix: "Add header: Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'"
  },
  {
    name: 'Strict-Transport-Security',
    header: 'strict-transport-security',
    severity: 'medium',  // Downgraded: modern browsers + hosts like Vercel already prefer HTTPS
    description: 'HSTS tells browsers to always use HTTPS. Most modern hosts already redirect HTTP→HTTPS, so this is defense-in-depth.',
    fix: 'Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains'
  },
  {
    name: 'X-Frame-Options',
    header: 'x-frame-options',
    severity: 'medium',
    description: 'Prevents clickjacking by controlling if your site can be embedded in iframes on other sites',
    fix: 'Add header: X-Frame-Options: DENY (or SAMEORIGIN if you need iframes)'
  },
  {
    name: 'X-Content-Type-Options',
    header: 'x-content-type-options',
    severity: 'low',  // Downgraded: very edge-case attack, easy fix but low real-world impact
    description: 'Prevents browsers from guessing file types, which can cause security issues in edge cases',
    fix: 'Add header: X-Content-Type-Options: nosniff'
  },
  {
    name: 'Referrer-Policy',
    header: 'referrer-policy',
    severity: 'low',
    description: 'Controls how much URL information is shared when users click links to other sites',
    fix: 'Add header: Referrer-Policy: strict-origin-when-cross-origin'
  },
  {
    name: 'Permissions-Policy',
    header: 'permissions-policy',
    severity: 'low',
    description: 'Restricts which browser features (camera, mic, location) your site can use',
    fix: 'Add header: Permissions-Policy: geolocation=(), microphone=(), camera=()'
  },
  {
    name: 'X-XSS-Protection',
    header: 'x-xss-protection',
    severity: 'low',
    description: 'Legacy XSS filter. Deprecated in modern browsers but still helps older ones.',
    fix: 'Add header: X-XSS-Protection: 1; mode=block'
  }
];

export async function checkSecurityHeaders(headers: Headers): Promise<CheckResult> {
  const issues: SecurityIssue[] = [];
  const details: Record<string, string | null> = {};

  for (const check of SECURITY_HEADERS) {
    const value = headers.get(check.header);
    details[check.name] = value;

    if (!value) {
      issues.push({
        id: `missing-${check.header}`,
        severity: check.severity,
        category: 'Security Headers',
        title: `Missing ${check.name} header`,
        description: check.description,
        fix: check.fix,
        evidence: {
          query: `HTTP response header: ${check.header}`,
          response: 'Header not present in response',
          verifyCommand: `curl -I https://example.com | grep -i "${check.header}"`
        }
      });
    } else if (check.validate && !check.validate(value)) {
      issues.push({
        id: `weak-${check.header}`,
        severity: check.severity,
        category: 'Security Headers',
        title: `Weak ${check.name} configuration`,
        description: `Header present but may not be configured securely: ${value}`,
        fix: check.fix,
        evidence: {
          query: `HTTP response header: ${check.header}`,
          response: value,
          verifyCommand: `curl -I https://example.com | grep -i "${check.header}"`
        }
      });
    }
  }

  return {
    name: 'Security Headers',
    passed: issues.length === 0,
    issues,
    details
  };
}
