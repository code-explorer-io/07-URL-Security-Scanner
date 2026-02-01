import { CheckResult, SecurityIssue } from '../types';

interface HeaderCheck {
  name: string;
  header: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  description: string;
  fix: string;
  validate?: (value: string) => boolean;
}

const SECURITY_HEADERS: HeaderCheck[] = [
  {
    name: 'Content-Security-Policy',
    header: 'content-security-policy',
    severity: 'high',
    description: 'CSP prevents XSS attacks by controlling which resources can be loaded',
    fix: "Add header: Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'"
  },
  {
    name: 'Strict-Transport-Security',
    header: 'strict-transport-security',
    severity: 'high',
    description: 'HSTS forces browsers to use HTTPS, preventing downgrade attacks',
    fix: 'Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'
  },
  {
    name: 'X-Frame-Options',
    header: 'x-frame-options',
    severity: 'medium',
    description: 'Prevents clickjacking by controlling if the site can be embedded in iframes',
    fix: 'Add header: X-Frame-Options: DENY (or SAMEORIGIN if you need iframes)'
  },
  {
    name: 'X-Content-Type-Options',
    header: 'x-content-type-options',
    severity: 'medium',
    description: 'Prevents MIME-type sniffing attacks',
    fix: 'Add header: X-Content-Type-Options: nosniff'
  },
  {
    name: 'Referrer-Policy',
    header: 'referrer-policy',
    severity: 'low',
    description: 'Controls how much referrer information is sent with requests',
    fix: 'Add header: Referrer-Policy: strict-origin-when-cross-origin'
  },
  {
    name: 'Permissions-Policy',
    header: 'permissions-policy',
    severity: 'low',
    description: 'Controls which browser features the site can use',
    fix: 'Add header: Permissions-Policy: geolocation=(), microphone=(), camera=()'
  },
  {
    name: 'X-XSS-Protection',
    header: 'x-xss-protection',
    severity: 'low',
    description: 'Legacy XSS filter (deprecated but still useful for older browsers)',
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
        fix: check.fix
      });
    } else if (check.validate && !check.validate(value)) {
      issues.push({
        id: `weak-${check.header}`,
        severity: check.severity,
        category: 'Security Headers',
        title: `Weak ${check.name} configuration`,
        description: `Header present but may not be configured securely: ${value}`,
        fix: check.fix
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
