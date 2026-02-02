import { CheckResult, SecurityIssue } from '../types';

interface CookieAnalysis {
  name: string;
  hasSecure: boolean;
  hasHttpOnly: boolean;
  hasSameSite: boolean;
  sameSiteValue?: string;
  raw: string;
}

export async function checkCookies(headers: Headers, isHttps: boolean): Promise<CheckResult> {
  const issues: SecurityIssue[] = [];
  const cookies: CookieAnalysis[] = [];

  // Get all Set-Cookie headers
  const setCookieHeaders: string[] = [];

  // Headers.getSetCookie() is the proper way in modern Node.js
  if (typeof (headers as unknown as { getSetCookie?: () => string[] }).getSetCookie === 'function') {
    setCookieHeaders.push(...(headers as unknown as { getSetCookie: () => string[] }).getSetCookie());
  } else {
    // Fallback: try to get from raw header
    const cookieHeader = headers.get('set-cookie');
    if (cookieHeader) {
      // This won't work perfectly for multiple cookies, but it's a fallback
      setCookieHeaders.push(cookieHeader);
    }
  }

  for (const cookie of setCookieHeaders) {
    const parts = cookie.split(';').map(p => p.trim());
    const nameValue = parts[0];
    const name = nameValue.split('=')[0];

    const lowerCookie = cookie.toLowerCase();

    const analysis: CookieAnalysis = {
      name,
      hasSecure: lowerCookie.includes('secure'),
      hasHttpOnly: lowerCookie.includes('httponly'),
      hasSameSite: lowerCookie.includes('samesite'),
      raw: cookie
    };

    // Extract SameSite value
    const sameSiteMatch = lowerCookie.match(/samesite\s*=\s*(strict|lax|none)/i);
    if (sameSiteMatch) {
      analysis.sameSiteValue = sameSiteMatch[1].toLowerCase();
    }

    cookies.push(analysis);

    // Mask the cookie value for evidence (show structure, not data)
    const maskedCookie = cookie.replace(/=([^;]+)/, '=[VALUE]');

    // Check for security issues
    if (isHttps && !analysis.hasSecure) {
      issues.push({
        id: `cookie-no-secure-${name}`,
        severity: 'high',
        category: 'Cookie Security',
        title: `Cookie "${name}" missing Secure flag`,
        description: 'Cookie can be transmitted over unencrypted connections',
        fix: `Add Secure flag to cookie: Set-Cookie: ${name}=value; Secure; HttpOnly; SameSite=Lax`,
        evidence: {
          query: `Set-Cookie header for "${name}"`,
          response: maskedCookie,
          verifyCommand: `curl -I https://example.com | grep -i "set-cookie"`
        }
      });
    }

    if (!analysis.hasHttpOnly) {
      // Check if it looks like a session cookie
      const isLikelySession = /sess|token|auth|jwt|sid|login|user/i.test(name);
      issues.push({
        id: `cookie-no-httponly-${name}`,
        severity: isLikelySession ? 'high' : 'medium',
        category: 'Cookie Security',
        title: `Cookie "${name}" missing HttpOnly flag`,
        description: 'Cookie is accessible via JavaScript, making it vulnerable to XSS theft',
        fix: `Add HttpOnly flag to cookie: Set-Cookie: ${name}=value; HttpOnly; Secure; SameSite=Lax`,
        evidence: {
          query: `Set-Cookie header for "${name}"`,
          response: maskedCookie,
          verifyCommand: `curl -I https://example.com | grep -i "set-cookie"`
        }
      });
    }

    if (!analysis.hasSameSite) {
      issues.push({
        id: `cookie-no-samesite-${name}`,
        severity: 'medium',
        category: 'Cookie Security',
        title: `Cookie "${name}" missing SameSite attribute`,
        description: 'Cookie may be sent with cross-site requests, enabling CSRF attacks',
        fix: `Add SameSite attribute: Set-Cookie: ${name}=value; SameSite=Lax; Secure; HttpOnly`,
        evidence: {
          query: `Set-Cookie header for "${name}"`,
          response: maskedCookie,
          verifyCommand: `curl -I https://example.com | grep -i "set-cookie"`
        }
      });
    } else if (analysis.sameSiteValue === 'none' && !analysis.hasSecure) {
      issues.push({
        id: `cookie-samesite-none-insecure-${name}`,
        severity: 'high',
        category: 'Cookie Security',
        title: `Cookie "${name}" has SameSite=None without Secure`,
        description: 'SameSite=None requires the Secure flag to work properly',
        fix: `Add Secure flag when using SameSite=None: Set-Cookie: ${name}=value; SameSite=None; Secure`,
        evidence: {
          query: `Set-Cookie header for "${name}"`,
          response: maskedCookie,
          verifyCommand: `curl -I https://example.com | grep -i "set-cookie"`
        }
      });
    }
  }

  return {
    name: 'Cookie Security',
    passed: issues.length === 0,
    issues,
    details: { cookies }
  };
}
