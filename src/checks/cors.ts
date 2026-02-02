import { CheckResult, SecurityIssue } from '../types';

interface CORSDetails {
  allowOrigin: string | null;
  allowCredentials: string | null;
  allowMethods: string | null;
  allowHeaders: string | null;
  exposeHeaders: string | null;
  maxAge: string | null;
}

export async function checkCORS(url: string, headers: Headers): Promise<CheckResult> {
  const issues: SecurityIssue[] = [];

  const details: CORSDetails = {
    allowOrigin: headers.get('access-control-allow-origin'),
    allowCredentials: headers.get('access-control-allow-credentials'),
    allowMethods: headers.get('access-control-allow-methods'),
    allowHeaders: headers.get('access-control-allow-headers'),
    exposeHeaders: headers.get('access-control-expose-headers'),
    maxAge: headers.get('access-control-max-age')
  };

  const parsedUrl = new URL(url);

  // Check for wildcard origin with credentials
  if (details.allowOrigin === '*') {
    const corsEvidence = {
      query: `HTTP response headers from ${url}`,
      response: `Access-Control-Allow-Origin: ${details.allowOrigin}${details.allowCredentials ? `, Access-Control-Allow-Credentials: ${details.allowCredentials}` : ''}`,
      verifyCommand: `curl -I ${url} | grep -i "access-control"`
    };

    if (details.allowCredentials?.toLowerCase() === 'true') {
      issues.push({
        id: 'cors-wildcard-credentials',
        severity: 'critical',
        category: 'CORS',
        title: 'CORS allows any origin with credentials',
        description: 'Access-Control-Allow-Origin: * with credentials enabled allows any website to make authenticated requests',
        fix: 'Never use wildcard (*) origin with credentials. Specify exact allowed origins instead.',
        evidence: corsEvidence
      });
    } else {
      issues.push({
        id: 'cors-wildcard',
        severity: 'medium',
        category: 'CORS',
        title: 'CORS allows any origin',
        description: 'Access-Control-Allow-Origin: * allows any website to read responses from your API',
        fix: 'Restrict to specific trusted origins: Access-Control-Allow-Origin: https://yourdomain.com',
        evidence: corsEvidence
      });
    }
  }

  // Check if origin reflects request (potential misconfiguration)
  // We can only detect this with a preflight request
  try {
    const testOrigin = 'https://evil-attacker-site.com';
    const preflightResponse = await fetch(url, {
      method: 'OPTIONS',
      headers: {
        'Origin': testOrigin,
        'Access-Control-Request-Method': 'GET'
      }
    });

    const reflectedOrigin = preflightResponse.headers.get('access-control-allow-origin');
    if (reflectedOrigin === testOrigin) {
      issues.push({
        id: 'cors-origin-reflection',
        severity: 'critical',
        category: 'CORS',
        title: 'CORS reflects arbitrary origin',
        description: 'The server reflects any Origin header back, allowing any website to make requests',
        fix: 'Validate the Origin header against a whitelist of trusted domains',
        evidence: {
          query: `OPTIONS ${url} with Origin: ${testOrigin}`,
          response: `Access-Control-Allow-Origin: ${reflectedOrigin} (reflected our test origin)`,
          verifyCommand: `curl -X OPTIONS -H "Origin: ${testOrigin}" -I ${url} | grep -i "access-control-allow-origin"`
        }
      });
    }

    // Check for null origin allowed
    const nullOriginResponse = await fetch(url, {
      method: 'OPTIONS',
      headers: {
        'Origin': 'null',
        'Access-Control-Request-Method': 'GET'
      }
    });

    const nullOriginAllowed = nullOriginResponse.headers.get('access-control-allow-origin');
    if (nullOriginAllowed === 'null') {
      issues.push({
        id: 'cors-null-origin',
        severity: 'high',
        category: 'CORS',
        title: 'CORS allows null origin',
        description: 'The server accepts "null" origin, which can be exploited via sandboxed iframes',
        fix: 'Do not whitelist "null" as an allowed origin',
        evidence: {
          query: `OPTIONS ${url} with Origin: null`,
          response: `Access-Control-Allow-Origin: ${nullOriginAllowed}`,
          verifyCommand: `curl -X OPTIONS -H "Origin: null" -I ${url} | grep -i "access-control-allow-origin"`
        }
      });
    }
  } catch {
    // Preflight requests may fail, that's okay
  }

  return {
    name: 'CORS Configuration',
    passed: issues.length === 0,
    issues,
    details
  };
}
