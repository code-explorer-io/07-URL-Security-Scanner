import { CheckResult, SecurityIssue } from '../types';

interface ApiKeyPattern {
  name: string;
  service: string;
  pattern: RegExp;
  severity: 'critical' | 'high';
  description: string;
  fix: string;
  // Some patterns may have high false positive rates
  confidence: 'high' | 'medium';
}

// Patterns for detecting exposed API keys in JavaScript
// Only include patterns with low false positive rates
const API_KEY_PATTERNS: ApiKeyPattern[] = [
  // OpenAI - very specific pattern
  {
    name: 'OpenAI API Key',
    service: 'OpenAI',
    pattern: /sk-(?:proj-)?[a-zA-Z0-9]{32,}/g,
    severity: 'critical',
    description: 'OpenAI API key found in JavaScript. Anyone can use your key and charge your account.',
    fix: 'Move the API key to a server-side environment variable. Never expose OpenAI keys in frontend code.',
    confidence: 'high'
  },
  // Stripe Secret Key (not publishable key which is meant to be public)
  {
    name: 'Stripe Secret Key',
    service: 'Stripe',
    pattern: /sk_live_[a-zA-Z0-9]{24,}/g,
    severity: 'critical',
    description: 'Stripe SECRET key found (not the publishable key). This gives full access to your Stripe account.',
    fix: 'Move to server-side immediately. Only pk_live_ keys should be in frontend code.',
    confidence: 'high'
  },
  {
    name: 'Stripe Test Secret Key',
    service: 'Stripe',
    pattern: /sk_test_[a-zA-Z0-9]{24,}/g,
    severity: 'high',
    description: 'Stripe test secret key found. While test mode, this indicates a pattern that may leak production keys.',
    fix: 'Move to server-side environment variables.',
    confidence: 'high'
  },
  // AWS Access Key
  {
    name: 'AWS Access Key',
    service: 'AWS',
    pattern: /AKIA[A-Z0-9]{16}/g,
    severity: 'critical',
    description: 'AWS Access Key ID found. If the secret key is also exposed, attackers can access your AWS resources.',
    fix: 'Rotate this key immediately in AWS IAM console. Use AWS Cognito or API Gateway for frontend auth.',
    confidence: 'high'
  },
  // Google API Key (with key= parameter pattern for higher confidence)
  {
    name: 'Google API Key',
    service: 'Google',
    pattern: /AIza[a-zA-Z0-9_-]{35}/g,
    severity: 'high',
    description: 'Google API key found. Depending on restrictions, this may allow unauthorized API usage.',
    fix: 'Restrict the API key in Google Cloud Console to specific domains and APIs.',
    confidence: 'high'
  },
  // GitHub Token
  {
    name: 'GitHub Token',
    service: 'GitHub',
    pattern: /ghp_[a-zA-Z0-9]{36}/g,
    severity: 'critical',
    description: 'GitHub Personal Access Token found. This provides access to your GitHub account and repositories.',
    fix: 'Revoke this token immediately at github.com/settings/tokens and create a new one stored securely.',
    confidence: 'high'
  },
  {
    name: 'GitHub OAuth Token',
    service: 'GitHub',
    pattern: /gho_[a-zA-Z0-9]{36}/g,
    severity: 'critical',
    description: 'GitHub OAuth token found.',
    fix: 'Revoke this token and implement proper OAuth flow server-side.',
    confidence: 'high'
  },
  // Slack tokens
  {
    name: 'Slack Bot Token',
    service: 'Slack',
    pattern: /xoxb-[a-zA-Z0-9-]{24,}/g,
    severity: 'critical',
    description: 'Slack Bot token found. This allows sending messages and accessing workspace data.',
    fix: 'Rotate the token in Slack API settings and store server-side.',
    confidence: 'high'
  },
  // Anthropic
  {
    name: 'Anthropic API Key',
    service: 'Anthropic',
    pattern: /sk-ant-[a-zA-Z0-9-]{32,}/g,
    severity: 'critical',
    description: 'Anthropic (Claude) API key found. Anyone can use your key and charge your account.',
    fix: 'Move to server-side environment variable immediately.',
    confidence: 'high'
  },
  // Database connection strings
  {
    name: 'MongoDB Connection String',
    service: 'MongoDB',
    pattern: /mongodb\+srv:\/\/[^:]+:[^@]+@[^\s"']+/g,
    severity: 'critical',
    description: 'MongoDB connection string with credentials found. Full database access is exposed.',
    fix: 'Never expose database credentials in frontend code. Use a backend API.',
    confidence: 'high'
  },
  {
    name: 'PostgreSQL Connection String',
    service: 'PostgreSQL',
    pattern: /postgres(?:ql)?:\/\/[^:]+:[^@]+@[^\s"']+/g,
    severity: 'critical',
    description: 'PostgreSQL connection string with credentials found.',
    fix: 'Move database access to backend. Frontend should never connect directly to databases.',
    confidence: 'high'
  },
  // Supabase - Note: We can't reliably detect service role vs anon keys by pattern alone
  // The anon key is MEANT to be public. Only flag if we see "service_role" in context.
  // Removing this pattern to avoid false positives on legitimate anon keys.
  // TODO: Add context-aware detection that looks for "service_role" string nearby
  // Firebase (checking for private key patterns)
  {
    name: 'Firebase Private Key',
    service: 'Firebase',
    pattern: /"private_key":\s*"-----BEGIN (?:RSA )?PRIVATE KEY-----/g,
    severity: 'critical',
    description: 'Firebase Admin SDK private key found. This provides full admin access to your Firebase project.',
    fix: 'Never expose service account keys in frontend. Use Firebase client SDK with security rules.',
    confidence: 'high'
  },
  // Twilio
  {
    name: 'Twilio Auth Token',
    service: 'Twilio',
    pattern: /SK[a-f0-9]{32}/g,
    severity: 'high',
    description: 'Possible Twilio API key found.',
    fix: 'Move to server-side and use Twilio Functions or your own backend.',
    confidence: 'medium'
  },
  // SendGrid
  {
    name: 'SendGrid API Key',
    service: 'SendGrid',
    pattern: /SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}/g,
    severity: 'critical',
    description: 'SendGrid API key found. This allows sending emails from your account.',
    fix: 'Move to server-side environment variable.',
    confidence: 'high'
  },
  // Mailgun
  {
    name: 'Mailgun API Key',
    service: 'Mailgun',
    pattern: /key-[a-zA-Z0-9]{32}/g,
    severity: 'critical',
    description: 'Mailgun API key found.',
    fix: 'Move to server-side environment variable.',
    confidence: 'high'
  },
  // Resend (popular with vibe coders)
  {
    name: 'Resend API Key',
    service: 'Resend',
    pattern: /re_[a-zA-Z0-9]{32,}/g,
    severity: 'critical',
    description: 'Resend API key found. Someone could send emails from your account.',
    fix: 'Move to server-side. Use Resend\'s API from your backend, not frontend.',
    confidence: 'high'
  },
  // Clerk (auth service popular with vibe coders)
  // Note: Clerk uses sk_live_/sk_test_ like Stripe, but their keys are longer (40+ chars)
  // and Stripe keys are typically 24-32 chars. We use a minimum of 40 to avoid overlap.
  {
    name: 'Clerk Secret Key',
    service: 'Clerk',
    pattern: /sk_(?:live|test)_[a-zA-Z0-9]{40,}/g,
    severity: 'critical',
    description: 'Clerk secret key found. This gives full access to your auth system.',
    fix: 'Only use Clerk publishable keys (pk_) in frontend. Secret keys go server-side.',
    confidence: 'high'
  },
  // Vercel token
  {
    name: 'Vercel Token',
    service: 'Vercel',
    pattern: /vercel_[a-zA-Z0-9]{24,}/g,
    severity: 'critical',
    description: 'Vercel deployment token found. Could allow unauthorized deployments.',
    fix: 'Rotate this token in Vercel settings immediately.',
    confidence: 'high'
  },
  // Planetscale (popular serverless DB)
  {
    name: 'PlanetScale Connection',
    service: 'PlanetScale',
    pattern: /mysql:\/\/[^:]+:[^@]+@[^\/]*\.psdb\.cloud/g,
    severity: 'critical',
    description: 'PlanetScale database connection string found.',
    fix: 'Move database connections to server-side. Use API routes.',
    confidence: 'high'
  },
  // Neon (serverless Postgres)
  {
    name: 'Neon Database Connection',
    service: 'Neon',
    pattern: /postgres(?:ql)?:\/\/[^:]+:[^@]+@[^\/]*\.neon\.tech/g,
    severity: 'critical',
    description: 'Neon database connection string found.',
    fix: 'Never expose database URLs in frontend. Use server-side API routes.',
    confidence: 'high'
  },
  // Upstash Redis
  {
    name: 'Upstash Redis',
    service: 'Upstash',
    pattern: /rediss?:\/\/[^:]+:[^@]+@[^\/]*\.upstash\.io/g,
    severity: 'critical',
    description: 'Upstash Redis connection string found.',
    fix: 'Use Upstash REST API with read-only tokens for frontend, or move to backend.',
    confidence: 'high'
  },
  // Convex (realtime DB popular with vibe coders)
  // Only match if it looks like a real Convex URL pattern with pipe separator
  {
    name: 'Convex Deploy Key',
    service: 'Convex',
    pattern: /prod:[a-zA-Z0-9]{10,}\|[a-zA-Z0-9]{10,}/g,
    severity: 'high',
    description: 'Possible Convex deploy key found.',
    fix: 'Convex deploy keys should only be in CI/CD, not in frontend code.',
    confidence: 'medium'
  }
];

interface ExposedKey {
  pattern: ApiKeyPattern;
  match: string;
  masked: string;
  location: string;
}

/**
 * Mask a key for safe display (show first 8 and last 4 chars)
 */
function maskKey(key: string): string {
  if (key.length <= 16) {
    return key.substring(0, 4) + '****' + key.substring(key.length - 4);
  }
  return key.substring(0, 8) + '****' + key.substring(key.length - 4);
}

/**
 * Extract JavaScript URLs from HTML
 */
function extractJsUrls(html: string, baseUrl: string): string[] {
  const urls: string[] = [];
  const scriptRegex = /<script[^>]+src=["']([^"']+)["'][^>]*>/gi;
  let match;

  while ((match = scriptRegex.exec(html)) !== null) {
    const src = match[1];
    try {
      // Handle relative and absolute URLs
      const fullUrl = new URL(src, baseUrl).toString();
      // Only include same-origin scripts (more likely to contain app secrets)
      const base = new URL(baseUrl);
      const script = new URL(fullUrl);
      if (script.hostname === base.hostname) {
        urls.push(fullUrl);
      }
    } catch {
      // Invalid URL, skip
    }
  }

  return urls;
}

/**
 * Scan content for API keys
 */
function scanForKeys(content: string, location: string): ExposedKey[] {
  const found: ExposedKey[] = [];

  for (const keyPattern of API_KEY_PATTERNS) {
    // Reset regex lastIndex
    keyPattern.pattern.lastIndex = 0;
    let match;

    while ((match = keyPattern.pattern.exec(content)) !== null) {
      // Avoid duplicates
      const masked = maskKey(match[0]);
      if (!found.some(f => f.masked === masked && f.pattern.name === keyPattern.name)) {
        found.push({
          pattern: keyPattern,
          match: match[0],
          masked,
          location
        });
      }
    }
  }

  return found;
}

export async function checkApiKeys(url: string, timeout: number = 10000): Promise<CheckResult> {
  const issues: SecurityIssue[] = [];
  const allFoundKeys: ExposedKey[] = [];

  try {
    // Fetch main page
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout);

    const response = await fetch(url, {
      method: 'GET',
      signal: controller.signal,
      headers: {
        'User-Agent': 'SecurityScanner/2.0 (Security Audit)'
      }
    });

    clearTimeout(timeoutId);

    if (!response.ok) {
      return {
        name: 'API Key Exposure',
        passed: true,
        issues: [],
        details: { error: `Failed to fetch: ${response.status}` }
      };
    }

    const html = await response.text();

    // Scan inline scripts in HTML
    const inlineScriptRegex = /<script(?![^>]*src=)[^>]*>([\s\S]*?)<\/script>/gi;
    let inlineMatch;
    while ((inlineMatch = inlineScriptRegex.exec(html)) !== null) {
      const scriptContent = inlineMatch[1];
      if (scriptContent.trim()) {
        const found = scanForKeys(scriptContent, 'inline script');
        allFoundKeys.push(...found);
      }
    }

    // Also scan the raw HTML for keys in data attributes, etc.
    const htmlKeys = scanForKeys(html, 'HTML source');
    allFoundKeys.push(...htmlKeys);

    // Extract and fetch external JS files (limit to first 5 for performance)
    const jsUrls = extractJsUrls(html, url).slice(0, 5);

    for (const jsUrl of jsUrls) {
      try {
        const jsController = new AbortController();
        const jsTimeoutId = setTimeout(() => jsController.abort(), 5000);

        const jsResponse = await fetch(jsUrl, {
          method: 'GET',
          signal: jsController.signal,
          headers: {
            'User-Agent': 'SecurityScanner/2.0 (Security Audit)'
          }
        });

        clearTimeout(jsTimeoutId);

        if (jsResponse.ok) {
          const jsContent = await jsResponse.text();
          // Only scan first 500KB of each JS file
          const contentToScan = jsContent.substring(0, 500000);
          const found = scanForKeys(contentToScan, jsUrl);
          allFoundKeys.push(...found);
        }
      } catch {
        // Skip failed JS fetches
      }
    }

    // Convert found keys to issues
    for (const key of allFoundKeys) {
      issues.push({
        id: `apikey-${key.pattern.service.toLowerCase()}-${key.masked.substring(0, 8)}`,
        severity: key.pattern.severity,
        category: 'Exposed Secrets',
        title: `${key.pattern.name} exposed: ${key.masked}`,
        description: key.pattern.description,
        fix: key.pattern.fix
      });
    }

  } catch (error) {
    // Network error or timeout
    return {
      name: 'API Key Exposure',
      passed: true,
      issues: [],
      details: { error: error instanceof Error ? error.message : 'Unknown error' }
    };
  }

  return {
    name: 'API Key Exposure',
    passed: issues.length === 0,
    issues,
    details: {
      keysFound: allFoundKeys.map(k => ({
        service: k.pattern.service,
        masked: k.masked,
        location: k.location,
        confidence: k.pattern.confidence
      }))
    }
  };
}

/**
 * Patterns that suggest client-side permission checks
 * These are RED FLAGS - business logic that should be on the server
 */
const CLIENT_SIDE_PERMISSION_PATTERNS = [
  // Pro/Premium checks
  { pattern: /\b(?:is|has)Pro\b/gi, name: 'isPro' },
  { pattern: /\b(?:is|has)Premium\b/gi, name: 'isPremium' },
  { pattern: /\b(?:is|has)Paid\b/gi, name: 'isPaid' },
  { pattern: /\b(?:is|has)Subscribed\b/gi, name: 'isSubscribed' },
  { pattern: /\bsubscription\s*(?:===?|!==?)\s*['"](?:pro|premium|paid)/gi, name: 'subscription check' },
  { pattern: /\bplan\s*(?:===?|!==?)\s*['"](?:pro|premium|free|paid)/gi, name: 'plan check' },

  // Admin/Role checks
  { pattern: /\b(?:is|has)Admin\b/gi, name: 'isAdmin' },
  { pattern: /\brole\s*(?:===?|!==?)\s*['"]admin['"]/gi, name: 'role === admin' },
  { pattern: /\buserRole\b/gi, name: 'userRole' },
  { pattern: /\b(?:is|has)Moderator\b/gi, name: 'isModerator' },

  // Feature flag checks (could be fine, but worth noting)
  { pattern: /\bcanAccess\w+\b/gi, name: 'canAccess*' },
  { pattern: /\bhasFeature\b/gi, name: 'hasFeature' },
  { pattern: /\bfeatureEnabled\b/gi, name: 'featureEnabled' },
];

interface PermissionPatternMatch {
  name: string;
  location: string;
  context: string;
}

/**
 * Scan for client-side permission patterns in JavaScript
 */
function scanForPermissionPatterns(content: string, location: string): PermissionPatternMatch[] {
  const found: PermissionPatternMatch[] = [];

  for (const { pattern, name } of CLIENT_SIDE_PERMISSION_PATTERNS) {
    pattern.lastIndex = 0;
    const match = pattern.exec(content);
    if (match) {
      // Get surrounding context (30 chars before and after)
      const start = Math.max(0, match.index - 30);
      const end = Math.min(content.length, match.index + match[0].length + 30);
      const context = content.substring(start, end).replace(/\s+/g, ' ').trim();

      // Avoid duplicates
      if (!found.some(f => f.name === name)) {
        found.push({ name, location, context });
      }
    }
  }

  return found;
}

/**
 * Check for client-side permission patterns
 * Returns warnings (not errors) since we can't know for sure if they're vulnerable
 */
export async function checkClientSidePermissions(url: string, htmlContent?: string, timeout: number = 10000): Promise<CheckResult> {
  const issues: SecurityIssue[] = [];
  const allMatches: PermissionPatternMatch[] = [];

  try {
    let html = htmlContent;

    if (!html) {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), timeout);

      const response = await fetch(url, {
        method: 'GET',
        signal: controller.signal,
        headers: { 'User-Agent': 'SecurityScanner/2.0 (Security Audit)' }
      });

      clearTimeout(timeoutId);
      if (!response.ok) {
        return { name: 'Client-Side Permissions', passed: true, issues: [], details: {} };
      }
      html = await response.text();
    }

    // Scan inline scripts
    const inlineScriptRegex = /<script(?![^>]*src=)[^>]*>([\s\S]*?)<\/script>/gi;
    let inlineMatch;
    while ((inlineMatch = inlineScriptRegex.exec(html)) !== null) {
      const scriptContent = inlineMatch[1];
      if (scriptContent.trim()) {
        const found = scanForPermissionPatterns(scriptContent, 'inline script');
        allMatches.push(...found);
      }
    }

    // Extract and scan external JS files (limit to first 3)
    const jsUrls = extractJsUrls(html, url).slice(0, 3);

    for (const jsUrl of jsUrls) {
      try {
        const jsController = new AbortController();
        const jsTimeoutId = setTimeout(() => jsController.abort(), 5000);

        const jsResponse = await fetch(jsUrl, {
          method: 'GET',
          signal: jsController.signal,
          headers: { 'User-Agent': 'SecurityScanner/2.0 (Security Audit)' }
        });

        clearTimeout(jsTimeoutId);

        if (jsResponse.ok) {
          const jsContent = await jsResponse.text();
          const contentToScan = jsContent.substring(0, 300000); // First 300KB
          const found = scanForPermissionPatterns(contentToScan, new URL(jsUrl).pathname);
          allMatches.push(...found);
        }
      } catch {
        // Skip failed fetches
      }
    }

    // If we found concerning patterns, add a warning
    if (allMatches.length > 0) {
      const patternNames = [...new Set(allMatches.map(m => m.name))].slice(0, 5);
      issues.push({
        id: 'clientside-permission-check',
        severity: 'medium',
        category: 'Code Review',
        title: `Possible client-side permission checks found`,
        description: `Found patterns like "${patternNames.join('", "')}" in JavaScript. If these control access to paid features or admin functions, make sure they're ALSO enforced on your server. Client-side checks can be bypassed via browser DevTools.`,
        fix: 'Ensure all permission checks happen on your backend API, not just in frontend JavaScript. The server should verify permissions before returning sensitive data or allowing actions.'
      });
    }

  } catch (error) {
    return {
      name: 'Client-Side Permissions',
      passed: true,
      issues: [],
      details: { error: error instanceof Error ? error.message : 'Unknown error' }
    };
  }

  return {
    name: 'Client-Side Permissions',
    passed: issues.length === 0,
    issues,
    details: {
      patternsFound: allMatches.map(m => ({ name: m.name, location: m.location }))
    }
  };
}
