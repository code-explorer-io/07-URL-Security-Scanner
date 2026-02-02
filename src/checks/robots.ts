import { CheckResult, SecurityIssue } from '../types';

interface RobotsDetails {
  exists: boolean;
  content?: string;
  disallowedPaths: string[];
  sitemaps: string[];
  sensitivePathsFound: string[];
}

// Patterns that might indicate sensitive paths in robots.txt
const SENSITIVE_PATTERNS = [
  /admin/i,
  /login/i,
  /dashboard/i,
  /api/i,
  /private/i,
  /secret/i,
  /backup/i,
  /\.env/i,
  /config/i,
  /database/i,
  /db/i,
  /internal/i,
  /staging/i,
  /dev/i,
  /test/i,
  /tmp/i,
  /temp/i,
  /upload/i,
  /files/i,
  /assets\/private/i,
  /\.git/i,
  /\.svn/i,
  /cgi-bin/i,
  /wp-includes/i,
  /wp-content\/uploads/i,
  /user/i,
  /account/i,
  /member/i,
  /payment/i,
  /checkout/i,
  /order/i,
  /invoice/i
];

export async function checkRobots(baseUrl: string, timeout: number = 5000): Promise<CheckResult> {
  const issues: SecurityIssue[] = [];
  const details: RobotsDetails = {
    exists: false,
    disallowedPaths: [],
    sitemaps: [],
    sensitivePathsFound: []
  };

  try {
    const robotsUrl = new URL('/robots.txt', baseUrl).toString();
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout);

    const response = await fetch(robotsUrl, {
      signal: controller.signal,
      headers: {
        'User-Agent': 'SecurityScanner/1.0 (Security Audit)'
      }
    });

    clearTimeout(timeoutId);

    if (response.status === 200) {
      const content = await response.text();
      details.exists = true;
      details.content = content;

      // Parse robots.txt
      const lines = content.split('\n');

      for (const line of lines) {
        const trimmed = line.trim();

        // Extract Disallow paths
        if (trimmed.toLowerCase().startsWith('disallow:')) {
          const path = trimmed.substring(9).trim();
          if (path && path !== '/') {
            details.disallowedPaths.push(path);

            // Check if this reveals sensitive paths
            for (const pattern of SENSITIVE_PATTERNS) {
              if (pattern.test(path)) {
                if (!details.sensitivePathsFound.includes(path)) {
                  details.sensitivePathsFound.push(path);
                }
                break;
              }
            }
          }
        }

        // Extract sitemaps
        if (trimmed.toLowerCase().startsWith('sitemap:')) {
          const sitemap = trimmed.substring(8).trim();
          if (sitemap) {
            details.sitemaps.push(sitemap);
          }
        }
      }

      // Report sensitive paths found
      if (details.sensitivePathsFound.length > 0) {
        issues.push({
          id: 'robots-sensitive-paths',
          severity: 'low',
          category: 'Information Disclosure',
          title: 'robots.txt reveals potentially sensitive paths',
          description: `Found ${details.sensitivePathsFound.length} potentially sensitive paths: ${details.sensitivePathsFound.slice(0, 5).join(', ')}${details.sensitivePathsFound.length > 5 ? '...' : ''}`,
          fix: 'While hiding paths in robots.txt is not a security measure, be aware that this reveals your directory structure to attackers. Ensure these paths are properly secured.',
          evidence: {
            query: 'HTTP GET /robots.txt',
            response: `Disallowed paths found: ${details.sensitivePathsFound.slice(0, 3).join(', ')}${details.sensitivePathsFound.length > 3 ? '...' : ''}`,
            verifyCommand: 'curl <url>/robots.txt'
          }
        });
      }

      // Check for disallow all (might be intentional but worth noting)
      if (details.disallowedPaths.includes('/') || content.includes('Disallow: /\n')) {
        issues.push({
          id: 'robots-disallow-all',
          severity: 'info',
          category: 'Information Disclosure',
          title: 'robots.txt blocks all crawlers',
          description: 'The site blocks all search engine crawlers. This may affect SEO.',
          fix: 'If this is intentional, no action needed. Otherwise, update robots.txt to allow search engines.',
          evidence: {
            query: 'HTTP GET /robots.txt',
            response: 'Contains "Disallow: /" - blocking all crawlers',
            verifyCommand: 'curl <url>/robots.txt'
          }
        });
      }
    }
  } catch {
    // robots.txt not found or error - not necessarily an issue
  }

  return {
    name: 'Robots.txt Analysis',
    passed: issues.filter(i => i.severity !== 'info' && i.severity !== 'low').length === 0,
    issues,
    details
  };
}
