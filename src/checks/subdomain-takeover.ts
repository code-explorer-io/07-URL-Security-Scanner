import { Resolver } from 'dns/promises';
import { CheckResult, SecurityIssue } from '../types';

// Known vulnerable CNAME patterns and their detection signatures
interface VulnerableService {
  name: string;
  cnamePattern: RegExp;
  // HTTP response patterns that indicate the service is unclaimed
  fingerprints: string[];
  severity: 'critical' | 'high';
}

const VULNERABLE_SERVICES: VulnerableService[] = [
  {
    name: 'AWS S3',
    cnamePattern: /\.s3[.-].*\.amazonaws\.com$/i,
    fingerprints: ['NoSuchBucket', 'The specified bucket does not exist'],
    severity: 'critical'
  },
  {
    name: 'GitHub Pages',
    cnamePattern: /\.github\.io$/i,
    fingerprints: ['There isn\'t a GitHub Pages site here', 'For root URLs'],
    severity: 'critical'
  },
  {
    name: 'Heroku',
    cnamePattern: /\.herokuapp\.com$/i,
    fingerprints: ['No such app', 'herokucdn.com/error-pages/no-such-app'],
    severity: 'critical'
  },
  {
    name: 'Azure',
    cnamePattern: /\.azurewebsites\.net$/i,
    fingerprints: ['404 Web Site not found', 'Microsoft Azure App Service'],
    severity: 'critical'
  },
  {
    name: 'Netlify',
    cnamePattern: /\.netlify\.app$/i,
    fingerprints: ['Not Found - Request ID'],
    severity: 'high'
  },
  {
    name: 'Vercel',
    cnamePattern: /\.vercel\.app$/i,
    fingerprints: ['The deployment you are trying to access'],
    severity: 'high'
  },
  {
    name: 'Cloudfront',
    cnamePattern: /\.cloudfront\.net$/i,
    fingerprints: ['The request could not be satisfied', 'ERROR: The request could not be satisfied'],
    severity: 'high'
  },
  {
    name: 'Fastly',
    cnamePattern: /\.fastly\.net$/i,
    fingerprints: ['Fastly error: unknown domain'],
    severity: 'high'
  },
  {
    name: 'Pantheon',
    cnamePattern: /\.pantheonsite\.io$/i,
    fingerprints: ['The gods are wise', '404 error unknown site'],
    severity: 'high'
  },
  {
    name: 'Tumblr',
    cnamePattern: /\.tumblr\.com$/i,
    fingerprints: ['There\'s nothing here', 'Whatever you were looking for doesn\'t currently exist'],
    severity: 'high'
  },
  {
    name: 'Shopify',
    cnamePattern: /\.myshopify\.com$/i,
    fingerprints: ['Sorry, this shop is currently unavailable'],
    severity: 'high'
  },
  {
    name: 'Surge.sh',
    cnamePattern: /\.surge\.sh$/i,
    fingerprints: ['project not found'],
    severity: 'high'
  },
  {
    name: 'UserVoice',
    cnamePattern: /\.uservoice\.com$/i,
    fingerprints: ['This UserVoice subdomain is currently available'],
    severity: 'high'
  },
  {
    name: 'Ghost',
    cnamePattern: /\.ghost\.io$/i,
    fingerprints: ['The thing you were looking for is no longer here'],
    severity: 'high'
  },
  {
    name: 'Cargo',
    cnamePattern: /\.cargo\.site$/i,
    fingerprints: ['<title>404 — File not found</title>'],
    severity: 'high'
  },
  {
    name: 'Fly.io',
    cnamePattern: /\.fly\.dev$/i,
    fingerprints: ['Could not resolve host'],
    severity: 'high'
  },
  {
    name: 'Railway',
    cnamePattern: /\.railway\.app$/i,
    fingerprints: ['Application not found'],
    severity: 'high'
  },
  {
    name: 'Render',
    cnamePattern: /\.onrender\.com$/i,
    fingerprints: ['Not Found'],
    severity: 'high'
  }
];

interface SubdomainTakeoverResult {
  subdomain: string;
  cname: string;
  service: string;
  vulnerable: boolean;
  severity: 'critical' | 'high';
  evidence?: string;
}

/**
 * Check if a subdomain has a dangling CNAME pointing to a vulnerable service
 */
async function checkSubdomainTakeover(subdomain: string): Promise<SubdomainTakeoverResult | null> {
  const resolver = new Resolver();
  resolver.setServers(['8.8.8.8', '1.1.1.1']);

  try {
    // First, try to resolve CNAME
    const cnames = await resolver.resolveCname(subdomain);
    if (!cnames || cnames.length === 0) {
      return null;
    }

    const cname = cnames[0].toLowerCase();

    // Check if CNAME matches any vulnerable service
    for (const service of VULNERABLE_SERVICES) {
      if (service.cnamePattern.test(cname)) {
        // Found a potentially vulnerable CNAME, verify by checking HTTP response
        const isVulnerable = await checkHttpFingerprint(subdomain, service.fingerprints);

        if (isVulnerable.vulnerable) {
          return {
            subdomain,
            cname,
            service: service.name,
            vulnerable: true,
            severity: service.severity,
            evidence: isVulnerable.evidence
          };
        }

        // Has CNAME but not vulnerable (service is claimed)
        return {
          subdomain,
          cname,
          service: service.name,
          vulnerable: false,
          severity: service.severity
        };
      }
    }

    return null;
  } catch (error) {
    // NXDOMAIN or lookup failure - might indicate a takeover opportunity if CNAME exists at parent
    // But we can't reliably detect this without the CNAME, so skip
    return null;
  }
}

/**
 * Check if HTTP response contains vulnerability fingerprints
 */
async function checkHttpFingerprint(
  subdomain: string,
  fingerprints: string[]
): Promise<{ vulnerable: boolean; evidence?: string }> {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5000);

    // Try HTTPS first, then HTTP
    for (const protocol of ['https', 'http']) {
      try {
        const response = await fetch(`${protocol}://${subdomain}`, {
          method: 'GET',
          signal: controller.signal,
          headers: {
            'User-Agent': 'SecurityScanner/2.0 (Subdomain Takeover Check)'
          },
          redirect: 'follow'
        });

        const body = await response.text();
        clearTimeout(timeoutId);

        // Check for vulnerability fingerprints
        for (const fingerprint of fingerprints) {
          if (body.includes(fingerprint)) {
            return { vulnerable: true, evidence: fingerprint };
          }
        }

        // Got a response, service is claimed
        return { vulnerable: false };
      } catch {
        // Connection failed, try next protocol
        continue;
      }
    }

    clearTimeout(timeoutId);
    return { vulnerable: false };
  } catch {
    return { vulnerable: false };
  }
}

/**
 * Check multiple subdomains for takeover vulnerabilities
 * @param subdomains Array of subdomains to check (from crt.sh)
 * @param maxChecks Maximum number of subdomains to check (default 10)
 */
export async function checkSubdomainTakeovers(
  subdomains: string[],
  maxChecks: number = 10
): Promise<CheckResult> {
  const issues: SecurityIssue[] = [];
  const results: SubdomainTakeoverResult[] = [];

  // Limit checks for performance
  const toCheck = subdomains.slice(0, maxChecks);

  // Run checks in parallel with concurrency limit
  const concurrency = 3;
  const batches = [];
  for (let i = 0; i < toCheck.length; i += concurrency) {
    batches.push(toCheck.slice(i, i + concurrency));
  }

  for (const batch of batches) {
    const batchResults = await Promise.all(
      batch.map(subdomain => checkSubdomainTakeover(subdomain))
    );

    for (const result of batchResults) {
      if (result) {
        results.push(result);

        if (result.vulnerable) {
          issues.push({
            id: `subdomain-takeover-${result.subdomain.replace(/\./g, '-')}`,
            severity: result.severity,
            category: 'Subdomain Security',
            title: `Subdomain takeover possible: ${result.subdomain}`,
            description: `The subdomain "${result.subdomain}" has a CNAME pointing to ${result.service} (${result.cname}), but the service appears unclaimed. An attacker could register this on ${result.service} and serve malicious content from your domain.`,
            fix: `Either claim the ${result.service} resource or remove the CNAME record from your DNS. If the service is no longer needed, delete the DNS record.`
          });
        }
      }
    }
  }

  return {
    name: 'Subdomain Takeover',
    passed: issues.length === 0,
    issues,
    details: {
      checkedCount: toCheck.length,
      totalSubdomains: subdomains.length,
      results: results.filter(r => r.vulnerable).map(r => ({
        subdomain: r.subdomain,
        cname: r.cname,
        service: r.service,
        evidence: r.evidence
      }))
    }
  };
}
