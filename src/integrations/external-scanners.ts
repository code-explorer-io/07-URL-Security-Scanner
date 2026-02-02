/**
 * External Scanner Integrations
 *
 * Second-level validation by cross-checking with trusted external tools.
 * All tools here are FREE and don't require payment.
 */

import { checkSubdomainTakeovers } from '../checks/subdomain-takeover';
import { CheckResult } from '../types';

export interface ExternalScanResult {
  source: string;
  grade?: string;
  score?: number;
  passed: boolean;
  details: Record<string, unknown>;
  url?: string;
}

interface ObservatoryResponse {
  id?: string;
  grade?: string;
  score?: number;
  tests_passed?: number;
  tests_failed?: number;
  tests_quantity?: number;
}

/**
 * Mozilla Observatory - Industry-standard security header grading
 *
 * API: https://observatory-api.mdn.mozilla.net/api/v2/scan
 * Rate limit: 1 scan per minute per host
 * No registration required
 *
 * @see https://developer.mozilla.org/en-US/observatory
 */
export async function scanWithObservatory(hostname: string): Promise<ExternalScanResult | null> {
  try {
    const response = await fetch(
      `https://observatory-api.mdn.mozilla.net/api/v2/scan?host=${encodeURIComponent(hostname)}`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: '{}' // API requires a JSON body, even if empty
      }
    );

    if (!response.ok) {
      const errorText = await response.text().catch(() => 'Unknown');
      console.error(`   Observatory API error: ${response.status} - ${errorText.slice(0, 100)}`);
      return null;
    }

    const data = await response.json() as ObservatoryResponse;

    return {
      source: 'Mozilla Observatory',
      grade: data.grade || undefined,
      score: data.score || undefined,
      passed: data.grade ? ['A+', 'A', 'A-', 'B+', 'B'].includes(data.grade) : false,
      details: {
        testsPassed: data.tests_passed,
        testsFailed: data.tests_failed,
        testsQuantity: data.tests_quantity,
        scanId: data.id
      },
      url: `https://developer.mozilla.org/en-US/observatory/analyze?host=${hostname}`
    };
  } catch (error) {
    console.error('Observatory scan failed:', error instanceof Error ? error.message : 'Unknown error');
    return null;
  }
}

/**
 * SSL Labs API v3 - Deep SSL/TLS analysis (FREE, no registration)
 *
 * API: https://api.ssllabs.com/api/v3/analyze
 * Rate limit: Max 25 assessments per rolling 24 hours, 1 concurrent
 * Scans take 60-120 seconds, but we can check for cached results
 *
 * Strategy: First check cache (fromCache=on), if not found return link
 *
 * @see https://github.com/ssllabs/ssllabs-scan/blob/master/ssllabs-api-docs-v3.md
 */
interface SslLabsResponse {
  host: string;
  port: number;
  protocol: string;
  status: 'DNS' | 'ERROR' | 'IN_PROGRESS' | 'READY';
  statusMessage?: string;
  endpoints?: Array<{
    ipAddress: string;
    grade?: string;
    gradeTrustIgnored?: string;
    hasWarnings?: boolean;
    isExceptional?: boolean;
    progress?: number;
    statusMessage?: string;
  }>;
}

export async function scanSslLabs(hostname: string): Promise<ExternalScanResult | null> {
  try {
    // First, try to get cached results (fast)
    const cacheUrl = `https://api.ssllabs.com/api/v3/analyze?host=${encodeURIComponent(hostname)}&fromCache=on&maxAge=24`;

    const response = await fetch(cacheUrl, {
      headers: {
        'Accept': 'application/json',
        'User-Agent': 'URLSecurityScanner/2.0'
      }
    });

    if (!response.ok) {
      return null;
    }

    const data = await response.json() as SslLabsResponse;

    // If no cached result or scan in progress, just return the link
    if (data.status !== 'READY' || !data.endpoints || data.endpoints.length === 0) {
      return {
        source: 'SSL Labs',
        passed: true, // Unknown, so don't fail
        details: {
          status: data.status,
          message: data.status === 'IN_PROGRESS' ? 'Scan in progress' : 'No cached result available',
          suggestion: 'Check the full report link for detailed TLS analysis'
        },
        url: `https://www.ssllabs.com/ssltest/analyze.html?d=${encodeURIComponent(hostname)}`
      };
    }

    // Get the best grade from all endpoints
    const grades = data.endpoints
      .map(e => e.grade)
      .filter((g): g is string => g !== undefined);

    const bestGrade = grades.sort()[0] || 'Unknown';
    const hasWarnings = data.endpoints.some(e => e.hasWarnings);

    // Grade A/A+ is good, B is acceptable, C and below needs attention
    const passed = ['A+', 'A', 'A-', 'B'].includes(bestGrade);

    return {
      source: 'SSL Labs',
      grade: bestGrade,
      passed,
      details: {
        grade: bestGrade,
        endpoints: data.endpoints.length,
        hasWarnings,
        grades: grades.join(', ')
      },
      url: `https://www.ssllabs.com/ssltest/analyze.html?d=${encodeURIComponent(hostname)}`
    };
  } catch (error) {
    console.error('SSL Labs scan failed:', error instanceof Error ? error.message : 'Unknown error');
    return null;
  }
}

/**
 * SecurityHeaders.com - Quick header analysis
 *
 * Note: API requires paid subscription
 * For now, we just generate a link to the free web checker
 */
export function getSecurityHeadersUrl(hostname: string): string {
  return `https://securityheaders.com/?q=${encodeURIComponent(hostname)}&followRedirects=on`;
}

/**
 * crt.sh - Certificate Transparency Logs
 *
 * API: https://crt.sh/?q=<domain>&output=json
 * No registration required, no rate limits mentioned
 * Finds all SSL certificates issued for a domain (useful for subdomain discovery)
 *
 * @see https://crt.sh
 */
interface CrtShEntry {
  issuer_ca_id: number;
  issuer_name: string;
  common_name: string;
  name_value: string;
  not_before: string;
  not_after: string;
}

export async function scanCertificateTransparency(hostname: string): Promise<ExternalScanResult | null> {
  try {
    // Remove www. prefix for broader search
    const baseDomain = hostname.replace(/^www\./, '');

    const response = await fetch(
      `https://crt.sh/?q=${encodeURIComponent(baseDomain)}&output=json`,
      {
        headers: {
          'Accept': 'application/json',
          'User-Agent': 'URLSecurityScanner/2.0'
        }
      }
    );

    if (!response.ok) {
      return null;
    }

    const data = await response.json() as CrtShEntry[];

    // Extract unique subdomains from certificates
    const subdomains = new Set<string>();
    const wildcards = new Set<string>();

    for (const entry of data) {
      const names = entry.name_value.split('\n');
      for (const name of names) {
        const cleanName = name.trim().toLowerCase();
        if (cleanName.startsWith('*.')) {
          wildcards.add(cleanName);
        } else if (cleanName.includes(baseDomain)) {
          subdomains.add(cleanName);
        }
      }
    }

    return {
      source: 'Certificate Transparency (crt.sh)',
      passed: true, // This is informational, not pass/fail
      details: {
        certificatesFound: data.length,
        uniqueSubdomains: Array.from(subdomains).slice(0, 20), // Limit for readability
        wildcardCerts: Array.from(wildcards),
        totalSubdomains: subdomains.size
      },
      url: `https://crt.sh/?q=${encodeURIComponent(baseDomain)}`
    };
  } catch (error) {
    console.error('crt.sh scan failed:', error instanceof Error ? error.message : 'Unknown error');
    return null;
  }
}

/**
 * URLScan.io - URL analysis and screenshot
 *
 * API: https://urlscan.io/api/v1/scan/
 * Free tier: 50 scans/day (public), 5000 lookups/day
 * Returns verdicts on malicious/suspicious content
 *
 * Note: Scans are async - we submit and get a result URL
 * For speed, we just check if domain has been scanned recently
 *
 * @see https://urlscan.io/docs/api/
 */
interface UrlScanSearchResult {
  results: Array<{
    task: { url: string; time: string };
    page: { url: string; domain: string };
    result: string;
    verdicts?: {
      overall: { malicious: boolean; score: number };
    };
  }>;
}

export async function searchUrlScan(hostname: string): Promise<ExternalScanResult | null> {
  try {
    // Search for recent scans of this domain (no API key needed for search)
    const response = await fetch(
      `https://urlscan.io/api/v1/search/?q=domain:${encodeURIComponent(hostname)}&size=5`,
      {
        headers: {
          'Accept': 'application/json'
        }
      }
    );

    if (!response.ok) {
      return null;
    }

    const data = await response.json() as UrlScanSearchResult;

    if (data.results.length === 0) {
      return {
        source: 'URLScan.io',
        passed: true,
        details: {
          message: 'No previous scans found',
          suggestion: 'Submit for analysis at urlscan.io'
        },
        url: `https://urlscan.io/search/#domain:${hostname}`
      };
    }

    // Check most recent scan result
    const latestScan = data.results[0];
    const isMalicious = latestScan.verdicts?.overall?.malicious ?? false;

    return {
      source: 'URLScan.io',
      passed: !isMalicious,
      score: latestScan.verdicts?.overall?.score,
      details: {
        lastScanned: latestScan.task.time,
        malicious: isMalicious,
        scanCount: data.results.length,
        latestResultUrl: latestScan.result
      },
      url: latestScan.result || `https://urlscan.io/search/#domain:${hostname}`
    };
  } catch (error) {
    console.error('URLScan.io search failed:', error instanceof Error ? error.message : 'Unknown error');
    return null;
  }
}

/**
 * Google PageSpeed Insights - Performance and security best practices
 *
 * API: https://www.googleapis.com/pagespeedonline/v5/runPagespeed
 * Free, no API key required (but rate limited without one)
 * Includes security best practices in the audit
 *
 * @see https://developers.google.com/speed/docs/insights/v5/get-started
 */
interface PageSpeedResult {
  lighthouseResult?: {
    categories?: {
      'best-practices'?: { score: number };
      performance?: { score: number };
    };
    audits?: {
      'is-on-https'?: { score: number };
      'uses-http2'?: { score: number };
      'no-vulnerable-libraries'?: { score: number; details?: { items?: Array<{ highestSeverity: string }> } };
      'csp-xss'?: { score: number };
      'valid-source-maps'?: { score: number };
    };
  };
}

export async function scanPageSpeed(hostname: string): Promise<ExternalScanResult | null> {
  try {
    const url = `https://${hostname}`;
    const apiUrl = `https://www.googleapis.com/pagespeedonline/v5/runPagespeed?url=${encodeURIComponent(url)}&category=best-practices&strategy=desktop`;

    const response = await fetch(apiUrl, {
      headers: {
        'Accept': 'application/json'
      }
    });

    if (!response.ok) {
      return null;
    }

    const data = await response.json() as PageSpeedResult;
    const lighthouse = data.lighthouseResult;

    if (!lighthouse?.categories) {
      return null;
    }

    const bestPracticesScore = lighthouse.categories['best-practices']?.score ?? 0;
    const audits = lighthouse.audits || {};

    // Check security-related audits
    const securityIssues: string[] = [];

    if (audits['is-on-https']?.score === 0) {
      securityIssues.push('Not using HTTPS');
    }
    if (audits['no-vulnerable-libraries']?.score === 0) {
      const vulnLibs = audits['no-vulnerable-libraries']?.details?.items?.length ?? 0;
      securityIssues.push(`${vulnLibs} vulnerable JavaScript libraries`);
    }
    if (audits['csp-xss']?.score === 0) {
      securityIssues.push('CSP not effective against XSS');
    }

    return {
      source: 'Google PageSpeed',
      score: Math.round(bestPracticesScore * 100),
      passed: bestPracticesScore >= 0.8 && securityIssues.length === 0,
      details: {
        bestPracticesScore: Math.round(bestPracticesScore * 100),
        httpsEnabled: audits['is-on-https']?.score === 1,
        http2Enabled: audits['uses-http2']?.score === 1,
        vulnerableLibraries: audits['no-vulnerable-libraries']?.score !== 1,
        securityIssues: securityIssues.length > 0 ? securityIssues : undefined
      },
      url: `https://pagespeed.web.dev/analysis?url=${encodeURIComponent(url)}`
    };
  } catch (error) {
    console.error('PageSpeed scan failed:', error instanceof Error ? error.message : 'Unknown error');
    return null;
  }
}

/**
 * VirusTotal - Malware/phishing detection
 *
 * Note: API requires free registration and API key
 * For now, we generate a link to the web interface
 *
 * @see https://www.virustotal.com
 */
export function getVirusTotalUrl(hostname: string): string {
  return `https://www.virustotal.com/gui/domain/${encodeURIComponent(hostname)}`;
}

/**
 * Shodan - Internet-wide scanning database
 *
 * Note: API requires registration
 * For now, we generate a link to search results
 *
 * @see https://www.shodan.io
 */
export function getShodanUrl(hostname: string): string {
  return `https://www.shodan.io/host/${encodeURIComponent(hostname)}`;
}

/**
 * Run all available external scans
 *
 * Returns results from all free, no-registration-required scanners
 */
export async function runExternalScans(
  hostname: string,
  options: {
    observatory?: boolean;
    sslLabs?: boolean;
    nuclei?: boolean;
    crtsh?: boolean;
    urlscan?: boolean;
    pagespeed?: boolean;
    subdomainTakeover?: boolean;
    techStack?: string[];
    verbose?: boolean;
  } = {}
): Promise<{
  results: ExternalScanResult[];
  links: { name: string; url: string }[];
  nucleiAvailable?: boolean;
  subdomainTakeoverResult?: CheckResult;
}> {
  const {
    observatory = true,
    sslLabs = true, // Check SSL Labs cache (fast if cached)
    nuclei = false,
    crtsh = true,
    urlscan = true,
    pagespeed = false, // Disabled by default as it's slow (~10s)
    subdomainTakeover = true, // Check for subdomain takeover using crt.sh data
    verbose = false
  } = options;
  const results: ExternalScanResult[] = [];
  const links: { name: string; url: string }[] = [];
  let nucleiAvailable: boolean | undefined;
  let subdomainTakeoverResult: CheckResult | undefined;
  let discoveredSubdomains: string[] = [];

  // Always add manual check links
  links.push({
    name: 'SecurityHeaders.com',
    url: getSecurityHeadersUrl(hostname)
  });
  links.push({
    name: 'SSL Labs',
    url: `https://www.ssllabs.com/ssltest/analyze.html?d=${hostname}`
  });
  links.push({
    name: 'Mozilla Observatory',
    url: `https://developer.mozilla.org/en-US/observatory/analyze?host=${hostname}`
  });
  links.push({
    name: 'VirusTotal',
    url: getVirusTotalUrl(hostname)
  });
  links.push({
    name: 'Shodan',
    url: getShodanUrl(hostname)
  });
  links.push({
    name: 'Certificate Transparency',
    url: `https://crt.sh/?q=${hostname.replace(/^www\./, '')}`
  });
  links.push({
    name: 'URLScan.io',
    url: `https://urlscan.io/search/#domain:${hostname}`
  });

  // Run scans in parallel for speed
  const scanPromises: Promise<void>[] = [];

  // Run Observatory scan if enabled
  if (observatory) {
    scanPromises.push((async () => {
      if (verbose) console.log('  Running Mozilla Observatory scan...');
      const observatoryResult = await scanWithObservatory(hostname);
      if (observatoryResult) {
        results.push(observatoryResult);
        if (verbose) {
          console.log(`    Observatory: Grade ${observatoryResult.grade} (${observatoryResult.score}/100)`);
        }
      }
    })());
  }

  // Run crt.sh scan if enabled
  if (crtsh) {
    scanPromises.push((async () => {
      if (verbose) console.log('  Running Certificate Transparency scan...');
      const crtResult = await scanCertificateTransparency(hostname);
      if (crtResult) {
        results.push(crtResult);
        // Store subdomains for takeover checks
        const details = crtResult.details as { uniqueSubdomains?: string[]; totalSubdomains?: number };
        discoveredSubdomains = details.uniqueSubdomains || [];
        if (verbose) {
          console.log(`    crt.sh: Found ${details.totalSubdomains || 0} subdomains`);
        }
      }
    })());
  }

  // Run URLScan.io search if enabled
  if (urlscan) {
    scanPromises.push((async () => {
      if (verbose) console.log('  Searching URLScan.io history...');
      const urlscanResult = await searchUrlScan(hostname);
      if (urlscanResult) {
        results.push(urlscanResult);
        if (verbose) {
          const details = urlscanResult.details as { malicious?: boolean };
          console.log(`    URLScan.io: ${details.malicious ? 'MALICIOUS DETECTED!' : 'No threats found'}`);
        }
      }
    })());
  }

  // Run PageSpeed if enabled (slow, ~10s)
  if (pagespeed) {
    scanPromises.push((async () => {
      if (verbose) console.log('  Running Google PageSpeed analysis...');
      const pageSpeedResult = await scanPageSpeed(hostname);
      if (pageSpeedResult) {
        results.push(pageSpeedResult);
        if (verbose) {
          console.log(`    PageSpeed: Best Practices ${pageSpeedResult.score}/100`);
        }
      }
    })());
  }

  // Run SSL Labs scan if enabled (checks cache first - fast if cached)
  if (sslLabs) {
    scanPromises.push((async () => {
      if (verbose) console.log('  Checking SSL Labs cache...');
      const sslLabsResult = await scanSslLabs(hostname);
      if (sslLabsResult) {
        results.push(sslLabsResult);
        if (verbose) {
          const grade = sslLabsResult.grade || 'N/A';
          console.log(`    SSL Labs: Grade ${grade}`);
        }
      }
    })());
  }

  // Wait for all parallel scans to complete
  await Promise.all(scanPromises);

  // Run subdomain takeover check if enabled and we have subdomains from crt.sh
  if (subdomainTakeover && discoveredSubdomains.length > 0) {
    if (verbose) console.log(`  Checking ${Math.min(discoveredSubdomains.length, 10)} subdomains for takeover vulnerabilities...`);
    try {
      subdomainTakeoverResult = await checkSubdomainTakeovers(discoveredSubdomains, 10);
      if (subdomainTakeoverResult.issues.length > 0) {
        if (verbose) {
          console.log(`    ⚠️ Found ${subdomainTakeoverResult.issues.length} potential subdomain takeover(s)!`);
        }
      } else if (verbose) {
        console.log('    No subdomain takeover vulnerabilities found');
      }
    } catch (error) {
      if (verbose) {
        console.log(`    Subdomain takeover check error: ${error instanceof Error ? error.message : 'Unknown'}`);
      }
    }
  }

  // Run Nuclei scan if enabled (requires local installation) - sequential as it's heavy
  if (nuclei) {
    try {
      const { isNucleiAvailable, quickNucleiScan } = await import('./nuclei');
      const { available, version } = await isNucleiAvailable();
      nucleiAvailable = available;

      if (available) {
        if (verbose) console.log(`  Running Nuclei scan (v${version})...`);
        const nucleiResult = await quickNucleiScan(`https://${hostname}`, verbose);

        if (nucleiResult.findings.length > 0) {
          results.push({
            source: 'Nuclei',
            passed: false,
            details: {
              findings: nucleiResult.findings,
              duration: nucleiResult.duration
            }
          });
          if (verbose) {
            console.log(`    Found ${nucleiResult.findings.length} issues`);
          }
        } else {
          results.push({
            source: 'Nuclei',
            passed: true,
            details: {
              message: 'No vulnerabilities found',
              duration: nucleiResult.duration
            }
          });
          if (verbose) console.log('    No issues found');
        }
      } else if (verbose) {
        console.log('  Nuclei not installed, skipping...');
      }
    } catch (error) {
      if (verbose) {
        console.log(`  Nuclei error: ${error instanceof Error ? error.message : 'Unknown'}`);
      }
    }
  }

  return { results, links, nucleiAvailable, subdomainTakeoverResult };
}

/**
 * Compare our scan results with external scanner results
 *
 * Returns a confidence assessment of our findings
 */
export function compareResults(
  ourGrade: string,
  ourScore: number,
  externalResults: ExternalScanResult[]
): {
  agreement: 'strong' | 'moderate' | 'weak' | 'no-data';
  summary: string;
  details: string[];
} {
  if (externalResults.length === 0) {
    return {
      agreement: 'no-data',
      summary: 'No external validation available',
      details: []
    };
  }

  const details: string[] = [];
  let agreementScore = 0;
  let totalChecks = 0;

  for (const result of externalResults) {
    if (result.grade) {
      totalChecks++;
      const ourGradeValue = gradeToValue(ourGrade);
      const theirGradeValue = gradeToValue(result.grade);
      const diff = Math.abs(ourGradeValue - theirGradeValue);

      if (diff <= 1) {
        agreementScore++;
        details.push(`${result.source}: ${result.grade} (matches our ${ourGrade})`);
      } else {
        details.push(`${result.source}: ${result.grade} (differs from our ${ourGrade})`);
      }
    }
  }

  if (totalChecks === 0) {
    return {
      agreement: 'no-data',
      summary: 'External scanners returned no grades',
      details
    };
  }

  const ratio = agreementScore / totalChecks;
  let agreement: 'strong' | 'moderate' | 'weak';
  let summary: string;

  if (ratio >= 0.8) {
    agreement = 'strong';
    summary = 'Our findings are validated by external scanners';
  } else if (ratio >= 0.5) {
    agreement = 'moderate';
    summary = 'Partial agreement with external scanners';
  } else {
    agreement = 'weak';
    summary = 'External scanners show different results - review recommended';
  }

  return { agreement, summary, details };
}

function gradeToValue(grade: string): number {
  const grades: Record<string, number> = {
    'A+': 10, 'A': 9, 'A-': 8,
    'B+': 7, 'B': 6, 'B-': 5,
    'C+': 4, 'C': 3, 'C-': 2,
    'D': 1, 'F': 0
  };
  return grades[grade] ?? 5;
}
