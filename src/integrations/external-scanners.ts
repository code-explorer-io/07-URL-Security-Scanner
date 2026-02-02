/**
 * External Scanner Integrations
 *
 * Second-level validation by cross-checking with trusted external tools.
 * All tools here are FREE and don't require payment.
 */

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
        }
      }
    );

    if (!response.ok) {
      console.error(`Observatory API error: ${response.status}`);
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
 * SSL Labs API v4 - Deep SSL/TLS analysis
 *
 * Note: Requires one-time registration (free)
 * Rate limit: Scans take 60+ seconds, intentionally slow
 *
 * This function only STARTS a scan. SSL Labs scans are async
 * and can take several minutes to complete.
 *
 * @see https://www.ssllabs.com/projects/ssllabs-apis/
 */
export async function startSslLabsScan(
  hostname: string,
  email?: string
): Promise<{ started: boolean; message: string; pollUrl?: string }> {
  // SSL Labs v4 requires registration. For now, we'll just return
  // a link to the web interface for manual checking.

  if (!email) {
    return {
      started: false,
      message: 'SSL Labs API v4 requires registration. Manual check available.',
      pollUrl: `https://www.ssllabs.com/ssltest/analyze.html?d=${encodeURIComponent(hostname)}`
    };
  }

  // TODO: Implement full API v4 integration when we have registration flow
  // API endpoint: https://api.ssllabs.com/api/v4/analyze
  // Requires: email header for registered users

  return {
    started: false,
    message: 'Full SSL Labs API integration coming soon',
    pollUrl: `https://www.ssllabs.com/ssltest/analyze.html?d=${encodeURIComponent(hostname)}`
  };
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
    techStack?: string[];
    verbose?: boolean;
  } = {}
): Promise<{
  results: ExternalScanResult[];
  links: { name: string; url: string }[];
  nucleiAvailable?: boolean;
}> {
  const { observatory = true, nuclei = false, techStack = [], verbose = false } = options;
  const results: ExternalScanResult[] = [];
  const links: { name: string; url: string }[] = [];
  let nucleiAvailable: boolean | undefined;

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

  // Run Observatory scan if enabled
  if (observatory) {
    if (verbose) console.log('  Running Mozilla Observatory scan...');
    const observatoryResult = await scanWithObservatory(hostname);
    if (observatoryResult) {
      results.push(observatoryResult);
      if (verbose) {
        console.log(`    Grade: ${observatoryResult.grade} (${observatoryResult.score}/100)`);
      }
    }
  }

  // Run Nuclei scan if enabled (requires local installation)
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

  return { results, links, nucleiAvailable };
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
