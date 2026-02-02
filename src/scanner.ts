import { ScanResult, ScanOptions, CheckResult } from './types';
import {
  checkSecurityHeaders,
  checkSSL,
  checkExposedFiles,
  checkCookies,
  checkCORS,
  checkServerInfo,
  checkAdminPaths,
  checkRobots,
  checkDnsSecurity,
  checkApiKeys,
  checkClientSidePermissions,
  checkTechStack
} from './checks';

export interface ExtendedScanResult extends ScanResult {
  techStack?: {
    detected: Array<{ name: string; category: string; confidence: string }>;
    summary: Record<string, string[]>;
  };
  htmlContent?: string;
}

export interface ExtendedScanOptions extends ScanOptions {
  outreach?: boolean; // Enable outreach mode (fewer, higher-confidence checks)
  skipAdminPaths?: boolean; // Skip admin path enumeration
}

export async function scanUrl(options: ExtendedScanOptions): Promise<ExtendedScanResult> {
  const startTime = Date.now();
  const { url, timeout = 10000, verbose = false, outreach = false, skipAdminPaths = false } = options;

  // Normalize URL
  let normalizedUrl = url;
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    normalizedUrl = `https://${url}`;
  }

  // Ensure trailing slash for base URL
  const parsedUrl = new URL(normalizedUrl);
  const baseUrl = `${parsedUrl.protocol}//${parsedUrl.host}`;
  const isHttps = parsedUrl.protocol === 'https:';

  // Calculate total checks based on mode
  const totalChecks = outreach ? 11 : 12; // Outreach skips admin paths

  if (verbose) {
    console.log(`\nScanning: ${baseUrl}`);
    if (outreach) {
      console.log('Mode: Outreach (high-confidence checks only)');
    }
    console.log('');
  }

  const checks: CheckResult[] = [];
  let mainHtml = '';
  let mainHeaders: Headers | null = null;

  // Step 1: Fetch the main page to get headers and HTML
  let checkNum = 1;
  if (verbose) console.log(`  [${checkNum}/${totalChecks}] Fetching main page...`);

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeout);

  try {
    const mainResponse = await fetch(normalizedUrl, {
      method: 'GET',
      signal: controller.signal,
      redirect: 'follow',
      headers: {
        'User-Agent': 'SecurityScanner/2.0 (Security Audit)'
      }
    });

    mainHeaders = mainResponse.headers;
    mainHtml = await mainResponse.text();
    if (verbose) console.log('      Done');
  } catch (error) {
    console.error(`Failed to fetch ${normalizedUrl}:`, error instanceof Error ? error.message : 'Unknown error');
  } finally {
    clearTimeout(timeoutId);
  }

  // Step 2: Security headers
  checkNum++;
  if (verbose) console.log(`  [${checkNum}/${totalChecks}] Checking security headers...`);
  if (mainHeaders) {
    const headersResult = await checkSecurityHeaders(mainHeaders);
    checks.push(headersResult);
    if (verbose) console.log(`      Found ${headersResult.issues.length} issues`);
  } else {
    checks.push({ name: 'Security Headers', passed: false, issues: [] });
  }

  // Step 3: Cookies
  checkNum++;
  if (verbose) console.log(`  [${checkNum}/${totalChecks}] Checking cookies...`);
  if (mainHeaders) {
    const cookiesResult = await checkCookies(mainHeaders, isHttps);
    checks.push(cookiesResult);
    if (verbose) console.log(`      Found ${cookiesResult.issues.length} issues`);
  } else {
    checks.push({ name: 'Cookie Security', passed: true, issues: [] });
  }

  // Step 4: CORS
  checkNum++;
  if (verbose) console.log(`  [${checkNum}/${totalChecks}] Checking CORS...`);
  if (mainHeaders) {
    const corsResult = await checkCORS(normalizedUrl, mainHeaders);
    checks.push(corsResult);
    if (verbose) console.log(`      Found ${corsResult.issues.length} issues`);
  } else {
    checks.push({ name: 'CORS Configuration', passed: true, issues: [] });
  }

  // Step 5: Server info
  checkNum++;
  if (verbose) console.log(`  [${checkNum}/${totalChecks}] Checking server info...`);
  if (mainHeaders) {
    const serverResult = await checkServerInfo(mainHeaders);
    checks.push(serverResult);
    if (verbose) console.log(`      Found ${serverResult.issues.length} issues`);
  } else {
    checks.push({ name: 'Server Information', passed: true, issues: [] });
  }

  // Step 6: Tech stack detection
  checkNum++;
  if (verbose) console.log(`  [${checkNum}/${totalChecks}] Detecting tech stack...`);
  let techResult: CheckResult = { name: 'Technology Stack', passed: true, issues: [] };
  if (mainHeaders && mainHtml) {
    techResult = await checkTechStack(normalizedUrl, mainHeaders, mainHtml);
    checks.push(techResult);
    const detected = (techResult.details as { detected?: unknown[] })?.detected || [];
    if (verbose) console.log(`      Detected ${detected.length} technologies`);
  } else {
    checks.push(techResult);
  }

  // Run remaining checks in parallel for speed
  const parallelChecks: Promise<CheckResult>[] = [];

  // Step 7: SSL/TLS
  checkNum++;
  if (verbose) console.log(`  [${checkNum}/${totalChecks}] Checking SSL/TLS...`);
  parallelChecks.push(checkSSL(normalizedUrl));

  // Step 8: DNS Security (SPF/DKIM/DMARC)
  checkNum++;
  if (verbose) console.log(`  [${checkNum}/${totalChecks}] Checking DNS security...`);
  parallelChecks.push(checkDnsSecurity(normalizedUrl));

  // Step 9: API Keys in JavaScript
  checkNum++;
  if (verbose) console.log(`  [${checkNum}/${totalChecks}] Scanning for exposed API keys...`);
  parallelChecks.push(checkApiKeys(normalizedUrl, timeout));

  // Step 10: Client-side permission patterns (partial check)
  checkNum++;
  if (verbose) console.log(`  [${checkNum}/${totalChecks}] Checking for client-side permission patterns...`);
  parallelChecks.push(checkClientSidePermissions(normalizedUrl, mainHtml, timeout));

  // Step 11: Exposed files
  checkNum++;
  if (verbose) console.log(`  [${checkNum}/${totalChecks}] Checking exposed files...`);
  parallelChecks.push(checkExposedFiles(baseUrl, timeout));

  // Step 12: Admin paths (skip in outreach mode by default)
  if (!outreach && !skipAdminPaths) {
    checkNum++;
    if (verbose) console.log(`  [${checkNum}/${totalChecks}] Checking admin paths...`);
    parallelChecks.push(checkAdminPaths(baseUrl, timeout, mainHtml));
  }

  // Step 13: Robots.txt
  checkNum++;
  if (verbose) console.log(`  [${checkNum}/${totalChecks}] Checking robots.txt...`);
  parallelChecks.push(checkRobots(baseUrl, timeout));

  // Wait for all parallel checks
  const parallelResults = await Promise.all(parallelChecks);

  // Add results in order
  for (const result of parallelResults) {
    checks.push(result);
    if (verbose) {
      const issueText = result.issues.length === 1 ? 'issue' : 'issues';
      console.log(`      ${result.name}: ${result.issues.length} ${issueText}`);
    }
  }

  // Calculate summary
  const allIssues = checks.flatMap(c => c.issues);
  const summary = {
    total: allIssues.length,
    passed: checks.filter(c => c.passed).length,
    failed: checks.filter(c => !c.passed).length,
    critical: allIssues.filter(i => i.severity === 'critical').length,
    high: allIssues.filter(i => i.severity === 'high').length,
    medium: allIssues.filter(i => i.severity === 'medium').length,
    low: allIssues.filter(i => i.severity === 'low').length,
    info: allIssues.filter(i => i.severity === 'info').length
  };

  const duration = Date.now() - startTime;

  // Extract tech stack details for reports
  const techStackDetails = techResult.details as {
    detected?: Array<{ name: string; category: string; confidence: string }>;
    summary?: Record<string, string[]>;
  } | undefined;

  return {
    url: baseUrl,
    timestamp: new Date().toISOString(),
    duration,
    checks,
    summary,
    techStack: techStackDetails ? {
      detected: techStackDetails.detected || [],
      summary: techStackDetails.summary || {}
    } : undefined,
    htmlContent: outreach ? mainHtml : undefined // Only include HTML in outreach mode for further analysis
  };
}
