#!/usr/bin/env node

import { scanUrl, ExtendedScanResult } from './scanner';
import { generateReport, generateCompactReport } from './report';
import { calculateScore, generateHumanReport, generateAgentReport, generateDmContent } from './report/index';
import { createGist, isGhAvailable } from './integrations/gist';
import * as fs from 'fs';
import * as path from 'path';

const VERSION = '2.0.0';

const HELP_TEXT = `
╔═══════════════════════════════════════════════════════════════════╗
║                    URL Security Scanner v${VERSION}                     ║
║         Quick security checks for any website URL                  ║
╚═══════════════════════════════════════════════════════════════════╝

USAGE:
  url-scanner <url> [options]

EXAMPLES:
  url-scanner https://example.com
  url-scanner example.com --verbose
  url-scanner https://mysite.com --outreach --gist
  url-scanner https://mysite.com --output report.md

OPTIONS:
  --verbose, -v     Show detailed progress during scan
  --output, -o      Save report to file (default: prints to console)
  --compact, -c     Generate compact report (for quick sharing)
  --timeout <ms>    Request timeout in milliseconds (default: 10000)
  --help, -h        Show this help message

OUTREACH MODE:
  --outreach        Generate outreach-optimized reports (human + agent)
  --gist            Auto-upload reports to GitHub Gist (requires gh CLI)
  --name <project>  Project name for personalized DM message

COMMANDS:
  stats             Show aggregate stats from all scans (for X content)

CHECKS PERFORMED:
  • Security Headers (CSP, HSTS, X-Frame-Options, etc.)
  • SSL/TLS Configuration (certificate, TLS version)
  • DNS Security (SPF, DKIM, DMARC for email authentication)
  • API Key Exposure (scans JavaScript for leaked secrets)
  • Exposed Sensitive Files (.env, .git, source maps, etc.)
  • Cookie Security (HttpOnly, Secure, SameSite)
  • CORS Misconfiguration
  • Server Information Disclosure
  • Technology Stack Detection
  • robots.txt Analysis

OUTPUT:
  Standard mode: Full technical report with fix instructions
  Outreach mode:
    - Human-friendly report (report-human.md)
    - Technical agent report (report-agent.md)
    - DM message (dm.txt)

`;

async function main() {
  const args = process.argv.slice(2);

  // Parse arguments
  if (args.length === 0 || args.includes('--help') || args.includes('-h')) {
    console.log(HELP_TEXT);
    process.exit(0);
  }

  // Check for stats command
  if (args[0] === 'stats') {
    showStats();
    process.exit(0);
  }

  // Extract URL (first non-flag argument)
  const url = args.find(arg => !arg.startsWith('-'));
  if (!url) {
    console.error('Error: No URL provided');
    console.log('\nUsage: url-scanner <url> [options]');
    process.exit(1);
  }

  // Parse options
  const verbose = args.includes('--verbose') || args.includes('-v');
  const compact = args.includes('--compact') || args.includes('-c');
  const outreach = args.includes('--outreach');
  const uploadGist = args.includes('--gist');

  let output: string | undefined;
  const outputIndex = args.findIndex(arg => arg === '--output' || arg === '-o');
  if (outputIndex !== -1 && args[outputIndex + 1]) {
    output = args[outputIndex + 1];
  }

  let timeout = 10000;
  const timeoutIndex = args.findIndex(arg => arg === '--timeout');
  if (timeoutIndex !== -1 && args[timeoutIndex + 1]) {
    timeout = parseInt(args[timeoutIndex + 1], 10);
  }

  let projectName: string | undefined;
  const nameIndex = args.findIndex(arg => arg === '--name');
  if (nameIndex !== -1 && args[nameIndex + 1]) {
    projectName = args[nameIndex + 1];
  }

  // Run the scan
  console.log('');
  console.log('╔═══════════════════════════════════════════════════════════════════╗');
  console.log(`║                    URL Security Scanner v${VERSION}                     ║`);
  console.log('╚═══════════════════════════════════════════════════════════════════╝');
  console.log('');

  try {
    const result: ExtendedScanResult = await scanUrl({
      url,
      timeout,
      verbose,
      outreach
    });

    // Calculate score
    const score = calculateScore(result, result.techStack);

    if (outreach) {
      // Outreach mode - generate multiple outputs
      await handleOutreachMode(result, score, uploadGist, projectName, verbose);
    } else {
      // Standard mode
      const report = compact ? generateCompactReport(result) : generateReport(result);

      if (output) {
        const outputPath = path.resolve(output);
        fs.writeFileSync(outputPath, report, 'utf-8');
        console.log(`\n✅ Report saved to: ${outputPath}`);
        printSummary(result, score);
      } else {
        console.log('');
        console.log(report);
      }
    }

    // Exit code based on findings
    if (result.summary.critical > 0) {
      process.exit(2);
    } else if (result.summary.high > 0) {
      process.exit(1);
    } else {
      process.exit(0);
    }

  } catch (error) {
    console.error('');
    console.error('❌ Scan failed:', error instanceof Error ? error.message : 'Unknown error');
    console.error('');
    console.error('Common issues:');
    console.error('  • Check if the URL is correct and accessible');
    console.error('  • Ensure you have internet connectivity');
    console.error('  • Try increasing timeout with --timeout 30000');
    process.exit(3);
  }
}

/**
 * Show aggregate stats from all scans
 * This is your X content generator - "Scanned 20 sites, here's what I found"
 */
function showStats(): void {
  const scansDir = path.resolve('scans');

  if (!fs.existsSync(scansDir)) {
    console.log('No scans yet. Run some scans first!');
    return;
  }

  const scanFiles = fs.readdirSync(scansDir).filter(f => f.endsWith('.json'));

  if (scanFiles.length === 0) {
    console.log('No scans yet. Run some scans first!');
    return;
  }

  // Load all scans
  const scans = scanFiles.map(f => {
    const content = fs.readFileSync(path.join(scansDir, f), 'utf-8');
    return JSON.parse(content);
  });

  // Calculate stats
  const totalScans = scans.length;
  const avgScore = Math.round(scans.reduce((sum, s) => sum + s.score, 0) / totalScans);

  // Count issue frequency
  const issueCount: Record<string, number> = {};
  for (const scan of scans) {
    for (const issue of scan.issues) {
      const key = issue.title;
      issueCount[key] = (issueCount[key] || 0) + 1;
    }
  }

  // Sort by frequency
  const sortedIssues = Object.entries(issueCount)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10);

  // Grade distribution
  const grades: Record<string, number> = { A: 0, B: 0, C: 0, D: 0, F: 0 };
  for (const scan of scans) {
    grades[scan.grade] = (grades[scan.grade] || 0) + 1;
  }

  // Tech stack frequency
  const techCount: Record<string, number> = {};
  for (const scan of scans) {
    // Handle both array format and object format
    const techStack = scan.techStack;
    if (Array.isArray(techStack)) {
      for (const tech of techStack) {
        techCount[tech] = (techCount[tech] || 0) + 1;
      }
    } else if (techStack?.detected) {
      for (const tech of techStack.detected) {
        techCount[tech.name] = (techCount[tech.name] || 0) + 1;
      }
    }
  }
  const sortedTech = Object.entries(techCount)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5);

  // Print stats
  console.log('');
  console.log('╔═══════════════════════════════════════════════════════════════════╗');
  console.log('║                    URL Security Scanner - Stats                    ║');
  console.log('╚═══════════════════════════════════════════════════════════════════╝');
  console.log('');
  console.log(`📊 Total scans: ${totalScans}`);
  console.log(`📈 Average score: ${avgScore}/100`);
  console.log('');
  console.log('Grade distribution:');
  for (const [grade, count] of Object.entries(grades)) {
    if (count > 0) {
      const pct = Math.round((count / totalScans) * 100);
      const bar = '█'.repeat(Math.round(pct / 5));
      console.log(`   ${grade}: ${bar} ${count} (${pct}%)`);
    }
  }
  console.log('');
  console.log('🔥 Most common issues:');
  for (const [issue, count] of sortedIssues) {
    const pct = Math.round((count / totalScans) * 100);
    console.log(`   ${pct}% - ${issue} (${count}/${totalScans} sites)`);
  }

  if (sortedTech.length > 0) {
    console.log('');
    console.log('🛠️  Tech stacks detected:');
    for (const [tech, count] of sortedTech) {
      console.log(`   ${tech}: ${count} sites`);
    }
  }

  console.log('');
  console.log('─'.repeat(67));
  console.log('');
  console.log('💡 X Post idea:');
  if (sortedIssues.length > 0) {
    const topIssue = sortedIssues[0];
    const pct = Math.round((topIssue[1] / totalScans) * 100);
    console.log(`   "Scanned ${totalScans} vibe coder sites this month.`);
    console.log(`   ${pct}% are missing ${topIssue[0].toLowerCase().replace('no ', '').replace('missing ', '')}.`);
    console.log(`   Here's why that matters and how to fix it in 5 minutes..."`);
  }
  console.log('');
}

/**
 * Save scan data for pattern analysis
 * This builds our internal database to generate stats like "80% miss SPF"
 */
function saveScanHistory(
  result: ExtendedScanResult,
  score: ReturnType<typeof calculateScore>,
  gistUrl: string
): void {
  const domain = new URL(result.url).hostname;
  const scansDir = path.resolve('scans');

  if (!fs.existsSync(scansDir)) {
    fs.mkdirSync(scansDir, { recursive: true });
  }

  // Collect all issues with their details
  const allIssues = result.checks.flatMap(c => c.issues);
  const issues = allIssues.map(issue => ({
    title: issue.title,
    severity: issue.severity,
    category: issue.category
  }));

  // Find the top issue (highest severity, first in list)
  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const sortedIssues = [...allIssues].sort((a, b) =>
    severityOrder[a.severity] - severityOrder[b.severity]
  );
  const topIssue = sortedIssues[0]?.title || 'None';

  const scanData = {
    domain,
    url: result.url,
    scannedAt: new Date().toISOString(),
    grade: score.grade,
    score: score.score,
    summary: {
      critical: result.summary.critical,
      high: result.summary.high,
      medium: result.summary.medium,
      low: result.summary.low,
      total: allIssues.length
    },
    issues,
    topIssue,
    techStack: result.techStack || [],
    gistUrl: gistUrl !== '[gist-url-here]' ? gistUrl : null
  };

  const scanPath = path.join(scansDir, `${domain}.json`);
  fs.writeFileSync(scanPath, JSON.stringify(scanData, null, 2), 'utf-8');
}

async function handleOutreachMode(
  result: ExtendedScanResult,
  score: ReturnType<typeof calculateScore>,
  uploadGist: boolean,
  projectName?: string,
  verbose?: boolean
): Promise<void> {
  const domain = new URL(result.url).hostname;

  // ═══════════════════════════════════════════════════════════════════
  // PHASE 1: Internal Scan Complete (passed in as result)
  // ═══════════════════════════════════════════════════════════════════
  console.log('');
  console.log('╔═══════════════════════════════════════════════════════════════════╗');
  console.log('║                    PHASE 1: Internal Scan                         ║');
  console.log('╚═══════════════════════════════════════════════════════════════════╝');
  console.log('');
  console.log(`   Grade: ${score.grade} (${score.score}/100)`);
  console.log(`   Issues: ${result.summary.critical} critical, ${result.summary.high} high, ${result.summary.medium} medium`);

  // ═══════════════════════════════════════════════════════════════════
  // PHASE 2: External Tool Validation
  // ═══════════════════════════════════════════════════════════════════
  console.log('');
  console.log('╔═══════════════════════════════════════════════════════════════════╗');
  console.log('║                    PHASE 2: External Validation                   ║');
  console.log('╚═══════════════════════════════════════════════════════════════════╝');
  console.log('');

  // Import external scanner module
  const { runExternalScans } = await import('./integrations/external-scanners');

  // Get tech stack for targeted Nuclei scanning
  const techStack = result.techStack?.detected?.map(t => t.name) || [];

  // Run external scans
  console.log('   Running external validation tools...');
  const externalResults = await runExternalScans(domain, {
    observatory: true,
    nuclei: true,
    techStack,
    verbose: true
  });

  // Extract Nuclei findings (type is inferred from the module)
  const nucleiResult = externalResults.results.find(r => r.source === 'Nuclei');
  const nucleiFindings = (nucleiResult?.details?.findings as Array<{
    templateId: string;
    info: { name: string; severity: string; description?: string };
    matched: string;
  }>) || [];

  console.log('');
  console.log('   External validation complete!');

  // Notify about failed external tools
  const observatoryResult = externalResults.results.find(r => r.source === 'Mozilla Observatory');
  if (!observatoryResult) {
    console.log('   ⚠️  Mozilla Observatory: FAILED (API error - may need manual check)');
  }
  if (externalResults.nucleiAvailable === false) {
    console.log('   ⚠️  Nuclei: Not installed (install for deeper scanning)');
  } else if (!nucleiResult) {
    console.log('   ⚠️  Nuclei: FAILED to run');
  }

  // ═══════════════════════════════════════════════════════════════════
  // COMBINE RESULTS & GENERATE REPORTS
  // ═══════════════════════════════════════════════════════════════════
  console.log('');
  console.log('╔═══════════════════════════════════════════════════════════════════╗');
  console.log('║                    Generating Combined Reports                    ║');
  console.log('╚═══════════════════════════════════════════════════════════════════╝');
  console.log('');

  // Import combined report generator
  const { createCombinedResult, generateCombinedReports } = await import('./report/combined');

  // Create combined result
  const combined = createCombinedResult(
    result,
    score,
    externalResults.results,
    nucleiFindings,
    externalResults.links,
    result.techStack
  );

  // Generate both reports
  const reports = generateCombinedReports(combined, projectName);

  // Create output directory per domain
  const outputDir = path.resolve('outputs', domain);
  if (!fs.existsSync(outputDir)) {
    fs.mkdirSync(outputDir, { recursive: true });
  }

  // Save individual reports
  const summaryPath = path.join(outputDir, 'executive-summary.md');
  const agentPath = path.join(outputDir, 'agent-report.md');

  fs.writeFileSync(summaryPath, reports.executiveSummary, 'utf-8');
  fs.writeFileSync(agentPath, reports.agentReport, 'utf-8');

  // Upload to gist if requested
  let gistUrl = '[not uploaded]';

  if (uploadGist) {
    console.log('');
    console.log('📤 Uploading to GitHub Gist...');

    if (!isGhAvailable()) {
      console.log('');
      console.log('⚠️  GitHub CLI not available. To enable gist upload:');
      console.log('   1. Install: winget install GitHub.cli');
      console.log('   2. Authenticate: gh auth login');
      console.log('');
      console.log('Reports saved locally. Create gist manually at: https://gist.github.com');
    } else {
      const gistResult = await createGist(reports.executiveSummary, reports.agentReport, domain);
      if (gistResult) {
        gistUrl = gistResult.url;
        console.log(`✅ Gist created: ${gistUrl}`);
      } else {
        console.log('❌ Failed to create gist. Reports saved locally.');
      }
    }
  }

  // Generate DM message
  const dmContent = generateDmContent(result, score, gistUrl, projectName);

  const dmPath = path.join(outputDir, 'dm.txt');
  fs.writeFileSync(dmPath, dmContent.message, 'utf-8');

  // Save scan history for pattern analysis
  saveScanHistory(result, score, gistUrl);

  // Build checklist for consolidated report
  const checklist = [
    { name: 'Internal scan (headers, cookies, CORS)', status: true },
    { name: 'DNS security (SPF/DMARC)', status: true },
    { name: 'API key exposure check', status: true },
    { name: 'Mozilla Observatory', status: !!observatoryResult },
    { name: 'Nuclei vulnerability scan', status: externalResults.nucleiAvailable !== false && !!nucleiResult },
  ];

  // Generate consolidated REPORT.md
  const consolidatedReport = generateConsolidatedReport({
    domain,
    url: result.url,
    grade: score.grade,
    scoreNum: score.score,
    timestamp: new Date().toISOString(),
    checklist,
    summary: {
      critical: result.summary.critical,
      high: result.summary.high,
      medium: result.summary.medium,
      low: result.summary.low,
      total: result.summary.total
    },
    observatoryGrade: observatoryResult?.grade,
    gistUrl,
    topIssues: result.checks
      .flatMap(c => c.issues)
      .filter(i => i.severity === 'critical' || i.severity === 'high' || i.severity === 'medium')
      .slice(0, 5)
      .map(i => ({ title: i.title, severity: i.severity, fix: i.fix }))
  });

  const reportPath = path.join(outputDir, 'REPORT.md');
  fs.writeFileSync(reportPath, consolidatedReport, 'utf-8');

  // ═══════════════════════════════════════════════════════════════════
  // SCAN CHECKLIST - What ran, what didn't
  // ═══════════════════════════════════════════════════════════════════
  console.log('');
  console.log('╔═══════════════════════════════════════════════════════════════════╗');
  console.log('║                    SCAN CHECKLIST                                 ║');
  console.log('╚═══════════════════════════════════════════════════════════════════╝');
  console.log('');

  let allPassed = true;
  for (const item of checklist) {
    const icon = item.status ? '✅' : '❌';
    const statusText = item.status ? 'Done' : 'FAILED';
    console.log(`   ${icon} ${item.name}: ${statusText}`);
    if (!item.status) allPassed = false;
  }

  console.log('');
  if (!allPassed) {
    console.log('   ⚠️  INCOMPLETE SCAN - Some tools failed! Review before sending.');
    console.log('');
  }

  // ═══════════════════════════════════════════════════════════════════
  // FINAL SUMMARY
  // ═══════════════════════════════════════════════════════════════════
  console.log('═'.repeat(67));
  console.log('');
  console.log(`🎯 Scan Complete: ${domain}`);
  console.log('');
  console.log(`   Grade: ${score.grade} (${score.score}/100)`);
  console.log(`   Issues: ${result.summary.critical} critical, ${result.summary.high} high, ${result.summary.medium} medium, ${result.summary.low} low`);
  if (observatoryResult?.grade) {
    console.log(`   Observatory: ${observatoryResult.grade}`);
  }
  console.log('');

  // Output folder
  console.log(`📁 Output: outputs/${domain}/`);
  console.log('   ├── REPORT.md        ← Start here (summary of everything)');
  console.log('   ├── executive-summary.md');
  console.log('   ├── agent-report.md');
  console.log('   └── dm.txt');
  console.log('');

  if (gistUrl !== '[not uploaded]') {
    console.log(`🔗 Gist: ${gistUrl}`);
    console.log('');
  }

  // Show DM message
  console.log('📨 DM Message:');
  console.log('─'.repeat(50));
  console.log(dmContent.message);
  console.log('─'.repeat(50));
  console.log('');
}

/**
 * Generate a consolidated report with everything in one place
 */
function generateConsolidatedReport(data: {
  domain: string;
  url: string;
  grade: string;
  scoreNum: number;
  timestamp: string;
  checklist: Array<{ name: string; status: boolean }>;
  summary: { critical: number; high: number; medium: number; low: number; total: number };
  observatoryGrade?: string;
  gistUrl: string;
  topIssues: Array<{ title: string; severity: string; fix: string }>;
}): string {
  const lines: string[] = [];
  const allPassed = data.checklist.every(c => c.status);

  lines.push(`# Security Scan Report: ${data.domain}`);
  lines.push('');
  lines.push(`**Scanned:** ${new Date(data.timestamp).toLocaleString()}`);
  lines.push(`**URL:** ${data.url}`);
  lines.push('');

  // Grade box
  lines.push('## Grade');
  lines.push('');
  lines.push(`| Grade | Score | Observatory |`);
  lines.push(`|-------|-------|-------------|`);
  lines.push(`| **${data.grade}** | ${data.scoreNum}/100 | ${data.observatoryGrade || 'N/A'} |`);
  lines.push('');

  // Checklist
  lines.push('## Scan Checklist');
  lines.push('');
  for (const item of data.checklist) {
    const icon = item.status ? '✅' : '❌';
    lines.push(`- ${icon} ${item.name}`);
  }
  lines.push('');
  if (!allPassed) {
    lines.push('> ⚠️ **INCOMPLETE SCAN** - Some tools failed. Results may be partial.');
    lines.push('');
  }

  // Summary
  lines.push('## Issues Summary');
  lines.push('');
  lines.push(`| Severity | Count |`);
  lines.push(`|----------|-------|`);
  lines.push(`| Critical | ${data.summary.critical} |`);
  lines.push(`| High | ${data.summary.high} |`);
  lines.push(`| Medium | ${data.summary.medium} |`);
  lines.push(`| Low | ${data.summary.low} |`);
  lines.push(`| **Total** | **${data.summary.total}** |`);
  lines.push('');

  // Top issues
  if (data.topIssues.length > 0) {
    lines.push('## Top Issues');
    lines.push('');
    for (const issue of data.topIssues) {
      lines.push(`### [${issue.severity.toUpperCase()}] ${issue.title}`);
      lines.push('');
      lines.push(`**Fix:** ${issue.fix}`);
      lines.push('');
    }
  }

  // Links
  lines.push('## Links');
  lines.push('');
  if (data.gistUrl !== '[not uploaded]') {
    lines.push(`- **Gist Report:** ${data.gistUrl}`);
  }
  lines.push(`- **Executive Summary:** executive-summary.md`);
  lines.push(`- **Agent Report:** agent-report.md`);
  lines.push(`- **DM Message:** dm.txt`);
  lines.push('');

  lines.push('---');
  lines.push(`*Generated by URL Security Scanner v${VERSION}*`);

  return lines.join('\n');
}

function printSummary(result: ExtendedScanResult, score: ReturnType<typeof calculateScore>): void {
  console.log('');
  console.log('─'.repeat(67));
  console.log('');
  console.log(`Scan complete for: ${result.url}`);
  console.log(`Duration: ${(result.duration / 1000).toFixed(1)}s`);
  console.log(`Grade: ${score.grade} (${score.score}/100)`);
  console.log('');
  console.log(`Issues found:`);
  console.log(`  🚨 Critical: ${result.summary.critical}`);
  console.log(`  🔴 High:     ${result.summary.high}`);
  console.log(`  🟠 Medium:   ${result.summary.medium}`);
  console.log(`  🟡 Low:      ${result.summary.low}`);
  console.log('');

  if (result.summary.critical > 0 || result.summary.high > 0) {
    console.log('⚠️  Action required! Review the report for critical/high issues.');
  } else {
    console.log('✅ No critical or high-priority issues found.');
  }
}

main();
