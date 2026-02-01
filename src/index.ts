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
    - DM messages (dm-intro.txt, dm-followup.txt)

`;

async function main() {
  const args = process.argv.slice(2);

  // Parse arguments
  if (args.length === 0 || args.includes('--help') || args.includes('-h')) {
    console.log(HELP_TEXT);
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

async function handleOutreachMode(
  result: ExtendedScanResult,
  score: ReturnType<typeof calculateScore>,
  uploadGist: boolean,
  projectName?: string,
  verbose?: boolean
): Promise<void> {
  const domain = new URL(result.url).hostname;

  // Generate reports
  const humanReport = generateHumanReport(result, score, result.techStack);
  const agentReport = generateAgentReport(result, score, result.techStack);

  // Create output directory
  const outputDir = path.resolve('outputs');
  if (!fs.existsSync(outputDir)) {
    fs.mkdirSync(outputDir, { recursive: true });
  }

  // Save reports locally
  const humanPath = path.join(outputDir, `report-human-${domain}.md`);
  const agentPath = path.join(outputDir, `report-agent-${domain}.md`);

  fs.writeFileSync(humanPath, humanReport, 'utf-8');
  fs.writeFileSync(agentPath, agentReport, 'utf-8');

  if (verbose) {
    console.log('');
    console.log('📄 Reports generated:');
    console.log(`   ${humanPath}`);
    console.log(`   ${agentPath}`);
  }

  // Upload to gist if requested
  let gistUrl = '[gist-url-here]';

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
      const gistResult = await createGist(humanReport, agentReport, domain);
      if (gistResult) {
        gistUrl = gistResult.url;
        console.log(`✅ Gist created: ${gistUrl}`);
      } else {
        console.log('❌ Failed to create gist. Reports saved locally.');
      }
    }
  }

  // Generate DM messages
  const dmContent = generateDmContent(result, score, gistUrl, projectName);

  const dmIntroPath = path.join(outputDir, `dm-intro-${domain}.txt`);
  const dmFollowupPath = path.join(outputDir, `dm-followup-${domain}.txt`);

  fs.writeFileSync(dmIntroPath, dmContent.intro, 'utf-8');
  fs.writeFileSync(dmFollowupPath, dmContent.followup, 'utf-8');

  // Print summary
  console.log('');
  console.log('═'.repeat(67));
  console.log('');
  console.log(`🎯 Outreach Package Ready for: ${domain}`);
  console.log('');
  console.log(`   Grade: ${score.grade} (${score.score}/100)`);
  console.log(`   Issues: ${result.summary.critical} critical, ${result.summary.high} high, ${result.summary.medium} medium`);
  console.log('');
  console.log('📁 Files generated:');
  console.log(`   ${humanPath}`);
  console.log(`   ${agentPath}`);
  console.log(`   ${dmIntroPath}`);
  console.log(`   ${dmFollowupPath}`);
  console.log('');

  if (gistUrl !== '[gist-url-here]') {
    console.log(`🔗 Gist URL: ${gistUrl}`);
    console.log('');
  }

  console.log('📨 DM Intro (copy this):');
  console.log('─'.repeat(40));
  console.log(dmContent.intro);
  console.log('─'.repeat(40));
  console.log('');
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
