/**
 * Combined Report Generator
 *
 * Generates two types of reports:
 * 1. Executive Summary - Human-friendly, for the vibe coder to understand
 * 2. Agent Report - Technical details for their AI agent to act on
 */

import { ScanResult, SecurityIssue } from '../types';
import { SecurityScore } from './score';
import { ExternalScanResult } from '../integrations/external-scanners';

// Simplified Nuclei finding type for report generation
export interface NucleiFinding {
  templateId: string;
  info: {
    name: string;
    severity: string;
    description?: string;
    tags?: string[];
  };
  matched: string;
  type?: string;
  host?: string;
  timestamp?: string;
}

export interface CombinedScanResult {
  // Phase 1: Our internal scan
  internal: {
    result: ScanResult;
    score: SecurityScore;
    techStack?: {
      detected: Array<{ name: string; category: string; confidence: string }>;
      summary: Record<string, string[]>;
    };
  };
  // Phase 2: External tool results
  external: {
    observatory?: ExternalScanResult;
    nuclei?: {
      findings: NucleiFinding[];
      duration?: number;
    };
    links: { name: string; url: string }[];
  };
  // Combined analysis
  analysis: {
    confidence: 'high' | 'medium' | 'low';
    agreementSummary: string;
    uniqueFindings: {
      internal: string[];
      external: string[];
    };
  };
}

/**
 * Analyze agreement between internal and external scans
 */
function analyzeAgreement(
  internalIssues: SecurityIssue[],
  observatoryGrade?: string,
  nucleiFindings?: NucleiFinding[]
): CombinedScanResult['analysis'] {
  const internalTitles = internalIssues.map(i => i.title.toLowerCase());
  const externalFindings: string[] = [];

  // Track what external tools found
  if (observatoryGrade && ['D', 'E', 'F'].includes(observatoryGrade)) {
    externalFindings.push('Poor header security (Observatory)');
  }
  if (nucleiFindings && nucleiFindings.length > 0) {
    nucleiFindings.forEach(f => externalFindings.push(f.info.name));
  }

  // Find overlaps
  const headerIssues = internalTitles.filter(t =>
    t.includes('csp') || t.includes('hsts') || t.includes('header')
  );
  const hasHeaderOverlap = headerIssues.length > 0 && observatoryGrade && ['D', 'E', 'F'].includes(observatoryGrade);

  // Determine confidence
  let confidence: 'high' | 'medium' | 'low' = 'medium';
  let agreementSummary = '';

  if (hasHeaderOverlap) {
    confidence = 'high';
    agreementSummary = 'Both our scan and Mozilla Observatory identified security header issues.';
  } else if (externalFindings.length === 0 && internalIssues.length > 0) {
    confidence = 'medium';
    agreementSummary = 'Our scan found issues that external tools did not flag (they may check different things).';
  } else if (externalFindings.length > 0 && internalIssues.length === 0) {
    confidence = 'medium';
    agreementSummary = 'External tools found issues our scan missed - review recommended.';
  } else if (externalFindings.length === 0 && internalIssues.length === 0) {
    confidence = 'high';
    agreementSummary = 'All scans agree: no significant issues found.';
  } else {
    agreementSummary = 'Multiple perspectives identified different issues.';
  }

  return {
    confidence,
    agreementSummary,
    uniqueFindings: {
      internal: internalIssues.filter(i => i.severity !== 'low').map(i => i.title).slice(0, 5),
      external: externalFindings.slice(0, 5)
    }
  };
}

/**
 * Generate Executive Summary - Human-friendly report
 */
export function generateExecutiveSummary(
  combined: CombinedScanResult,
  projectName?: string
): string {
  const { internal, external, analysis } = combined;
  const domain = new URL(internal.result.url).hostname;
  const displayName = projectName || domain;

  const lines: string[] = [];

  // Header
  lines.push(`# Security Report: ${displayName}`);
  lines.push('');
  lines.push(`> Scanned on ${new Date().toLocaleDateString('en-US', { month: 'long', day: 'numeric', year: 'numeric' })}`);
  lines.push('');

  // Grade Box
  lines.push('## Overall Grade');
  lines.push('');
  lines.push(`**${internal.score.grade}** (${internal.score.score}/100)`);
  lines.push('');

  // What this means
  const gradeExplanations: Record<string, string> = {
    'A': 'Excellent! Your security posture is solid. Keep it up.',
    'B': 'Good! A few small improvements would make it even better.',
    'C': 'Fair. Some security gaps should be addressed.',
    'D': 'Needs attention. Several issues could put your users at risk.',
    'F': 'Critical issues found. These need immediate attention.'
  };
  lines.push(gradeExplanations[internal.score.grade] || '');
  lines.push('');

  // Quick Stats
  lines.push('## At a Glance');
  lines.push('');
  lines.push(`| Metric | Value |`);
  lines.push(`|--------|-------|`);
  lines.push(`| Critical Issues | ${internal.result.summary.critical} |`);
  lines.push(`| High Issues | ${internal.result.summary.high} |`);
  lines.push(`| Medium Issues | ${internal.result.summary.medium} |`);
  lines.push(`| External Validation | ${analysis.confidence} confidence |`);
  lines.push('');

  // Top Issues (Human-Friendly)
  const allIssues = internal.result.checks.flatMap(c => c.issues);
  const topIssues = allIssues
    .filter(i => i.severity === 'critical' || i.severity === 'high')
    .slice(0, 3);

  if (topIssues.length > 0) {
    lines.push('## Top Issues to Fix');
    lines.push('');
    lines.push('These are the most important things to address:');
    lines.push('');

    for (const issue of topIssues) {
      lines.push(`### ${issue.title}`);
      lines.push('');
      lines.push(`**What this means:** ${issue.description}`);
      lines.push('');
      lines.push(`**How to fix:** ${issue.fix}`);
      lines.push('');
    }
  } else {
    lines.push('## No Critical Issues Found');
    lines.push('');
    lines.push('Great news! No critical or high-severity issues were found.');
    lines.push('');
  }

  // External Validation Section
  lines.push('## External Validation');
  lines.push('');
  lines.push('We cross-checked our findings with industry-standard tools:');
  lines.push('');

  if (external.observatory) {
    lines.push(`**Mozilla Observatory:** Grade ${external.observatory.grade || 'N/A'}`);
    if (external.observatory.url) {
      lines.push(`[View full report](${external.observatory.url})`);
    }
    lines.push('');
  }

  if (external.nuclei) {
    const vulnCount = external.nuclei.findings.length;
    lines.push(`**Nuclei Vulnerability Scan:** ${vulnCount === 0 ? 'No vulnerabilities found' : `${vulnCount} issue(s) found`}`);
    lines.push('');
  }

  // Confidence
  lines.push(`**Confidence Level:** ${analysis.confidence.toUpperCase()}`);
  lines.push('');
  lines.push(analysis.agreementSummary);
  lines.push('');

  // Quick Wins
  const quickWins = allIssues
    .filter(i => i.severity === 'medium' || i.severity === 'low')
    .slice(0, 3);

  if (quickWins.length > 0) {
    lines.push('## Quick Wins');
    lines.push('');
    lines.push('Smaller improvements you can make:');
    lines.push('');
    for (const issue of quickWins) {
      lines.push(`- **${issue.title}**: ${issue.fix.split('.')[0]}.`);
    }
    lines.push('');
  }

  // Next Steps
  lines.push('## What To Do Next');
  lines.push('');
  lines.push('1. Share the **Technical Report** (below) with your AI coding assistant');
  lines.push('2. Ask it to implement the fixes');
  lines.push('3. Re-scan after deploying to verify the fixes worked');
  lines.push('');
  lines.push('---');
  lines.push('');
  lines.push('*Generated by URL Security Scanner | [GitHub](https://github.com)*');

  return lines.join('\n');
}

/**
 * Generate Agent Report - Technical details for AI assistants
 */
export function generateAgentReport(combined: CombinedScanResult): string {
  const { internal, external, analysis } = combined;
  const domain = new URL(internal.result.url).hostname;

  const lines: string[] = [];

  // Header for AI
  lines.push('# Security Scan Technical Report');
  lines.push('');
  lines.push('> This report is designed to be parsed by AI coding assistants.');
  lines.push('> Copy this entire report and paste it to your AI agent with: "Fix these security issues"');
  lines.push('');
  lines.push(`**Target:** ${internal.result.url}`);
  lines.push(`**Scanned:** ${internal.result.timestamp}`);
  lines.push(`**Grade:** ${internal.score.grade} (${internal.score.score}/100)`);
  lines.push('');

  // Phase 1: Internal Scan Results
  lines.push('---');
  lines.push('## PHASE 1: Internal Security Scan');
  lines.push('');

  for (const check of internal.result.checks) {
    if (check.issues.length === 0) continue;

    lines.push(`### ${check.name}`);
    lines.push('');

    for (const issue of check.issues) {
      lines.push(`#### [${issue.severity.toUpperCase()}] ${issue.title}`);
      lines.push('');
      lines.push(`- **ID:** ${issue.id}`);
      lines.push(`- **Category:** ${issue.category}`);
      lines.push(`- **Description:** ${issue.description}`);
      lines.push(`- **Fix:** ${issue.fix}`);
      lines.push('');
    }
  }

  // Phase 2: External Tool Results
  lines.push('---');
  lines.push('## PHASE 2: External Tool Validation');
  lines.push('');

  // Observatory
  if (external.observatory) {
    lines.push('### Mozilla Observatory');
    lines.push('');
    lines.push(`- **Grade:** ${external.observatory.grade || 'N/A'}`);
    lines.push(`- **Score:** ${external.observatory.score || 'N/A'}/100`);
    const details = external.observatory.details as { testsPassed?: number; testsFailed?: number };
    if (details.testsPassed !== undefined) {
      lines.push(`- **Tests Passed:** ${details.testsPassed}`);
      lines.push(`- **Tests Failed:** ${details.testsFailed}`);
    }
    if (external.observatory.url) {
      lines.push(`- **Full Report:** ${external.observatory.url}`);
    }
    lines.push('');
  }

  // Nuclei
  if (external.nuclei) {
    lines.push('### Nuclei Vulnerability Scanner');
    lines.push('');
    if (external.nuclei.findings.length === 0) {
      lines.push('No vulnerabilities detected by Nuclei templates.');
    } else {
      lines.push(`Found ${external.nuclei.findings.length} issue(s):`);
      lines.push('');
      for (const finding of external.nuclei.findings) {
        lines.push(`#### [${finding.info.severity.toUpperCase()}] ${finding.info.name}`);
        lines.push('');
        lines.push(`- **Template:** ${finding.templateId}`);
        lines.push(`- **Matched:** ${finding.matched}`);
        if (finding.info.description) {
          lines.push(`- **Description:** ${finding.info.description}`);
        }
        lines.push('');
      }
    }
    lines.push('');
  }

  // Manual Check Links
  if (external.links.length > 0) {
    lines.push('### Additional Manual Checks');
    lines.push('');
    lines.push('These tools require manual verification:');
    lines.push('');
    for (const link of external.links) {
      lines.push(`- [${link.name}](${link.url})`);
    }
    lines.push('');
  }

  // Cross-Reference Analysis
  lines.push('---');
  lines.push('## Cross-Reference Analysis');
  lines.push('');
  lines.push(`**Confidence:** ${analysis.confidence}`);
  lines.push('');
  lines.push(analysis.agreementSummary);
  lines.push('');

  if (analysis.uniqueFindings.internal.length > 0) {
    lines.push('**Issues found by our scan:**');
    for (const finding of analysis.uniqueFindings.internal) {
      lines.push(`- ${finding}`);
    }
    lines.push('');
  }

  if (analysis.uniqueFindings.external.length > 0) {
    lines.push('**Issues found by external tools:**');
    for (const finding of analysis.uniqueFindings.external) {
      lines.push(`- ${finding}`);
    }
    lines.push('');
  }

  // Tech Stack (if detected)
  if (internal.techStack && internal.techStack.detected.length > 0) {
    lines.push('---');
    lines.push('## Detected Technology Stack');
    lines.push('');
    for (const tech of internal.techStack.detected) {
      lines.push(`- ${tech.name} (${tech.category})`);
    }
    lines.push('');
  }

  // Fix Priority
  lines.push('---');
  lines.push('## Recommended Fix Order');
  lines.push('');
  lines.push('Address issues in this order:');
  lines.push('');
  lines.push('1. **CRITICAL** - Fix immediately (security breach risk)');
  lines.push('2. **HIGH** - Fix soon (significant vulnerability)');
  lines.push('3. **MEDIUM** - Fix when possible (best practice)');
  lines.push('4. **LOW** - Nice to have (hardening)');
  lines.push('');

  // Summary for AI
  lines.push('---');
  lines.push('## AI Agent Instructions');
  lines.push('');
  lines.push('To fix these issues:');
  lines.push('1. Start with CRITICAL and HIGH severity issues');
  lines.push('2. For each issue, implement the fix described');
  lines.push('3. Test the fix locally before deploying');
  lines.push('4. After deploying, the user should re-scan to verify');
  lines.push('');
  lines.push(`Domain: ${domain}`);
  lines.push(`Total Issues: ${internal.result.summary.total}`);
  lines.push(`Critical: ${internal.result.summary.critical}, High: ${internal.result.summary.high}, Medium: ${internal.result.summary.medium}, Low: ${internal.result.summary.low}`);

  return lines.join('\n');
}

/**
 * Generate all combined reports
 */
export function generateCombinedReports(
  combined: CombinedScanResult,
  projectName?: string
): {
  executiveSummary: string;
  agentReport: string;
} {
  return {
    executiveSummary: generateExecutiveSummary(combined, projectName),
    agentReport: generateAgentReport(combined)
  };
}

/**
 * Create a CombinedScanResult from separate scan phases
 */
export function createCombinedResult(
  internalResult: ScanResult,
  score: SecurityScore,
  externalResults: ExternalScanResult[],
  nucleiFindings: NucleiFinding[],
  links: { name: string; url: string }[],
  techStack?: CombinedScanResult['internal']['techStack']
): CombinedScanResult {
  const observatory = externalResults.find(r => r.source === 'Mozilla Observatory');
  const allIssues = internalResult.checks.flatMap(c => c.issues);

  return {
    internal: {
      result: internalResult,
      score,
      techStack
    },
    external: {
      observatory,
      nuclei: nucleiFindings.length > 0 || nucleiFindings !== undefined ? {
        findings: nucleiFindings,
        duration: undefined
      } : undefined,
      links
    },
    analysis: analyzeAgreement(allIssues, observatory?.grade, nucleiFindings)
  };
}
