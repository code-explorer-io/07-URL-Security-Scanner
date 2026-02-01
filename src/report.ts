import { ScanResult, SecurityIssue } from './types';

const SEVERITY_EMOJI: Record<string, string> = {
  critical: '🚨',
  high: '🔴',
  medium: '🟠',
  low: '🟡',
  info: 'ℹ️'
};

const SEVERITY_LABEL: Record<string, string> = {
  critical: 'CRITICAL',
  high: 'HIGH',
  medium: 'MEDIUM',
  low: 'LOW',
  info: 'INFO'
};

export function generateReport(result: ScanResult): string {
  const lines: string[] = [];

  // ==========================================
  // SECTION 1: Friendly Human Overview
  // ==========================================

  lines.push(`# Security Scan Report`);
  lines.push(``);
  lines.push(`**Website:** ${result.url}`);
  lines.push(`**Scanned:** ${new Date(result.timestamp).toLocaleString()}`);
  lines.push(`**Duration:** ${(result.duration / 1000).toFixed(1)}s`);
  lines.push(``);

  // Quick verdict
  lines.push(`## Quick Summary`);
  lines.push(``);

  if (result.summary.critical > 0) {
    lines.push(`🚨 **Action Required!** Found ${result.summary.critical} critical issue${result.summary.critical > 1 ? 's' : ''} that need immediate attention.`);
  } else if (result.summary.high > 0) {
    lines.push(`🔴 **Issues Found:** ${result.summary.high} high-priority issue${result.summary.high > 1 ? 's' : ''} you should fix soon.`);
  } else if (result.summary.medium > 0) {
    lines.push(`🟠 **Looking Good!** A few medium-priority improvements recommended.`);
  } else if (result.summary.low > 0) {
    lines.push(`🟡 **Nice Work!** Just some minor tweaks to make it even better.`);
  } else {
    lines.push(`✅ **Excellent!** No significant security issues found.`);
  }

  lines.push(``);

  // Score card - friendly counts
  const totalChecks = result.checks.length;
  const passedChecks = result.checks.filter(c => c.passed).length;

  lines.push(`| Check | Result |`);
  lines.push(`|-------|--------|`);
  for (const check of result.checks) {
    const status = check.passed ? '✅ Pass' : `❌ ${check.issues.length} issue${check.issues.length > 1 ? 's' : ''}`;
    lines.push(`| ${check.name} | ${status} |`);
  }
  lines.push(``);
  lines.push(`**Overall:** ${passedChecks}/${totalChecks} checks passed`);
  lines.push(``);

  // ==========================================
  // SECTION 2: What We Found (Friendly Explanation)
  // ==========================================

  const allIssues = result.checks.flatMap(c => c.issues);

  if (allIssues.length > 0) {
    lines.push(`## What We Found`);
    lines.push(``);
    lines.push(`Here's a plain-English breakdown of the issues:`);
    lines.push(``);

    // Group by severity
    const criticalIssues = allIssues.filter(i => i.severity === 'critical');
    const highIssues = allIssues.filter(i => i.severity === 'high');
    const mediumIssues = allIssues.filter(i => i.severity === 'medium');
    const lowIssues = allIssues.filter(i => i.severity === 'low');

    if (criticalIssues.length > 0) {
      lines.push(`### 🚨 Critical Issues (Fix These First!)`);
      lines.push(``);
      lines.push(`These are serious security problems that attackers actively look for:`);
      lines.push(``);
      for (const issue of criticalIssues) {
        lines.push(`- **${issue.title}**`);
        lines.push(`  - *What it means:* ${issue.description}`);
        lines.push(`  - *Quick fix:* ${issue.fix}`);
        lines.push(``);
      }
    }

    if (highIssues.length > 0) {
      lines.push(`### 🔴 High Priority`);
      lines.push(``);
      lines.push(`Important security improvements to make:`);
      lines.push(``);
      for (const issue of highIssues) {
        lines.push(`- **${issue.title}**`);
        lines.push(`  - *What it means:* ${issue.description}`);
        lines.push(`  - *Quick fix:* ${issue.fix}`);
        lines.push(``);
      }
    }

    if (mediumIssues.length > 0) {
      lines.push(`### 🟠 Medium Priority`);
      lines.push(``);
      lines.push(`Good security practices to implement:`);
      lines.push(``);
      for (const issue of mediumIssues) {
        lines.push(`- **${issue.title}** - ${issue.description}`);
        lines.push(``);
      }
    }

    if (lowIssues.length > 0) {
      lines.push(`### 🟡 Low Priority`);
      lines.push(``);
      lines.push(`Minor improvements for extra hardening:`);
      lines.push(``);
      for (const issue of lowIssues) {
        lines.push(`- **${issue.title}** - ${issue.description}`);
        lines.push(``);
      }
    }
  }

  // ==========================================
  // SECTION 3: AI Agent Instructions
  // ==========================================

  if (allIssues.length > 0) {
    lines.push(`---`);
    lines.push(``);
    lines.push(`## 🤖 Paste This To Your AI Agent`);
    lines.push(``);
    lines.push(`Copy everything below and paste it to Claude, ChatGPT, or your AI coding assistant to fix these issues:`);
    lines.push(``);
    lines.push('```');
    lines.push(`SECURITY FIXES NEEDED FOR: ${result.url}`);
    lines.push(``);
    lines.push(`Please implement the following security fixes. For each fix, show me the code changes needed.`);
    lines.push(``);

    let fixNumber = 1;

    // Critical and High get detailed instructions
    const priorityIssues = [...allIssues.filter(i => i.severity === 'critical'), ...allIssues.filter(i => i.severity === 'high')];

    for (const issue of priorityIssues) {
      lines.push(`${fixNumber}. [${SEVERITY_LABEL[issue.severity]}] ${issue.title}`);
      lines.push(`   Category: ${issue.category}`);
      lines.push(`   Fix: ${issue.fix}`);
      lines.push(``);
      fixNumber++;
    }

    // Medium issues - condensed
    const mediumIssues = allIssues.filter(i => i.severity === 'medium');
    if (mediumIssues.length > 0) {
      lines.push(`MEDIUM PRIORITY:`);
      for (const issue of mediumIssues) {
        lines.push(`${fixNumber}. ${issue.title} - ${issue.fix}`);
        fixNumber++;
      }
      lines.push(``);
    }

    // Low issues - just list
    const lowIssues = allIssues.filter(i => i.severity === 'low');
    if (lowIssues.length > 0) {
      lines.push(`LOW PRIORITY (optional but recommended):`);
      for (const issue of lowIssues) {
        lines.push(`${fixNumber}. ${issue.title}`);
        fixNumber++;
      }
      lines.push(``);
    }

    lines.push(`Show me the specific code or configuration changes for each fix.`);
    lines.push('```');
    lines.push(``);
  }

  // ==========================================
  // SECTION 4: Technical Details (for reference)
  // ==========================================

  lines.push(`---`);
  lines.push(``);
  lines.push(`<details>`);
  lines.push(`<summary>📋 Technical Details (Click to expand)</summary>`);
  lines.push(``);

  for (const check of result.checks) {
    if (check.issues.length > 0 || check.details) {
      lines.push(`### ${check.name}`);
      lines.push(``);

      if (check.details) {
        lines.push('```json');
        lines.push(JSON.stringify(check.details, null, 2));
        lines.push('```');
        lines.push(``);
      }

      for (const issue of check.issues) {
        lines.push(`- \`${issue.id}\` [${issue.severity.toUpperCase()}] ${issue.title}`);
      }
      lines.push(``);
    }
  }

  lines.push(`</details>`);
  lines.push(``);

  // Footer
  lines.push(`---`);
  lines.push(`*Generated by URL Security Scanner v1.0*`);

  return lines.join('\n');
}

// Compact report for quick sharing
export function generateCompactReport(result: ScanResult): string {
  const lines: string[] = [];

  lines.push(`🔒 Security Scan: ${result.url}`);
  lines.push(``);

  const { critical, high, medium, low } = result.summary;

  if (critical === 0 && high === 0 && medium === 0) {
    lines.push(`✅ Looking good! No major issues found.`);
  } else {
    if (critical > 0) lines.push(`🚨 ${critical} critical`);
    if (high > 0) lines.push(`🔴 ${high} high`);
    if (medium > 0) lines.push(`🟠 ${medium} medium`);
    if (low > 0) lines.push(`🟡 ${low} low`);
  }

  lines.push(``);
  lines.push(`Top issues:`);

  const allIssues = result.checks.flatMap(c => c.issues);
  const topIssues = allIssues
    .sort((a, b) => {
      const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
      return order[a.severity] - order[b.severity];
    })
    .slice(0, 5);

  for (const issue of topIssues) {
    lines.push(`${SEVERITY_EMOJI[issue.severity]} ${issue.title}`);
  }

  if (allIssues.length > 5) {
    lines.push(`... and ${allIssues.length - 5} more`);
  }

  return lines.join('\n');
}
