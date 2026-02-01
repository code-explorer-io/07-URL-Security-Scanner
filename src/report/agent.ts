import { ScanResult, SecurityIssue } from '../types';
import { SecurityScore } from './score';

/**
 * Framework-specific fix instructions
 */
const FRAMEWORK_FIXES: Record<string, Record<string, string>> = {
  'Next.js': {
    'Content-Security-Policy': `Add to next.config.js:
\`\`\`javascript
const securityHeaders = [
  {
    key: 'Content-Security-Policy',
    value: "default-src 'self'; script-src 'self' 'unsafe-eval' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:;"
  }
];

module.exports = {
  async headers() {
    return [{ source: '/:path*', headers: securityHeaders }];
  }
};
\`\`\``,
    'Strict-Transport-Security': `Add to next.config.js headers array:
\`\`\`javascript
{ key: 'Strict-Transport-Security', value: 'max-age=31536000; includeSubDomains' }
\`\`\``,
    'X-Frame-Options': `Add to next.config.js headers array:
\`\`\`javascript
{ key: 'X-Frame-Options', value: 'DENY' }
\`\`\``,
    'X-Content-Type-Options': `Add to next.config.js headers array:
\`\`\`javascript
{ key: 'X-Content-Type-Options', value: 'nosniff' }
\`\`\``,
  },
  'Vercel': {
    'Content-Security-Policy': `Add to vercel.json:
\`\`\`json
{
  "headers": [
    {
      "source": "/(.*)",
      "headers": [
        {
          "key": "Content-Security-Policy",
          "value": "default-src 'self'; script-src 'self' 'unsafe-eval' 'unsafe-inline';"
        }
      ]
    }
  ]
}
\`\`\``,
    'headers': `Create or edit vercel.json:
\`\`\`json
{
  "headers": [
    {
      "source": "/(.*)",
      "headers": [
        { "key": "X-Frame-Options", "value": "DENY" },
        { "key": "X-Content-Type-Options", "value": "nosniff" },
        { "key": "Strict-Transport-Security", "value": "max-age=31536000; includeSubDomains" }
      ]
    }
  ]
}
\`\`\``,
  },
  'Netlify': {
    'headers': `Create or edit netlify.toml:
\`\`\`toml
[[headers]]
  for = "/*"
  [headers.values]
    X-Frame-Options = "DENY"
    X-Content-Type-Options = "nosniff"
    Strict-Transport-Security = "max-age=31536000; includeSubDomains"
    Content-Security-Policy = "default-src 'self'; script-src 'self' 'unsafe-inline';"
\`\`\``,
  },
};

/**
 * Get framework-specific fix if available
 */
function getFrameworkFix(framework: string | null, issueType: string): string | null {
  if (!framework) return null;
  return FRAMEWORK_FIXES[framework]?.[issueType] || FRAMEWORK_FIXES[framework]?.['headers'] || null;
}

/**
 * Generate a super technical report designed for AI agents
 */
export function generateAgentReport(
  result: ScanResult,
  score: SecurityScore,
  techStack?: { detected: Array<{ name: string; category: string }> }
): string {
  const lines: string[] = [];
  const domain = new URL(result.url).hostname;

  // Detect primary framework/hosting for targeted fixes
  const frameworks = techStack?.detected?.filter(d => d.category === 'framework').map(d => d.name) || [];
  const hosting = techStack?.detected?.filter(d => d.category === 'hosting').map(d => d.name) || [];
  const primaryFramework = frameworks[0] || hosting[0] || null;

  // Header with context
  lines.push('# Security Remediation Instructions');
  lines.push('');
  lines.push('## Scan Context');
  lines.push('');
  lines.push(`- **Target:** ${result.url}`);
  lines.push(`- **Domain:** ${domain}`);
  lines.push(`- **Scan Date:** ${new Date(result.timestamp).toISOString()}`);
  lines.push(`- **Grade:** ${score.grade} (${score.score}/100)`);

  if (primaryFramework) {
    lines.push(`- **Detected Stack:** ${[...frameworks, ...hosting].join(', ')}`);
  }

  lines.push('');
  lines.push('---');
  lines.push('');

  // All issues with technical details
  const allIssues = result.checks.flatMap(c => c.issues);

  if (allIssues.length === 0) {
    lines.push('## No Issues Requiring Remediation');
    lines.push('');
    lines.push('The scan did not identify any security issues requiring fixes.');
    lines.push('');
  } else {
    lines.push('## Issues Requiring Remediation');
    lines.push('');

    // Sort by severity
    const sortedIssues = [...allIssues].sort((a, b) => {
      const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
      return order[a.severity] - order[b.severity];
    });

    let issueNum = 1;
    for (const issue of sortedIssues) {
      lines.push(`### Issue ${issueNum}: ${issue.title}`);
      lines.push('');
      lines.push(`- **Severity:** ${issue.severity.toUpperCase()}`);
      lines.push(`- **Category:** ${issue.category}`);
      lines.push(`- **ID:** \`${issue.id}\``);
      lines.push('');
      lines.push('**Description:**');
      lines.push(issue.description);
      lines.push('');

      // Framework-specific fix if available
      const frameworkFix = getFrameworkFix(primaryFramework, issue.title.split(' ')[1] || issue.category);

      lines.push('**Remediation:**');
      lines.push('');

      if (frameworkFix) {
        lines.push(frameworkFix);
      } else {
        lines.push(issue.fix);
      }

      lines.push('');

      // Add verification step
      lines.push('**Verification:**');
      if (issue.category === 'Security Headers') {
        lines.push(`After deploying, verify with: \`curl -I ${result.url} | grep -i "${issue.title.split(' ')[1] || 'security'}"\``);
      } else if (issue.category === 'Email Security') {
        lines.push(`Verify with: \`dig +short TXT ${domain}\` and \`dig +short TXT _dmarc.${domain}\``);
      } else if (issue.category === 'Exposed Secrets') {
        lines.push('After fixing, redeploy and verify the key no longer appears in client-side JavaScript.');
      } else {
        lines.push('Re-run this security scan to verify the fix.');
      }

      lines.push('');
      lines.push('---');
      lines.push('');

      issueNum++;
    }
  }

  // Check details for debugging
  lines.push('## Technical Details');
  lines.push('');
  lines.push('<details>');
  lines.push('<summary>Raw Scan Data (Click to expand)</summary>');
  lines.push('');
  lines.push('```json');
  lines.push(JSON.stringify({
    url: result.url,
    timestamp: result.timestamp,
    duration: result.duration,
    summary: result.summary,
    checks: result.checks.map(c => ({
      name: c.name,
      passed: c.passed,
      issueCount: c.issues.length,
      details: c.details
    }))
  }, null, 2));
  lines.push('```');
  lines.push('');
  lines.push('</details>');
  lines.push('');

  // Ready-to-paste prompt for other agents
  lines.push('---');
  lines.push('');
  lines.push('## Copy-Paste Prompt for AI Coding Assistant');
  lines.push('');
  lines.push('If you want another AI to implement these fixes, copy everything below:');
  lines.push('');
  lines.push('````');
  lines.push(`I need to fix security issues on my website ${result.url}.`);
  lines.push('');
  lines.push(`Detected stack: ${primaryFramework || 'Unknown'}`);
  lines.push('');
  lines.push('Please implement these fixes:');
  lines.push('');

  for (const issue of allIssues.slice(0, 10)) {
    lines.push(`${issueNumForPrompt(issue)}: [${issue.severity.toUpperCase()}] ${issue.title}`);
    lines.push(`   Fix: ${issue.fix}`);
    lines.push('');
  }

  if (allIssues.length > 10) {
    lines.push(`(Plus ${allIssues.length - 10} more issues - see full report)`);
  }

  lines.push('');
  lines.push('Show me the exact code changes needed for each fix.');
  lines.push('````');
  lines.push('');

  // Footer
  lines.push('---');
  lines.push('*Generated by URL Security Scanner v2.0*');

  return lines.join('\n');
}

let promptIssueCounter = 0;
function issueNumForPrompt(issue: SecurityIssue): number {
  promptIssueCounter++;
  return promptIssueCounter;
}
