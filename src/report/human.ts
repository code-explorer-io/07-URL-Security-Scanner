import { ScanResult, SecurityIssue } from '../types';
import { SecurityScore, getGradeDescription } from './score';

/**
 * Friendly analogies for common security issues
 */
const ANALOGIES: Record<string, string> = {
  'Email Security': "It's like having no caller ID on your phone — anyone can pretend to be you.",
  'Missing Content-Security-Policy header': "It's like a party with no guest list — any script can walk in.",
  'Missing Strict-Transport-Security header': "It's like a door that can be unlocked from outside — connections can be downgraded.",
  'Missing X-Frame-Options header': "It's like someone putting a fake frame around your window to trick visitors.",
  'API Key Exposure': "It's like leaving your house key under the doormat — everyone knows to look there.",
  'Exposed Files': "It's like leaving private documents on your lawn for anyone walking by to read.",
  'Source map': "It's like leaving your blueprints on the construction site after the building is done.",
  'Git': "It's like leaving your entire project folder out in the open — attackers can download everything.",
  'Database': "It's like leaving your filing cabinet unlocked and open on the street.",
};

/**
 * Get a friendly analogy for an issue
 */
function getAnalogy(issue: SecurityIssue): string | null {
  for (const [key, analogy] of Object.entries(ANALOGIES)) {
    if (issue.title.includes(key) || issue.category.includes(key) || issue.description.includes(key)) {
      return analogy;
    }
  }
  return null;
}

/**
 * Generate a beginner-friendly report designed for humans
 */
export function generateHumanReport(
  result: ScanResult,
  score: SecurityScore,
  techStack?: { detected: Array<{ name: string; category: string }> }
): string {
  const lines: string[] = [];
  const domain = new URL(result.url).hostname;

  // Header
  lines.push(`# Security Checkup: ${domain}`);
  lines.push('');
  lines.push(`**Grade: ${score.grade}** (${score.score}/100)`);
  lines.push('');
  lines.push(getGradeDescription(score.grade));
  lines.push('');
  lines.push(`*Scanned on ${new Date(result.timestamp).toLocaleDateString()}*`);
  lines.push('');

  // Tech stack if detected
  if (techStack?.detected && techStack.detected.length > 0) {
    const frameworks = techStack.detected.filter(d => d.category === 'framework').map(d => d.name);
    const hosting = techStack.detected.filter(d => d.category === 'hosting').map(d => d.name);
    const cdn = techStack.detected.filter(d => d.category === 'cdn').map(d => d.name);

    if (frameworks.length || hosting.length || cdn.length) {
      lines.push('**Detected Stack:** ' + [...frameworks, ...hosting, ...cdn].join(', '));
      lines.push('');
    }
  }

  lines.push('---');
  lines.push('');

  // What's looking good
  const passedChecks = result.checks.filter(c => c.passed);
  if (passedChecks.length > 0 || score.bonuses.length > 0) {
    lines.push('## What\'s Looking Good');
    lines.push('');

    for (const check of passedChecks) {
      lines.push(`- ✅ ${check.name}`);
    }

    for (const bonus of score.bonuses) {
      lines.push(`- ✅ ${bonus}`);
    }

    lines.push('');
  }

  // Issues to address
  const allIssues = result.checks.flatMap(c => c.issues);

  if (allIssues.length > 0) {
    lines.push('## Things to Improve');
    lines.push('');

    // Group by severity, show max 5 total for readability
    const criticalIssues = allIssues.filter(i => i.severity === 'critical').slice(0, 2);
    const highIssues = allIssues.filter(i => i.severity === 'high').slice(0, 2);
    const mediumIssues = allIssues.filter(i => i.severity === 'medium').slice(0, 2);
    const priorityIssues = [...criticalIssues, ...highIssues, ...mediumIssues].slice(0, 5);

    for (const issue of priorityIssues) {
      const severityEmoji = issue.severity === 'critical' ? '🔴' :
                           issue.severity === 'high' ? '🟠' :
                           issue.severity === 'medium' ? '🟡' : '⚪';

      lines.push(`### ${severityEmoji} ${issue.title}`);
      lines.push('');

      // Friendly description
      lines.push(`**What this means:** ${issue.description}`);
      lines.push('');

      // Add analogy if we have one
      const analogy = getAnalogy(issue);
      if (analogy) {
        lines.push(`*${analogy}*`);
        lines.push('');
      }

      // Simple fix
      lines.push(`**How to fix:** ${issue.fix}`);
      lines.push('');
    }

    const remainingCount = allIssues.length - priorityIssues.length;
    if (remainingCount > 0) {
      lines.push(`*Plus ${remainingCount} more lower-priority items in the full report.*`);
      lines.push('');
    }
  } else {
    lines.push('## No Issues Found!');
    lines.push('');
    lines.push('Great job! We didn\'t find any security issues in our scan.');
    lines.push('');
  }

  // What we didn't check
  lines.push('---');
  lines.push('');
  lines.push('## What This Didn\'t Check');
  lines.push('');
  lines.push('This was a surface-level checkup. It doesn\'t test:');
  lines.push('- Server-side vulnerabilities');
  lines.push('- Database security');
  lines.push('- Login/authentication bypass');
  lines.push('- Your backend code');
  lines.push('');
  lines.push('*Think of it like checking tire pressure — useful, but doesn\'t mean you won\'t get a flat.*');
  lines.push('');

  // Footer
  lines.push('---');
  lines.push('');
  lines.push('*Generated by [URL Security Scanner](https://github.com/code-explorer-io)*');

  return lines.join('\n');
}
