import { ScanResult, SecurityIssue } from '../types';
import { SecurityScore } from './score';

/**
 * High-impact issue explanations - explain the ACTUAL RISK
 * These get special treatment in DMs because they're serious
 */
const HIGH_IMPACT_EXPLANATIONS: Record<string, { short: string; risk: string }> = {
  'No SPF record': {
    short: 'No SPF record',
    risk: 'anyone can send emails pretending to be you (@{domain}). Someone could email your users "from you" with phishing links. One-line DNS fix.'
  },
  'No DMARC record': {
    short: 'No DMARC record',
    risk: 'email spoofing protection is missing - works with SPF to stop fake emails.'
  },
  'API Key': {
    short: 'Exposed API key',
    risk: 'someone could use your API key and rack up charges on your account.'
  },
  'OpenAI': {
    short: 'OpenAI key exposed',
    risk: 'your OpenAI key is in your public code - someone could use it and you\'d get the bill.'
  },
  'Stripe': {
    short: 'Stripe key exposed',
    risk: 'payment credentials visible in your code - this needs fixing ASAP.'
  },
  'AWS': {
    short: 'AWS credentials exposed',
    risk: 'AWS keys in your code - someone could spin up servers on your account.'
  },
  'Environment file': {
    short: '.env file exposed',
    risk: 'your secrets file is publicly accessible - passwords, API keys, everything in there is visible.'
  },
};

/**
 * Lower-priority issues - still mention but don't emphasize
 */
const MINOR_ISSUE_NAMES: Record<string, string> = {
  'Content-Security-Policy': 'CSP header (blocks malicious scripts)',
  'X-Frame-Options': 'clickjacking protection',
  'X-Content-Type-Options': 'MIME sniffing protection',
  'Strict-Transport-Security': 'HTTPS enforcement',
  'Referrer-Policy': 'privacy setting',
  'Permissions-Policy': 'browser permissions',
  'Git config': 'git config exposed',
  'Source map': 'source maps visible',
};

/**
 * Check if an issue is high-impact (deserves full explanation)
 */
function getHighImpactExplanation(issue: SecurityIssue, domain: string): { short: string; risk: string } | null {
  for (const [key, explanation] of Object.entries(HIGH_IMPACT_EXPLANATIONS)) {
    if (issue.title.includes(key) || issue.description.includes(key)) {
      return {
        short: explanation.short,
        risk: explanation.risk.replace('{domain}', domain)
      };
    }
  }
  return null;
}

/**
 * Get a short name for minor issues
 */
function getMinorIssueName(issue: SecurityIssue): string {
  for (const [key, name] of Object.entries(MINOR_ISSUE_NAMES)) {
    if (issue.title.includes(key) || issue.description.includes(key)) {
      return name;
    }
  }
  // Fallback
  return issue.title.replace(/^Missing\s+/i, '').replace(/\s+header$/i, '').toLowerCase();
}

/**
 * Prioritize issues for DM - most understandable/impactful first
 */
function prioritizeForDm(issues: SecurityIssue[]): SecurityIssue[] {
  const priority: Record<string, number> = {
    // Critical stuff people understand
    'Exposed Secrets': 1,
    'API Key Exposure': 1,
    // Email is easy to understand
    'Email Security': 2,
    // Files are tangible
    'Exposed Files': 3,
    // Headers are abstract - put last
    'Security Headers': 4,
  };

  return [...issues].sort((a, b) => {
    const aPriority = priority[a.category] || 5;
    const bPriority = priority[b.category] || 5;
    if (aPriority !== bPriority) return aPriority - bPriority;
    // Within same category, sort by severity
    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    return severityOrder[a.severity] - severityOrder[b.severity];
  });
}

/**
 * Generate DM message - single message with link included
 * Explains the ACTUAL RISK for high-impact issues
 */
export function generateDmMessage(
  result: ScanResult,
  _score: SecurityScore,
  gistUrl?: string
): string {
  const domain = new URL(result.url).hostname;
  const allIssues = result.checks.flatMap(c => c.issues);

  // Get top issues, prioritized for understandability
  const prioritized = prioritizeForDm(allIssues);
  const filtered = prioritized
    .filter(i => i.severity === 'critical' || i.severity === 'high' || i.severity === 'medium');

  // Separate high-impact issues from minor ones
  const highImpact: { issue: SecurityIssue; explanation: { short: string; risk: string } }[] = [];
  const minor: SecurityIssue[] = [];
  const seenCategories = new Set<string>();

  for (const issue of filtered) {
    if (seenCategories.has(issue.category)) continue;
    seenCategories.add(issue.category);

    const explanation = getHighImpactExplanation(issue, domain);
    if (explanation) {
      highImpact.push({ issue, explanation });
    } else {
      minor.push(issue);
    }
  }

  const lines: string[] = [];

  // Opening
  lines.push(`Hey! Saw your site in the chat - looks great.`);
  lines.push('');
  lines.push(`Ran a quick security check (I do this for fun). Found something worth mentioning:`);
  lines.push('');

  // High-impact issues get full explanation
  if (highImpact.length > 0) {
    const main = highImpact[0];
    lines.push(`${main.explanation.short} - ${main.explanation.risk}`);

    // Additional high-impact issues (if any)
    for (let i = 1; i < Math.min(highImpact.length, 2); i++) {
      lines.push('');
      lines.push(`${highImpact[i].explanation.short} - ${highImpact[i].explanation.risk}`);
    }
  }

  // Minor issues get brief mention
  if (minor.length > 0 && highImpact.length > 0) {
    lines.push('');
    const minorNames = minor.slice(0, 3).map(i => getMinorIssueName(i)).join(', ');
    lines.push(`Also a couple minor things (${minorNames}) but the above is the main one.`);
  } else if (minor.length > 0) {
    // Only minor issues found
    for (const issue of minor.slice(0, 3)) {
      lines.push(`- ${getMinorIssueName(issue)}`);
    }
  }

  lines.push('');

  // Link and close
  if (gistUrl) {
    lines.push(`Got a detailed report here if you want it: ${gistUrl}`);
  } else {
    lines.push(`Happy to share the full details if useful!`);
  }

  lines.push('');
  lines.push(`The fixes are quick - you can paste them straight to your AI agent. Happy to help if you have questions!`);

  return lines.join('\n');
}

/**
 * Legacy function - now just calls generateDmMessage
 */
export function generateDmIntro(
  result: ScanResult,
  score: SecurityScore,
  _projectName?: string
): string {
  return generateDmMessage(result, score);
}

/**
 * Legacy function - kept for compatibility
 */
export function generateDmFollowup(gistUrl: string): string {
  return `Here's the full report: ${gistUrl}\n\nYou can paste the fixes straight to your AI agent.`;
}

/**
 * Generate a tweet-length summary (under 280 chars)
 * For public replies if appropriate
 */
export function generateTweetSummary(result: ScanResult, score: SecurityScore): string {
  const domain = new URL(result.url).hostname;
  const allIssues = result.checks.flatMap(c => c.issues);

  if (allIssues.length === 0) {
    return `Quick security check on ${domain}: Grade ${score.grade} - looking solid! No major issues found.`;
  }

  const topIssue = allIssues[0];
  const highImpact = getHighImpactExplanation(topIssue, domain);
  const issueName = highImpact ? highImpact.short : getMinorIssueName(topIssue);

  if (score.grade === 'A' || score.grade === 'B') {
    return `Quick security check on ${domain}: Grade ${score.grade}. Looking good! One small thing: ${issueName}. Easy fix.`;
  } else {
    return `Quick security check on ${domain}: Grade ${score.grade}. Found ${allIssues.length} things - main one is ${issueName}. Happy to share details!`;
  }
}

/**
 * Generate all DM content in one object
 */
export function generateDmContent(
  result: ScanResult,
  score: SecurityScore,
  gistUrl: string,
  _projectName?: string
): {
  message: string;
  tweet: string;
} {
  return {
    message: generateDmMessage(result, score, gistUrl),
    tweet: generateTweetSummary(result, score)
  };
}
