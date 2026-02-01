import { ScanResult, SecurityIssue } from '../types';
import { SecurityScore } from './score';

/**
 * Short, friendly descriptions for DM messages
 * Written like you're texting a friend, not writing a security report
 * NO jargon - explain like they're 10 years old
 */
const FRIENDLY_ISSUE_NAMES: Record<string, string> = {
  // Email security
  'No SPF record': 'anyone can send emails pretending to be you',
  'No DMARC record': 'email spoofing protection is missing',

  // Headers - explain benefit simply
  'Content-Security-Policy': 'a security setting that blocks malicious code',
  'Strict-Transport-Security': 'a setting to force secure connections',
  'X-Frame-Options': 'a setting to prevent your site being copied/faked',
  'X-Content-Type-Options': 'a small security tweak',
  'Referrer-Policy': 'a privacy setting',
  'Permissions-Policy': 'a browser permissions setting',

  // The big ones - these matter, be clear
  'API Key': 'an API key sitting in your public code',
  'OpenAI': 'your OpenAI key is visible (someone could use it)',
  'Stripe': 'a Stripe key visible in your code',
  'AWS': 'AWS credentials in your code',
  'GitHub': 'a GitHub token in your code',
  'Anthropic': 'your Claude API key is visible',
  'MongoDB': 'your database password is in the code',
  'Postgres': 'database credentials are visible',

  // Files
  'Environment file': 'your .env file is publicly visible',
  'Git config': 'your code history is exposed',
  'Source map': 'your original source code is visible',
  'Database': 'a database backup is accessible',
};

/**
 * Get a friendly name for an issue
 * Format: "Technical Term - simple explanation"
 * This helps both humans understand AND gives AI agents the technical context to fix
 */
function getFriendlyName(issue: SecurityIssue): string {
  for (const [key, friendly] of Object.entries(FRIENDLY_ISSUE_NAMES)) {
    if (issue.title.includes(key) || issue.description.includes(key)) {
      // Return both technical term and friendly explanation
      return `${key} - ${friendly}`;
    }
  }
  // Fallback: use title but make it lowercase and friendly
  const technicalTerm = issue.title.replace(/^Missing\s+/i, '').replace(/\s+header$/i, '');
  return `${technicalTerm} - security setting that could be improved`;
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
 * Clean, friendly, no pressure
 */
export function generateDmMessage(
  result: ScanResult,
  _score: SecurityScore,
  gistUrl?: string
): string {
  const allIssues = result.checks.flatMap(c => c.issues);

  // Get top issues, prioritized for understandability
  const prioritized = prioritizeForDm(allIssues);
  const filtered = prioritized
    .filter(i => i.severity === 'critical' || i.severity === 'high' || i.severity === 'medium');

  // Dedupe by category - only show one issue per category in DM
  const seenCategories = new Set<string>();
  const topIssues: SecurityIssue[] = [];
  for (const issue of filtered) {
    if (!seenCategories.has(issue.category) && topIssues.length < 3) {
      seenCategories.add(issue.category);
      topIssues.push(issue);
    }
  }

  const lines: string[] = [];

  // Opening
  lines.push(`Hey! Saw your site in the chat - looks great.`);
  lines.push('');

  // The value
  lines.push(`Ran a quick security check (I do this for fun). Found a few small things:`);
  lines.push('');

  // List issues
  for (const issue of topIssues) {
    const friendly = getFriendlyName(issue);
    lines.push(`- ${friendly}`);
  }

  lines.push('');

  // Link and close
  if (gistUrl) {
    lines.push(`Nothing major, easy fixes. Got a detailed report here if you want it: ${gistUrl}`);
  } else {
    lines.push(`Nothing major, easy fixes. Happy to share details if useful!`);
  }

  lines.push('');
  lines.push(`You can paste the fixes straight to your AI agent. Happy to help if you have questions.`);

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
  const friendly = getFriendlyName(topIssue);

  if (score.grade === 'A' || score.grade === 'B') {
    return `Quick security check on ${domain}: Grade ${score.grade}. Looking good! One small thing: ${friendly}. Easy 5 min fix.`;
  } else {
    return `Quick security check on ${domain}: Grade ${score.grade}. Found ${allIssues.length} things to look at - main one is ${friendly}. Happy to share details!`;
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
