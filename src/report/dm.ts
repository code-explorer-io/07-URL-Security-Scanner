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
 * Generate the intro DM message (no link, just value)
 * This is the first message to establish rapport
 */
export function generateDmIntro(
  result: ScanResult,
  score: SecurityScore,
  projectName?: string
): string {
  const domain = new URL(result.url).hostname;
  const allIssues = result.checks.flatMap(c => c.issues);

  // Get top 2-3 issues, prioritized for understandability
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

  // Opening - acknowledge their work
  if (projectName) {
    lines.push(`Hey! Love what you're building with ${projectName}.`);
  } else {
    lines.push(`Hey! Saw your project - looks cool.`);
  }

  lines.push('');

  // The value proposition
  lines.push(`Ran a quick security check (I do this for fun) and noticed a couple things:`);
  lines.push('');

  // List top issues briefly
  for (const issue of topIssues) {
    const friendly = getFriendlyName(issue);
    lines.push(`- ${friendly}`);
  }

  lines.push('');

  // Soft close - no pressure
  if (topIssues.length > 0) {
    lines.push(`All easy fixes (5-10 min each). Happy to share the details if useful!`);
  } else {
    lines.push(`Looking solid overall! Just a few minor tweaks if you want to polish it up.`);
  }

  return lines.join('\n');
}

/**
 * Generate the follow-up DM message (includes gist link)
 * Send this after they respond positively
 */
export function generateDmFollowup(gistUrl: string): string {
  const lines: string[] = [];

  lines.push(`Here's the full report with copy-paste fixes:`);
  lines.push(gistUrl);
  lines.push('');
  lines.push(`There's a prompt at the bottom you can paste into Cursor/Claude to fix everything automatically.`);
  lines.push('');
  lines.push(`No pressure - just thought it might help!`);

  return lines.join('\n');
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
  projectName?: string
): {
  intro: string;
  followup: string;
  tweet: string;
} {
  return {
    intro: generateDmIntro(result, score, projectName),
    followup: generateDmFollowup(gistUrl),
    tweet: generateTweetSummary(result, score)
  };
}
