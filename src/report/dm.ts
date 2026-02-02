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
    risk: 'anyone can send emails pretending to be from your domain. One DNS record fixes this.'
  },
  'API Key': {
    short: 'Exposed API key',
    risk: 'someone could use your API key and rack up charges on your account.'
  },
  'Token exposed': {
    short: 'API token exposed in JavaScript',
    risk: 'someone could use your token to send emails/make API calls and you\'d get the bill.'
  },
  'Postmark': {
    short: 'Postmark email token exposed',
    risk: 'your Postmark token is in public JavaScript - anyone can send emails from your account.'
  },
  'SendGrid': {
    short: 'SendGrid API key exposed',
    risk: 'your SendGrid key is visible - someone could send emails as you or exhaust your quota.'
  },
  'Twilio': {
    short: 'Twilio credentials exposed',
    risk: 'your Twilio credentials are visible - someone could send SMS/calls on your account.'
  },
  'Mailgun': {
    short: 'Mailgun API key exposed',
    risk: 'your Mailgun key is visible - someone could send emails from your domain.'
  },
  'Resend': {
    short: 'Resend API key exposed',
    risk: 'your Resend key is in public code - anyone can send emails from your account.'
  },
  'OpenAI': {
    short: 'OpenAI key exposed',
    risk: 'your OpenAI key is in your public code - someone could use it and you\'d get the bill.'
  },
  'Anthropic': {
    short: 'Anthropic (Claude) key exposed',
    risk: 'your Claude API key is visible - someone could use your credits.'
  },
  'Stripe Secret': {
    short: 'Stripe SECRET key exposed',
    risk: 'your Stripe secret key is visible - this gives full access to your payment data!'
  },
  'Firebase Private': {
    short: 'Firebase admin key exposed',
    risk: 'your Firebase admin credentials are visible - full access to your database.'
  },
  'MongoDB': {
    short: 'Database credentials exposed',
    risk: 'your database connection string is visible - anyone can access your data.'
  },
  'PostgreSQL': {
    short: 'Database credentials exposed',
    risk: 'your database connection string is visible - anyone can access your data.'
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
  // Services popular with vibe coders
  'Supabase': {
    short: 'Supabase key exposed',
    risk: 'your Supabase service key is visible - this bypasses Row Level Security (anyone can read/write your database).'
  },
  'Firebase': {
    short: 'Firebase credentials exposed',
    risk: 'Firebase admin credentials are visible - full access to your Firebase project.'
  },
  'Clerk': {
    short: 'Clerk secret key exposed',
    risk: 'your auth system secret key is visible - full access to user data.'
  },
  'PlanetScale': {
    short: 'Database URL exposed',
    risk: 'your database connection string is public - full database access.'
  },
  'Neon': {
    short: 'Database URL exposed',
    risk: 'your Postgres connection string is public - anyone can read your database.'
  },
  'Vercel': {
    short: 'Vercel token exposed',
    risk: 'your deployment token is visible - someone could deploy to your project.'
  },
};

/**
 * Medium-priority issues - explain like talking to a friend who doesn't code
 * Format: { name: simple name, why: plain English consequence }
 */
/**
 * Medium-priority issues - structured for clarity:
 * - term: the technical name (what devs call it)
 * - means: plain English explanation
 * - bad: why this actually matters (the consequence)
 */
const MEDIUM_IMPACT_EXPLANATIONS: Record<string, { term: string; means: string; bad: string }> = {
  'CORS': {
    term: 'CORS allows any origin',
    means: 'any website can request data from your site and your site will respond',
    bad: 'if you store user info, other sites could read it'
  },
  'Content-Security-Policy': {
    term: 'Missing Content Security Policy',
    means: 'your site doesn\'t tell browsers which scripts are allowed to run',
    bad: 'if someone injects bad code, visitors\' browsers will run it (this is how data gets stolen)'
  },
  'X-Frame-Options': {
    term: 'Missing X-Frame-Options',
    means: 'your site can be embedded inside other websites',
    bad: 'scammers put your site in a fake page and trick people into clicking things (called clickjacking)'
  },
  'X-Content-Type-Options': {
    term: 'Missing X-Content-Type-Options',
    means: 'browsers guess what type files are instead of being told',
    bad: 'can cause weird security issues (easy one-liner fix though)'
  },
  'Strict-Transport-Security': {
    term: 'HTTPS not enforced',
    means: 'browsers can still visit the http:// version of your site',
    bad: 'someone on the same WiFi could see everything your visitors type (passwords, etc)'
  },
};

/**
 * Lower-priority issues - just name them simply
 */
const MINOR_ISSUE_NAMES: Record<string, string> = {
  'Referrer-Policy': 'privacy setting',
  'Permissions-Policy': 'browser permissions',
  'X-XSS-Protection': 'legacy browser protection',
  'X-Powered-By': 'server info visible (tells hackers what software you use)',
  'Git config': 'git config exposed',
  'Source map': 'source code visible',
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
 * Get medium-impact explanation (with "why it matters")
 */
function getMediumImpactExplanation(issue: SecurityIssue): { term: string; means: string; bad: string } | null {
  for (const [key, explanation] of Object.entries(MEDIUM_IMPACT_EXPLANATIONS)) {
    if (issue.title.includes(key) || issue.description.includes(key) || issue.category.includes(key)) {
      return explanation;
    }
  }
  return null;
}

/**
 * Get a short name for minor issues
 */
function getMinorIssueName(issue: SecurityIssue): string {
  // First check medium-impact (return just the term part)
  const medium = getMediumImpactExplanation(issue);
  if (medium) return medium.term;

  // Then check minor issues
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
    // SSL issues are tangible (browser warnings)
    'SSL/TLS': 3,
    // Files are tangible
    'Exposed Files': 4,
    // CORS is more technical
    'CORS': 5,
    // Headers are abstract - put last
    'Security Headers': 6,
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

  // Separate by severity level
  const significantIssues = prioritized.filter(i =>
    i.severity === 'critical' || i.severity === 'high' || i.severity === 'medium'
  );
  const lowIssues = prioritized.filter(i => i.severity === 'low');

  // Separate issues into tiers: high-impact, medium-impact, minor
  const highImpact: { issue: SecurityIssue; explanation: { short: string; risk: string } }[] = [];
  const mediumImpact: { issue: SecurityIssue; explanation: { term: string; means: string; bad: string } }[] = [];
  const minor: SecurityIssue[] = [];
  const seenCategories = new Set<string>();

  for (const issue of significantIssues) {
    if (seenCategories.has(issue.category)) continue;
    seenCategories.add(issue.category);

    const highExplanation = getHighImpactExplanation(issue, domain);
    if (highExplanation) {
      highImpact.push({ issue, explanation: highExplanation });
      continue;
    }

    const mediumExplanation = getMediumImpactExplanation(issue);
    if (mediumExplanation) {
      mediumImpact.push({ issue, explanation: mediumExplanation });
      continue;
    }

    minor.push(issue);
  }

  const lines: string[] = [];

  // Opening
  lines.push(`Hey! Saw your site in the chat - looks great.`);
  lines.push('');

  // Handle clean sites (no significant issues)
  if (highImpact.length === 0 && mediumImpact.length === 0 && minor.length === 0) {
    // Check if there are only LOW severity issues
    if (lowIssues.length > 0) {
      lines.push(`Ran a quick security check (I do this for fun) - your site is looking solid!`);
      lines.push('');
      lines.push(`Just one small thing (really minor): ${getMinorIssueName(lowIssues[0])}. Easy 2-minute fix if you want to tighten things up.`);
      if (lowIssues.length > 1) {
        const otherLow = lowIssues.slice(1, 3).map(i => getMinorIssueName(i)).join(', ');
        lines.push('');
        lines.push(`Also spotted: ${otherLow} - but honestly these are just nice-to-haves.`);
      }
      lines.push('');
      lines.push(`Happy to share the full details if you want them. Let me know if you need anything else!`);
      return lines.join('\n');
    }

    // Truly clean - no issues at all
    lines.push(`Ran a quick security check (I do this for fun) and didn't find any issues - nice work!`);
    lines.push('');
    lines.push(`Always cool to see someone shipping with security in mind.`);
    lines.push('');
    lines.push(`Let me know if you need anything else!`);
    return lines.join('\n');
  }

  lines.push(`Ran a quick security check (I do this for fun). Found something worth mentioning:`);
  lines.push('');

  // Track issue number for readability
  let issueNum = 1;

  // High-impact issues get full explanation with new format
  if (highImpact.length > 0) {
    const main = highImpact[0];
    lines.push(`${issueNum}. ${main.explanation.short}`);
    lines.push(`What this means: ${main.explanation.risk}`);
    issueNum++;

    // Additional high-impact issues (if any)
    for (const item of highImpact.slice(1, 3)) {
      lines.push('');
      lines.push(`${issueNum}. ${item.explanation.short}`);
      issueNum++;
    }
  }

  // Medium-impact issues get beginner-friendly explanation
  if (mediumImpact.length > 0) {
    // If we already have high-impact, be brief with medium
    if (highImpact.length > 0) {
      lines.push('');
      for (const item of mediumImpact.slice(0, 2)) {
        lines.push(`${issueNum}. ${item.explanation.term}`);
        issueNum++;
      }
    } else {
      // Medium is the top priority - give full explanation with new format
      const main = mediumImpact[0];
      lines.push(`${issueNum}. ${main.explanation.term}`);
      lines.push(`What this means: ${main.explanation.means}. ${main.explanation.bad}.`);
      issueNum++;

      // Additional medium-impact issues (brief)
      for (const item of mediumImpact.slice(1, 3)) {
        lines.push('');
        lines.push(`${issueNum}. ${item.explanation.term}`);
        issueNum++;
      }

      // If we ONLY found header issues (no API keys, no exposed files, etc.)
      // add honest context - headers are the least impactful thing we check
      const allCategories = new Set(significantIssues.map(i => i.category));
      const onlyHeaders = allCategories.size === 1 && allCategories.has('Security Headers');
      if (onlyHeaders) {
        lines.push('');
        lines.push(`(These are mostly best-practice headers - not urgent, but worth adding when you have time.)`);
      }
    }
  }

  // Minor issues get brief mention
  if (minor.length > 0 && (highImpact.length > 0 || mediumImpact.length > 0)) {
    lines.push('');
    const minorNames = minor.slice(0, 2).map(i => getMinorIssueName(i)).join(', ');
    lines.push(`Plus some smaller things (${minorNames}).`);
  } else if (minor.length > 0) {
    // Only minor issues found
    for (const issue of minor.slice(0, 3)) {
      lines.push(`${issueNum}. ${getMinorIssueName(issue)}`);
      issueNum++;
    }
  }

  lines.push('');

  // Link and close (only show real gist URLs, not placeholder)
  if (gistUrl && !gistUrl.includes('gist-url-here')) {
    lines.push(`Got a detailed report here if you want it: ${gistUrl}`);
  } else {
    lines.push(`Happy to share the full details if useful!`);
  }

  lines.push('');
  lines.push(`Let me know if you need anything else!`);

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
