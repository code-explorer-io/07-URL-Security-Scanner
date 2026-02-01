import { ScanResult } from '../types';

export interface SecurityScore {
  grade: 'A' | 'B' | 'C' | 'D' | 'F';
  score: number;
  maxScore: number;
  breakdown: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  bonuses: string[];
}

/**
 * Calculate security grade from scan results
 *
 * Scoring:
 * - Start at 100 points
 * - Critical: -30 each (max 2 counted to avoid overwhelming)
 * - High: -15 each
 * - Medium: -8 each
 * - Low: -3 each
 * - Bonuses: +5 each for good practices detected
 *
 * Grades:
 * - A: 90-100
 * - B: 75-89
 * - C: 60-74
 * - D: 40-59
 * - F: <40
 */
export function calculateScore(result: ScanResult, techDetails?: Record<string, unknown>): SecurityScore {
  let score = 100;
  const bonuses: string[] = [];

  // Deductions
  const criticalCount = Math.min(result.summary.critical, 2); // Cap at 2
  const highCount = result.summary.high;
  const mediumCount = result.summary.medium;
  const lowCount = result.summary.low;

  score -= criticalCount * 30;
  score -= highCount * 15;
  score -= mediumCount * 8;
  score -= lowCount * 3;

  // Bonuses for good practices
  const allDetails = result.checks.reduce((acc, check) => {
    if (check.details) {
      return { ...acc, ...check.details };
    }
    return acc;
  }, {} as Record<string, unknown>);

  // SSL bonus - valid certificate with good expiry
  const sslCheck = result.checks.find(c => c.name === 'SSL/TLS');
  if (sslCheck?.passed) {
    bonuses.push('Valid SSL certificate');
    score += 5;
  }

  // Headers bonus - has HSTS
  const headersCheck = result.checks.find(c => c.name === 'Security Headers');
  if (headersCheck?.details) {
    const details = headersCheck.details as Record<string, string | null>;
    if (details['Strict-Transport-Security']) {
      bonuses.push('HSTS enabled');
      score += 5;
    }
    if (details['Content-Security-Policy']) {
      bonuses.push('CSP configured');
      score += 5;
    }
  }

  // CDN/WAF bonus
  if (techDetails) {
    const detected = (techDetails.detected as Array<{ name: string; category: string }>) || [];
    if (detected.some(d => d.name === 'Cloudflare')) {
      bonuses.push('Cloudflare protection');
      score += 5;
    }
  }

  // DNS bonus - has SPF and DMARC
  const dnsCheck = result.checks.find(c => c.name === 'Email Security (DNS)');
  if (dnsCheck?.details) {
    const details = dnsCheck.details as { spf?: { exists: boolean }; dmarc?: { exists: boolean } };
    if (details.spf?.exists && details.dmarc?.exists) {
      bonuses.push('Email authentication configured');
      score += 5;
    }
  }

  // Ensure score stays in range
  score = Math.max(0, Math.min(100, score));

  // Determine grade
  let grade: 'A' | 'B' | 'C' | 'D' | 'F';
  if (score >= 90) {
    grade = 'A';
  } else if (score >= 75) {
    grade = 'B';
  } else if (score >= 60) {
    grade = 'C';
  } else if (score >= 40) {
    grade = 'D';
  } else {
    grade = 'F';
  }

  return {
    grade,
    score,
    maxScore: 100,
    breakdown: {
      critical: result.summary.critical,
      high: result.summary.high,
      medium: result.summary.medium,
      low: result.summary.low
    },
    bonuses
  };
}

/**
 * Get a human-friendly description of the grade
 */
export function getGradeDescription(grade: 'A' | 'B' | 'C' | 'D' | 'F'): string {
  switch (grade) {
    case 'A':
      return 'Excellent! Your security posture is solid.';
    case 'B':
      return 'Good! A few improvements would make it even better.';
    case 'C':
      return 'Fair. Some security gaps need attention.';
    case 'D':
      return 'Needs work. Several security issues should be addressed.';
    case 'F':
      return 'Critical issues found. Immediate action recommended.';
  }
}

/**
 * Get emoji for grade display
 */
export function getGradeEmoji(grade: 'A' | 'B' | 'C' | 'D' | 'F'): string {
  switch (grade) {
    case 'A':
      return '🟢';
    case 'B':
      return '🟢';
    case 'C':
      return '🟡';
    case 'D':
      return '🟠';
    case 'F':
      return '🔴';
  }
}
