import { CheckResult, SecurityIssue } from '../types';
import * as dns from 'dns';
import { promisify } from 'util';

const resolveTxt = promisify(dns.resolveTxt);

interface DnsSecurityDetails {
  domain: string;
  spf: {
    exists: boolean;
    record: string | null;
    policy: string | null;
  };
  dmarc: {
    exists: boolean;
    record: string | null;
    policy: string | null;
  };
  hasMxRecords: boolean;
}

/**
 * Extract domain from URL
 */
function extractDomain(url: string): string {
  try {
    const parsed = new URL(url);
    return parsed.hostname;
  } catch {
    return url;
  }
}

/**
 * Parse SPF record to extract policy
 */
function parseSpfPolicy(record: string): string | null {
  // SPF ends with -all (fail), ~all (softfail), ?all (neutral), +all (pass)
  if (record.includes('-all')) return 'fail';
  if (record.includes('~all')) return 'softfail';
  if (record.includes('?all')) return 'neutral';
  if (record.includes('+all')) return 'pass';
  return null;
}

/**
 * Parse DMARC record to extract policy
 */
function parseDmarcPolicy(record: string): string | null {
  const match = record.match(/p=(none|quarantine|reject)/i);
  return match ? match[1].toLowerCase() : null;
}

export async function checkDnsSecurity(url: string): Promise<CheckResult> {
  const issues: SecurityIssue[] = [];
  const domain = extractDomain(url);

  const details: DnsSecurityDetails = {
    domain,
    spf: { exists: false, record: null, policy: null },
    dmarc: { exists: false, record: null, policy: null },
    hasMxRecords: false
  };

  // Check if domain has MX records (sends email)
  try {
    const mxRecords = await promisify(dns.resolveMx)(domain);
    details.hasMxRecords = mxRecords && mxRecords.length > 0;
  } catch {
    details.hasMxRecords = false;
  }

  // Check SPF record
  try {
    const txtRecords = await resolveTxt(domain);
    const flatRecords = txtRecords.map(r => r.join(''));
    const spfRecord = flatRecords.find(r => r.toLowerCase().startsWith('v=spf1'));

    if (spfRecord) {
      details.spf.exists = true;
      details.spf.record = spfRecord;
      details.spf.policy = parseSpfPolicy(spfRecord);

      // Check for weak SPF policy
      if (details.spf.policy === 'pass') {
        issues.push({
          id: 'dns-spf-permissive',
          severity: 'high',
          category: 'Email Security',
          title: 'SPF policy is too permissive (+all)',
          description: 'Your SPF record ends with +all which allows anyone to send email as your domain',
          fix: 'Change +all to ~all or -all in your SPF record'
        });
      }
    } else {
      details.spf.exists = false;
      issues.push({
        id: 'dns-no-spf',
        severity: 'medium',
        category: 'Email Security',
        title: 'No SPF record found',
        description: 'Without SPF, anyone can send emails pretending to be from your domain. This is like having no caller ID on your phone.',
        fix: `Add a TXT record to your DNS: v=spf1 include:_spf.google.com ~all (adjust based on your email provider)`
      });
    }
  } catch (error) {
    // DNS lookup failed - might be no TXT records
    issues.push({
      id: 'dns-no-spf',
      severity: 'medium',
      category: 'Email Security',
      title: 'No SPF record found',
      description: 'Without SPF, anyone can send emails pretending to be from your domain',
      fix: 'Add a TXT record to your DNS with your SPF policy'
    });
  }

  // Check DMARC record
  try {
    const dmarcRecords = await resolveTxt(`_dmarc.${domain}`);
    const flatRecords = dmarcRecords.map(r => r.join(''));
    const dmarcRecord = flatRecords.find(r => r.toLowerCase().startsWith('v=dmarc1'));

    if (dmarcRecord) {
      details.dmarc.exists = true;
      details.dmarc.record = dmarcRecord;
      details.dmarc.policy = parseDmarcPolicy(dmarcRecord);

      // Check for weak DMARC policy
      if (details.dmarc.policy === 'none') {
        issues.push({
          id: 'dns-dmarc-none',
          severity: 'low',
          category: 'Email Security',
          title: 'DMARC policy is set to "none"',
          description: 'DMARC is configured but set to monitoring only. Spoofed emails are not rejected.',
          fix: 'Consider changing DMARC policy from p=none to p=quarantine or p=reject after monitoring'
        });
      }
    } else {
      details.dmarc.exists = false;
      issues.push({
        id: 'dns-no-dmarc',
        severity: 'medium',
        category: 'Email Security',
        title: 'No DMARC record found',
        description: 'DMARC tells email servers what to do when SPF/DKIM checks fail. Without it, spoofed emails may still be delivered.',
        fix: `Add a TXT record for _dmarc.${domain}: v=DMARC1; p=quarantine; rua=mailto:dmarc@${domain}`
      });
    }
  } catch {
    // No DMARC record
    issues.push({
      id: 'dns-no-dmarc',
      severity: 'medium',
      category: 'Email Security',
      title: 'No DMARC record found',
      description: 'DMARC tells email servers what to do when SPF/DKIM checks fail. Without it, spoofed emails may still be delivered.',
      fix: `Add a TXT record for _dmarc.${domain}: v=DMARC1; p=quarantine; rua=mailto:dmarc@${domain}`
    });
  }

  return {
    name: 'Email Security (DNS)',
    passed: issues.length === 0,
    issues,
    details
  };
}
