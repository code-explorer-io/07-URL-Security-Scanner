export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface SecurityIssue {
  id: string;
  severity: Severity;
  category: string;
  title: string;
  description: string;
  fix: string;
}

export interface CheckResult {
  name: string;
  passed: boolean;
  issues: SecurityIssue[];
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  details?: any;
}

export interface ScanResult {
  url: string;
  timestamp: string;
  duration: number;
  checks: CheckResult[];
  summary: {
    total: number;
    passed: number;
    failed: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
}

export interface ScanOptions {
  url: string;
  timeout?: number;
  userAgent?: string;
  verbose?: boolean;
}
