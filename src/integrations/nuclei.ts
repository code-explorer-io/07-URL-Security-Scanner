/**
 * Nuclei Scanner Integration
 *
 * Nuclei is a fast, customizable vulnerability scanner with 21k+ GitHub stars.
 * Uses YAML templates to detect specific vulnerabilities.
 *
 * @see https://github.com/projectdiscovery/nuclei
 *
 * Installation:
 *   go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
 *   OR
 *   brew install nuclei (macOS)
 *   OR
 *   Download from https://github.com/projectdiscovery/nuclei/releases
 */

import { spawn } from 'child_process';
import * as path from 'path';
import * as fs from 'fs';

// Check for local Nuclei installation in tools/ directory
function getNucleiPath(): string {
  // Try multiple possible locations
  const possiblePaths = [
    // From dist/integrations/ -> tools/
    path.join(__dirname, '../../tools/nuclei.exe'),
    // From project root
    path.join(process.cwd(), 'tools/nuclei.exe'),
    // Absolute fallback
    'C:\\Users\\Code Explorer\\Documents\\GitHub\\07-URL-Security-Scanner\\tools\\nuclei.exe'
  ];

  for (const p of possiblePaths) {
    if (fs.existsSync(p)) {
      return p;
    }
  }

  // Fall back to system PATH
  return 'nuclei';
}

export interface NucleiResult {
  templateId: string;
  info: {
    name: string;
    severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
    description?: string;
    tags?: string[];
  };
  matcherName?: string;
  type: string;
  host: string;
  matched: string;
  extractedResults?: string[];
  timestamp: string;
}

export interface NucleiScanResult {
  available: boolean;
  version?: string;
  findings: NucleiResult[];
  error?: string;
  duration?: number;
}

/**
 * Check if Nuclei is installed and get version
 */
export async function isNucleiAvailable(): Promise<{ available: boolean; version?: string }> {
  return new Promise((resolve) => {
    const nucleiPath = getNucleiPath();
    const nucleiProcess = spawn(nucleiPath, ['-version'], {
      timeout: 5000
    });

    let output = '';

    nucleiProcess.stdout.on('data', (data) => {
      output += data.toString();
    });

    nucleiProcess.stderr.on('data', (data) => {
      output += data.toString();
    });

    nucleiProcess.on('close', (code) => {
      if (code === 0 || output.includes('Nuclei')) {
        // Extract version from output like "Nuclei v3.3.2"
        const versionMatch = output.match(/v?(\d+\.\d+\.\d+)/);
        resolve({
          available: true,
          version: versionMatch ? versionMatch[1] : 'unknown'
        });
      } else {
        resolve({ available: false });
      }
    });

    nucleiProcess.on('error', () => {
      resolve({ available: false });
    });
  });
}

/**
 * Map detected tech stack to Nuclei template tags
 */
function getTechStackTags(techStack: string[]): string[] {
  const tagMap: Record<string, string[]> = {
    // Frameworks
    'Next.js': ['nextjs', 'react'],
    'React': ['react'],
    'Vue.js': ['vue'],
    'Angular': ['angular'],
    'WordPress': ['wordpress', 'wp'],
    'Laravel': ['laravel', 'php'],
    'Django': ['django', 'python'],
    'Express': ['express', 'nodejs'],
    'Rails': ['rails', 'ruby'],

    // Hosting/CDN
    'Vercel': ['vercel'],
    'Netlify': ['netlify'],
    'Cloudflare': ['cloudflare'],
    'AWS': ['aws', 'amazon'],
    'Firebase': ['firebase', 'google'],

    // Databases
    'Supabase': ['supabase'],
    'MongoDB': ['mongodb'],
    'PostgreSQL': ['postgres'],

    // CMS
    'Strapi': ['strapi'],
    'Ghost': ['ghost'],
    'Sanity': ['sanity'],
  };

  const tags = new Set<string>();

  for (const tech of techStack) {
    const matchedTags = tagMap[tech];
    if (matchedTags) {
      matchedTags.forEach(tag => tags.add(tag));
    }
  }

  // Always include common web security checks
  tags.add('exposure');
  tags.add('misconfig');
  tags.add('cve');

  return Array.from(tags);
}

/**
 * Run Nuclei scan with specific templates
 *
 * @param url - Target URL to scan
 * @param options - Scan options
 */
export async function runNucleiScan(
  url: string,
  options: {
    techStack?: string[];
    severity?: ('info' | 'low' | 'medium' | 'high' | 'critical')[];
    timeout?: number;
    verbose?: boolean;
  } = {}
): Promise<NucleiScanResult> {
  const startTime = Date.now();

  // Check if Nuclei is available
  const { available, version } = await isNucleiAvailable();

  if (!available) {
    return {
      available: false,
      findings: [],
      error: 'Nuclei not installed. Install with: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest'
    };
  }

  const {
    techStack = [],
    severity = ['medium', 'high', 'critical'],
    timeout = 120000, // 2 minutes default
    verbose = false
  } = options;

  // Build Nuclei command arguments
  const args: string[] = [
    '-u', url,
    '-json',           // JSON output for parsing
    '-silent',         // Suppress banner
    '-no-color',       // No ANSI colors
    '-timeout', '10',  // Request timeout in seconds
  ];

  // Add severity filter
  if (severity.length > 0) {
    args.push('-severity', severity.join(','));
  }

  // Add tech-stack specific tags if we have them
  if (techStack.length > 0) {
    const tags = getTechStackTags(techStack);
    if (tags.length > 0) {
      args.push('-tags', tags.join(','));
    }
  } else {
    // Default: focus on exposures and misconfigurations (fast, high-value)
    args.push('-tags', 'exposure,misconfig,token,api');
  }

  // Limit templates for speed
  args.push('-rl', '50');      // Rate limit: 50 requests/second
  args.push('-c', '25');       // Concurrency: 25 templates

  const nucleiPath = getNucleiPath();

  if (verbose) {
    console.log(`  Running Nuclei (${version})...`);
    console.log(`    Command: ${nucleiPath} ${args.join(' ')}`);
  }

  return new Promise((resolve) => {
    const findings: NucleiResult[] = [];
    let stderr = '';

    const nucleiProcess = spawn(nucleiPath, args, {
      timeout
    });

    nucleiProcess.stdout.on('data', (data) => {
      const lines = data.toString().trim().split('\n');
      for (const line of lines) {
        if (line.startsWith('{')) {
          try {
            const result = JSON.parse(line) as NucleiResult;
            findings.push(result);
            if (verbose) {
              console.log(`    Found: [${result.info.severity}] ${result.info.name}`);
            }
          } catch {
            // Not valid JSON, skip
          }
        }
      }
    });

    nucleiProcess.stderr.on('data', (data) => {
      stderr += data.toString();
    });

    nucleiProcess.on('close', (code) => {
      const duration = Date.now() - startTime;

      if (code === 0 || findings.length > 0) {
        resolve({
          available: true,
          version,
          findings,
          duration
        });
      } else {
        resolve({
          available: true,
          version,
          findings: [],
          error: stderr || `Nuclei exited with code ${code}`,
          duration
        });
      }
    });

    nucleiProcess.on('error', (err) => {
      resolve({
        available: true,
        version,
        findings: [],
        error: `Failed to run Nuclei: ${err.message}`,
        duration: Date.now() - startTime
      });
    });

    // Handle timeout
    setTimeout(() => {
      nucleiProcess.kill();
      resolve({
        available: true,
        version,
        findings,
        error: 'Nuclei scan timed out',
        duration: timeout
      });
    }, timeout);
  });
}

/**
 * Convert Nuclei findings to our SecurityIssue format
 */
export function nucleiToSecurityIssues(findings: NucleiResult[]): Array<{
  id: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  category: string;
  title: string;
  description: string;
  fix: string;
}> {
  return findings.map(finding => ({
    id: `nuclei-${finding.templateId}`,
    severity: finding.info.severity,
    category: 'Vulnerability Scan',
    title: `[Nuclei] ${finding.info.name}`,
    description: finding.info.description || `Found by Nuclei template: ${finding.templateId}. Matched: ${finding.matched}`,
    fix: `Review the Nuclei finding and apply appropriate fix. Template: ${finding.templateId}`
  }));
}

/**
 * Quick Nuclei check - fast scan for common exposures only
 * Good for initial outreach scans
 */
export async function quickNucleiScan(
  url: string,
  verbose = false
): Promise<NucleiScanResult> {
  return runNucleiScan(url, {
    severity: ['high', 'critical'],
    timeout: 60000, // 1 minute
    verbose
  });
}

/**
 * Get installation instructions for the current platform
 */
export function getNucleiInstallInstructions(): string {
  const platform = process.platform;

  if (platform === 'darwin') {
    return `
Install Nuclei on macOS:
  brew install nuclei

Or with Go:
  go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

Then update templates:
  nuclei -update-templates
`;
  } else if (platform === 'win32') {
    return `
Install Nuclei on Windows:
  1. Download from: https://github.com/projectdiscovery/nuclei/releases
  2. Extract and add to PATH

Or with Go:
  go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

Then update templates:
  nuclei -update-templates
`;
  } else {
    return `
Install Nuclei on Linux:
  # Download latest release
  wget https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_linux_amd64.zip
  unzip nuclei_linux_amd64.zip
  sudo mv nuclei /usr/local/bin/

Or with Go:
  go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

Then update templates:
  nuclei -update-templates
`;
  }
}
