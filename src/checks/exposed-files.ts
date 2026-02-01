import { CheckResult, SecurityIssue } from '../types';

interface SensitiveFile {
  path: string;
  name: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  description: string;
  fix: string;
  // Content validator - returns true if content matches expected file type
  validator?: (content: string, contentType: string) => boolean;
}

// Content validators to prevent false positives from SPAs returning HTML for all routes
const validators = {
  // .env files should have KEY=VALUE pattern
  envFile: (content: string, contentType: string): boolean => {
    // If it's HTML, it's definitely not an env file
    if (contentType.includes('text/html')) return false;
    if (content.trim().startsWith('<!DOCTYPE') || content.trim().startsWith('<html')) return false;
    // Check for at least one KEY=VALUE pattern (common env var format)
    return /^[A-Z_][A-Z0-9_]*\s*=.+/m.test(content);
  },

  // Git config should have [section] format
  gitConfig: (content: string, contentType: string): boolean => {
    if (contentType.includes('text/html')) return false;
    if (content.trim().startsWith('<!DOCTYPE') || content.trim().startsWith('<html')) return false;
    return /\[(core|remote|branch|user|submodule)/i.test(content);
  },

  // Git HEAD should reference a branch
  gitHead: (content: string, contentType: string): boolean => {
    if (contentType.includes('text/html')) return false;
    return /^ref: refs\/(heads|tags)\//.test(content.trim()) || /^[a-f0-9]{40}$/.test(content.trim());
  },

  // SQL files should have SQL syntax
  sqlFile: (content: string, contentType: string): boolean => {
    if (contentType.includes('text/html')) return false;
    if (content.trim().startsWith('<!DOCTYPE') || content.trim().startsWith('<html')) return false;
    return /(CREATE TABLE|INSERT INTO|DROP TABLE|SELECT \* FROM|ALTER TABLE|--.*dump)/i.test(content);
  },

  // Source maps should be valid JSON with specific keys
  sourceMap: (content: string, contentType: string): boolean => {
    if (contentType.includes('text/html')) return false;
    try {
      const parsed = JSON.parse(content);
      return 'version' in parsed && ('sources' in parsed || 'mappings' in parsed);
    } catch {
      return false;
    }
  },

  // PHP info should contain phpinfo output markers
  phpInfo: (content: string, _contentType: string): boolean => {
    return content.includes('PHP Version') && content.includes('Configuration');
  },

  // Log files should look like logs, not HTML
  logFile: (content: string, contentType: string): boolean => {
    if (contentType.includes('text/html')) return false;
    if (content.trim().startsWith('<!DOCTYPE') || content.trim().startsWith('<html')) return false;
    // Log files typically have timestamps or log level indicators
    return /\d{4}[-/]\d{2}[-/]\d{2}|\[error\]|\[warning\]|\[info\]|\[debug\]/i.test(content);
  },

  // JSON config files
  jsonConfig: (content: string, contentType: string): boolean => {
    if (contentType.includes('text/html')) return false;
    try {
      JSON.parse(content);
      return true;
    } catch {
      return false;
    }
  },

  // Gitignore should have typical patterns
  gitignore: (content: string, contentType: string): boolean => {
    if (contentType.includes('text/html')) return false;
    if (content.trim().startsWith('<!DOCTYPE') || content.trim().startsWith('<html')) return false;
    // Should have file patterns like *.log, node_modules, etc.
    return /^[#*\/\w\.\-]+$/m.test(content) && (
      content.includes('node_modules') ||
      content.includes('.env') ||
      content.includes('*.log') ||
      content.includes('.git') ||
      content.includes('dist/') ||
      content.includes('build/')
    );
  },

  // Archive files - check magic bytes (first few chars when converted)
  archiveFile: (content: string, contentType: string): boolean => {
    // ZIP files start with PK
    if (content.startsWith('PK')) return true;
    // Gzip starts with specific bytes
    if (content.charCodeAt(0) === 0x1f && content.charCodeAt(1) === 0x8b) return true;
    // Check content-type
    return contentType.includes('application/zip') ||
           contentType.includes('application/gzip') ||
           contentType.includes('application/x-tar') ||
           contentType.includes('application/octet-stream');
  },

  // PHP config files - should contain PHP code with db credentials patterns
  phpConfig: (content: string, _contentType: string): boolean => {
    // If served as text/html and contains PHP tags, it might be exposed source
    if (content.includes('<?php') || content.includes('<?=')) {
      return content.includes('DB_') || content.includes('database') || content.includes('password');
    }
    return false;
  },

  // Package.json should be valid JSON with name/version
  packageJson: (content: string, contentType: string): boolean => {
    if (contentType.includes('text/html')) return false;
    try {
      const parsed = JSON.parse(content);
      return 'name' in parsed || 'version' in parsed || 'dependencies' in parsed;
    } catch {
      return false;
    }
  },

  // Composer files
  composerJson: (content: string, contentType: string): boolean => {
    if (contentType.includes('text/html')) return false;
    try {
      const parsed = JSON.parse(content);
      return 'require' in parsed || 'autoload' in parsed || 'name' in parsed;
    } catch {
      return false;
    }
  }
};

const SENSITIVE_FILES: SensitiveFile[] = [
  // Critical - Environment files (most important for vibe coders)
  {
    path: '/.env',
    name: 'Environment file',
    severity: 'critical',
    description: 'Environment file contains API keys, database passwords, and secrets',
    fix: 'Block access to .env files in your web server config',
    validator: validators.envFile
  },
  {
    path: '/.env.local',
    name: 'Local environment file',
    severity: 'critical',
    description: 'Local environment file may contain development secrets',
    fix: 'Block access to .env* files in your web server config',
    validator: validators.envFile
  },
  {
    path: '/.env.production',
    name: 'Production environment file',
    severity: 'critical',
    description: 'Production secrets exposed',
    fix: 'Block access to .env* files in your web server config',
    validator: validators.envFile
  },

  // Critical - Git exposure
  {
    path: '/.git/config',
    name: 'Git config',
    severity: 'critical',
    description: 'Git repository exposed - attackers can download your entire source code',
    fix: 'Block access to .git directory in your web server or hosting config',
    validator: validators.gitConfig
  },
  {
    path: '/.git/HEAD',
    name: 'Git HEAD',
    severity: 'critical',
    description: 'Git repository exposed - source code can be reconstructed',
    fix: 'Block access to .git directory in your web server config',
    validator: validators.gitHead
  },

  // Critical - Database dumps
  {
    path: '/backup.sql',
    name: 'SQL backup',
    severity: 'critical',
    description: 'Database backup exposed - contains all your data',
    fix: 'Remove backup files from web root and never store them publicly',
    validator: validators.sqlFile
  },
  {
    path: '/database.sql',
    name: 'Database dump',
    severity: 'critical',
    description: 'Database dump exposed',
    fix: 'Remove database files from web root',
    validator: validators.sqlFile
  },
  {
    path: '/dump.sql',
    name: 'Database dump',
    severity: 'critical',
    description: 'Database dump exposed',
    fix: 'Remove database files from web root',
    validator: validators.sqlFile
  },
  {
    path: '/db.sql',
    name: 'Database file',
    severity: 'critical',
    description: 'Database file exposed',
    fix: 'Remove database files from web root',
    validator: validators.sqlFile
  },

  // High - Source maps (important for vibe coders using bundlers)
  {
    path: '/main.js.map',
    name: 'JavaScript source map',
    severity: 'high',
    description: 'Source maps expose your original source code to anyone',
    fix: 'Disable source maps in production: set devtool: false in webpack or sourcemap: false in Vite',
    validator: validators.sourceMap
  },
  {
    path: '/bundle.js.map',
    name: 'Bundle source map',
    severity: 'high',
    description: 'Source maps expose your original source code',
    fix: 'Disable source maps in production builds',
    validator: validators.sourceMap
  },
  {
    path: '/app.js.map',
    name: 'App source map',
    severity: 'high',
    description: 'Source maps expose your original source code',
    fix: 'Disable source maps in production builds',
    validator: validators.sourceMap
  },
  {
    path: '/_next/static/chunks/main.js.map',
    name: 'Next.js source map',
    severity: 'high',
    description: 'Next.js source maps expose your original source code',
    fix: 'Set productionBrowserSourceMaps: false in next.config.js',
    validator: validators.sourceMap
  },

  // High - Debug and info files
  {
    path: '/phpinfo.php',
    name: 'PHP info page',
    severity: 'high',
    description: 'PHP info page exposes server configuration and installed modules',
    fix: 'Remove phpinfo.php from production servers',
    validator: validators.phpInfo
  },
  {
    path: '/info.php',
    name: 'PHP info page',
    severity: 'high',
    description: 'PHP info page exposes server configuration',
    fix: 'Remove info.php from production servers',
    validator: validators.phpInfo
  },
  {
    path: '/debug.log',
    name: 'Debug log',
    severity: 'high',
    description: 'Debug logs may contain sensitive information and stack traces',
    fix: 'Remove or restrict access to log files',
    validator: validators.logFile
  },
  {
    path: '/error.log',
    name: 'Error log',
    severity: 'medium',
    description: 'Error logs may expose internal paths and errors',
    fix: 'Remove or restrict access to log files',
    validator: validators.logFile
  },
  {
    path: '/wp-content/debug.log',
    name: 'WordPress debug log',
    severity: 'high',
    description: 'WordPress debug log may contain sensitive errors',
    fix: 'Remove debug log or disable WP_DEBUG_LOG in production',
    validator: validators.logFile
  },

  // Medium - Config files
  {
    path: '/wp-config.php',
    name: 'WordPress config',
    severity: 'critical',
    description: 'WordPress configuration contains database credentials',
    fix: 'Ensure PHP files are processed by your server, not served as plaintext',
    validator: validators.phpConfig
  },
  {
    path: '/config.json',
    name: 'Config JSON',
    severity: 'high',
    description: 'Configuration file may contain sensitive settings',
    fix: 'Move config files outside the web root or block access',
    validator: validators.jsonConfig
  },

  // Low - Package files (info disclosure but not critical)
  {
    path: '/package.json',
    name: 'NPM package file',
    severity: 'low',
    description: 'Exposes dependencies which could reveal vulnerabilities to target',
    fix: 'Consider blocking access to package.json in production',
    validator: validators.packageJson
  },
  {
    path: '/.gitignore',
    name: 'Git ignore file',
    severity: 'low',
    description: 'Reveals project structure and what files the developer considers sensitive',
    fix: 'Block access to dotfiles in your web server config',
    validator: validators.gitignore
  }
];

export async function checkExposedFiles(baseUrl: string, timeout: number = 5000): Promise<CheckResult> {
  const issues: SecurityIssue[] = [];
  const details: Record<string, { status: number; accessible: boolean; validated: boolean }> = {};

  // Run checks in parallel with concurrency limit
  const concurrency = 5;
  const chunks: SensitiveFile[][] = [];
  for (let i = 0; i < SENSITIVE_FILES.length; i += concurrency) {
    chunks.push(SENSITIVE_FILES.slice(i, i + concurrency));
  }

  for (const chunk of chunks) {
    const results = await Promise.all(
      chunk.map(async (file) => {
        const url = new URL(file.path, baseUrl).toString();
        try {
          const controller = new AbortController();
          const timeoutId = setTimeout(() => controller.abort(), timeout);

          const response = await fetch(url, {
            method: 'GET',
            signal: controller.signal,
            redirect: 'follow',
            headers: {
              'User-Agent': 'SecurityScanner/2.0 (Security Audit; contact: security@example.com)'
            }
          });

          clearTimeout(timeoutId);

          // Skip if not 200
          if (response.status !== 200) {
            return {
              file,
              status: response.status,
              accessible: false,
              validated: false,
              contentType: ''
            };
          }

          const contentType = response.headers.get('content-type') || '';

          // Read content for validation (limit to 50KB to avoid large files)
          const contentLength = parseInt(response.headers.get('content-length') || '0', 10);
          if (contentLength > 50000) {
            // Large file - if it's not HTML, might be a real backup/dump
            const isHtml = contentType.includes('text/html');
            return {
              file,
              status: response.status,
              accessible: !isHtml,
              validated: !isHtml,
              contentType
            };
          }

          const content = await response.text();

          // Validate content if validator exists
          let validated = false;
          if (file.validator) {
            validated = file.validator(content, contentType);
          } else {
            // No validator - check it's not HTML (basic false positive prevention)
            validated = !contentType.includes('text/html') &&
                       !content.trim().startsWith('<!DOCTYPE') &&
                       !content.trim().startsWith('<html');
          }

          return {
            file,
            status: response.status,
            accessible: validated,
            validated,
            contentType
          };
        } catch {
          return {
            file,
            status: 0,
            accessible: false,
            validated: false,
            contentType: ''
          };
        }
      })
    );

    for (const result of results) {
      details[result.file.path] = {
        status: result.status,
        accessible: result.accessible,
        validated: result.validated
      };

      // Only report if content was validated as real (not a SPA catch-all)
      if (result.accessible && result.validated) {
        issues.push({
          id: `exposed-${result.file.path.replace(/[^a-z0-9]/gi, '-')}`,
          severity: result.file.severity,
          category: 'Exposed Files',
          title: `${result.file.name} accessible: ${result.file.path}`,
          description: result.file.description,
          fix: result.file.fix
        });
      }
    }
  }

  return {
    name: 'Exposed Files',
    passed: issues.length === 0,
    issues,
    details
  };
}
