import { CheckResult, SecurityIssue } from '../types';

interface AdminPath {
  path: string;
  name: string;
  description: string;
  // Markers that should be present in a real instance of this page
  contentMarkers?: RegExp[];
}

// Reduced list focused on high-confidence detections
const ADMIN_PATHS: AdminPath[] = [
  // Database tools - these are always critical if real
  {
    path: '/phpmyadmin',
    name: 'phpMyAdmin',
    description: 'Database management - should not be public',
    contentMarkers: [/phpMyAdmin/i, /pma_/i, /mysql/i]
  },
  {
    path: '/phpmyadmin/',
    name: 'phpMyAdmin',
    description: 'Database management tool',
    contentMarkers: [/phpMyAdmin/i, /pma_/i]
  },
  {
    path: '/adminer.php',
    name: 'Adminer',
    description: 'Database management tool',
    contentMarkers: [/adminer/i, /login.*database/i]
  },

  // WordPress specific
  {
    path: '/wp-admin/install.php',
    name: 'WordPress Install',
    description: 'WordPress installation script - should not be accessible',
    contentMarkers: [/wordpress/i, /installation/i, /wp-install/i]
  },
  {
    path: '/wp-login.php',
    name: 'WordPress Login',
    description: 'WordPress login page',
    contentMarkers: [/wp-login/i, /wordpress/i, /login.*form/i]
  },

  // Debug endpoints
  {
    path: '/_profiler',
    name: 'Symfony Profiler',
    description: 'Symfony debug profiler - exposes app internals',
    contentMarkers: [/symfony/i, /profiler/i, /debug/i]
  },
  {
    path: '/elmah.axd',
    name: 'ELMAH',
    description: 'ASP.NET error log',
    contentMarkers: [/elmah/i, /error.*log/i, /asp\.net/i]
  },
  {
    path: '/server-status',
    name: 'Apache Server Status',
    description: 'Apache status page exposes server information',
    contentMarkers: [/apache/i, /server.*status/i, /requests.*being.*processed/i]
  },
  {
    path: '/server-info',
    name: 'Apache Server Info',
    description: 'Apache info page exposes configuration',
    contentMarkers: [/apache/i, /server.*info/i, /module/i]
  },

  // Exposed configs/debug
  {
    path: '/phpinfo.php',
    name: 'PHP Info',
    description: 'PHP configuration exposed',
    contentMarkers: [/php version/i, /configuration/i, /php\.ini/i]
  },
  {
    path: '/info.php',
    name: 'PHP Info',
    description: 'PHP configuration exposed',
    contentMarkers: [/php version/i, /configuration/i]
  }
];

/**
 * Simple hash function for content comparison
 */
function simpleHash(str: string): string {
  let hash = 0;
  // Use first 5000 chars for hashing
  const sample = str.substring(0, 5000);
  for (let i = 0; i < sample.length; i++) {
    const char = sample.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash; // Convert to 32bit integer
  }
  return hash.toString(16);
}

/**
 * Check if content looks like the main page (SPA catch-all)
 */
function isSpaFallback(mainPageHash: string, mainPageLength: number, content: string): boolean {
  const contentHash = simpleHash(content);
  const contentLength = content.length;

  // If hash matches, it's the same page
  if (contentHash === mainPageHash) return true;

  // If length is very similar (within 5%), likely same page with minor differences
  const lengthDiff = Math.abs(contentLength - mainPageLength) / mainPageLength;
  if (lengthDiff < 0.05) {
    // Also check for common SPA markers
    if (content.includes('__NEXT_DATA__') ||
        content.includes('__NUXT__') ||
        content.includes('data-reactroot') ||
        content.includes('ng-app')) {
      return true;
    }
  }

  return false;
}

export async function checkAdminPaths(
  baseUrl: string,
  timeout: number = 5000,
  mainPageContent?: string
): Promise<CheckResult> {
  const issues: SecurityIssue[] = [];
  const details: Record<string, { status: number; accessible: boolean; validated: boolean }> = {};

  // Get main page for comparison if not provided
  let mainContent = mainPageContent || '';
  let mainHash = '';
  let mainLength = 0;

  if (!mainContent) {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), timeout);

      const response = await fetch(baseUrl, {
        method: 'GET',
        signal: controller.signal,
        headers: {
          'User-Agent': 'SecurityScanner/2.0 (Security Audit)'
        }
      });

      clearTimeout(timeoutId);

      if (response.ok) {
        mainContent = await response.text();
        mainHash = simpleHash(mainContent);
        mainLength = mainContent.length;
      }
    } catch {
      // Continue without main page comparison
    }
  } else {
    mainHash = simpleHash(mainContent);
    mainLength = mainContent.length;
  }

  // Check admin paths with validation
  const concurrency = 3;
  const chunks: AdminPath[][] = [];
  for (let i = 0; i < ADMIN_PATHS.length; i += concurrency) {
    chunks.push(ADMIN_PATHS.slice(i, i + concurrency));
  }

  for (const chunk of chunks) {
    const results = await Promise.all(
      chunk.map(async (adminPath) => {
        const url = new URL(adminPath.path, baseUrl).toString();
        try {
          const controller = new AbortController();
          const timeoutId = setTimeout(() => controller.abort(), timeout);

          const response = await fetch(url, {
            method: 'GET',
            signal: controller.signal,
            redirect: 'follow',
            headers: {
              'User-Agent': 'SecurityScanner/2.0 (Security Audit)'
            }
          });

          clearTimeout(timeoutId);

          if (response.status !== 200) {
            return {
              adminPath,
              status: response.status,
              accessible: false,
              validated: false
            };
          }

          const content = await response.text();

          // Check if it's just the SPA fallback page
          if (mainHash && isSpaFallback(mainHash, mainLength, content)) {
            return {
              adminPath,
              status: response.status,
              accessible: false,
              validated: false
            };
          }

          // Check for content markers if defined
          let validated = false;
          if (adminPath.contentMarkers) {
            validated = adminPath.contentMarkers.some(marker => marker.test(content));
          } else {
            // No markers - just ensure it's not HTML that looks like main page
            validated = true;
          }

          return {
            adminPath,
            status: response.status,
            accessible: validated,
            validated
          };
        } catch {
          return {
            adminPath,
            status: 0,
            accessible: false,
            validated: false
          };
        }
      })
    );

    for (const result of results) {
      details[result.adminPath.path] = {
        status: result.status,
        accessible: result.accessible,
        validated: result.validated
      };

      // Only report validated findings
      if (result.accessible && result.validated) {
        let severity: 'critical' | 'high' | 'medium' | 'low' = 'medium';
        let fix = 'Restrict access to admin paths by IP or remove from public access';

        // Database tools are always critical
        if (/phpmyadmin|adminer|mysql/i.test(result.adminPath.path)) {
          severity = 'critical';
          fix = 'Remove or restrict access to database tools. Never expose them to the public internet.';
        }
        // Debug/profiler tools
        else if (/profiler|debug|elmah|server-status|server-info|phpinfo/i.test(result.adminPath.path)) {
          severity = 'high';
          fix = 'Remove debug endpoints from production. They expose sensitive server information.';
        }
        // Install scripts
        else if (/install/i.test(result.adminPath.path)) {
          severity = 'high';
          fix = 'Remove installation scripts after setup is complete.';
        }

        issues.push({
          id: `admin-${result.adminPath.path.replace(/[^a-z0-9]/gi, '-')}`,
          severity,
          category: 'Admin Paths',
          title: `${result.adminPath.name} found: ${result.adminPath.path}`,
          description: result.adminPath.description,
          fix
        });
      }
    }
  }

  return {
    name: 'Admin Paths',
    passed: issues.length === 0,
    issues,
    details
  };
}
