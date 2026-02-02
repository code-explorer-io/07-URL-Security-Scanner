import { CheckResult, SecurityIssue } from '../types';

interface ServerInfoDetails {
  server: string | null;
  poweredBy: string | null;
  aspNetVersion: string | null;
  phpVersion: string | null;
  otherHeaders: Record<string, string>;
}

const INFO_HEADERS = [
  'server',
  'x-powered-by',
  'x-aspnet-version',
  'x-aspnetmvc-version',
  'x-runtime',
  'x-version',
  'x-generator',
  'x-drupal-cache',
  'x-drupal-dynamic-cache',
  'x-pingback',
  'x-redirect-by',
  'via',
  'x-varnish'
];

export async function checkServerInfo(headers: Headers): Promise<CheckResult> {
  const issues: SecurityIssue[] = [];

  const details: ServerInfoDetails = {
    server: headers.get('server'),
    poweredBy: headers.get('x-powered-by'),
    aspNetVersion: headers.get('x-aspnet-version'),
    phpVersion: null,
    otherHeaders: {}
  };

  // Check for version info in X-Powered-By
  const poweredBy = headers.get('x-powered-by');
  if (poweredBy) {
    // Extract PHP version if present
    const phpMatch = poweredBy.match(/PHP\/([\d.]+)/i);
    if (phpMatch) {
      details.phpVersion = phpMatch[1];
    }

    issues.push({
      id: 'server-x-powered-by',
      severity: 'medium',
      category: 'Information Disclosure',
      title: 'X-Powered-By header exposes technology stack',
      description: `Server reveals: ${poweredBy}. This helps attackers target known vulnerabilities.`,
      fix: 'Remove X-Powered-By header. In PHP: Header("X-Powered-By: "); In Express: app.disable("x-powered-by")',
      evidence: {
        query: 'HTTP response header: x-powered-by',
        response: `X-Powered-By: ${poweredBy}`,
        verifyCommand: 'curl -I <url> | grep -i "x-powered-by"'
      }
    });
  }

  // Check Server header for version info
  const server = headers.get('server');
  if (server) {
    // Check if it contains version numbers
    const hasVersion = /[\d]+\.[\d]+/.test(server);
    if (hasVersion) {
      issues.push({
        id: 'server-version-disclosure',
        severity: 'medium',
        category: 'Information Disclosure',
        title: 'Server header exposes version information',
        description: `Server header reveals: ${server}. Version info helps attackers find known vulnerabilities.`,
        fix: 'Configure your web server to hide version info. Apache: ServerTokens Prod. Nginx: server_tokens off;',
        evidence: {
          query: 'HTTP response header: server',
          response: `Server: ${server}`,
          verifyCommand: 'curl -I <url> | grep -i "^server:"'
        }
      });
    } else if (server.toLowerCase() !== 'cloudflare' &&
               server.toLowerCase() !== 'nginx' &&
               server.toLowerCase() !== 'apache' &&
               !server.toLowerCase().startsWith('vercel') &&
               !server.toLowerCase().startsWith('netlify')) {
      // Only flag if it's more than just the server name
      issues.push({
        id: 'server-info-disclosure',
        severity: 'low',
        category: 'Information Disclosure',
        title: 'Server header present',
        description: `Server: ${server}. Consider hiding server type.`,
        fix: 'Configure your web server to hide or minimize the Server header',
        evidence: {
          query: 'HTTP response header: server',
          response: `Server: ${server}`,
          verifyCommand: 'curl -I <url> | grep -i "^server:"'
        }
      });
    }
  }

  // Check for ASP.NET version headers
  const aspNetVersion = headers.get('x-aspnet-version');
  if (aspNetVersion) {
    issues.push({
      id: 'server-aspnet-version',
      severity: 'medium',
      category: 'Information Disclosure',
      title: 'X-AspNet-Version header exposes framework version',
      description: `ASP.NET version ${aspNetVersion} is exposed`,
      fix: 'In web.config, add: <httpRuntime enableVersionHeader="false" />',
      evidence: {
        query: 'HTTP response header: x-aspnet-version',
        response: `X-AspNet-Version: ${aspNetVersion}`,
        verifyCommand: 'curl -I <url> | grep -i "x-aspnet-version"'
      }
    });
  }

  const aspNetMvcVersion = headers.get('x-aspnetmvc-version');
  if (aspNetMvcVersion) {
    issues.push({
      id: 'server-aspnetmvc-version',
      severity: 'medium',
      category: 'Information Disclosure',
      title: 'X-AspNetMvc-Version header exposes MVC version',
      description: `ASP.NET MVC version ${aspNetMvcVersion} is exposed`,
      fix: 'In Application_Start, add: MvcHandler.DisableMvcResponseHeader = true;',
      evidence: {
        query: 'HTTP response header: x-aspnetmvc-version',
        response: `X-AspNetMvc-Version: ${aspNetMvcVersion}`,
        verifyCommand: 'curl -I <url> | grep -i "x-aspnetmvc-version"'
      }
    });
  }

  // Collect other potentially revealing headers
  for (const headerName of INFO_HEADERS) {
    const value = headers.get(headerName);
    if (value && !['server', 'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version'].includes(headerName)) {
      details.otherHeaders[headerName] = value;
    }
  }

  // Check for X-Generator (WordPress, etc.)
  const generator = headers.get('x-generator');
  if (generator) {
    issues.push({
      id: 'server-generator',
      severity: 'low',
      category: 'Information Disclosure',
      title: 'X-Generator header reveals CMS/platform',
      description: `Generator: ${generator}`,
      fix: 'Remove the X-Generator header from your responses',
      evidence: {
        query: 'HTTP response header: x-generator',
        response: `X-Generator: ${generator}`,
        verifyCommand: 'curl -I <url> | grep -i "x-generator"'
      }
    });
  }

  return {
    name: 'Server Information',
    passed: issues.length === 0,
    issues,
    details
  };
}
