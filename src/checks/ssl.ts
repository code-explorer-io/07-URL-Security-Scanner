import * as https from 'https';
import * as tls from 'tls';
import { CheckResult, SecurityIssue } from '../types';

interface SSLDetails {
  valid: boolean;
  issuer?: string;
  subject?: string;
  validFrom?: string;
  validTo?: string;
  daysUntilExpiry?: number;
  protocol?: string;
  cipher?: string;
  error?: string;
}

export async function checkSSL(url: string): Promise<CheckResult> {
  const issues: SecurityIssue[] = [];
  const details: SSLDetails = { valid: false };

  const parsedUrl = new URL(url);

  // Check if site uses HTTPS
  if (parsedUrl.protocol !== 'https:') {
    issues.push({
      id: 'no-https',
      severity: 'critical',
      category: 'SSL/TLS',
      title: 'Site not using HTTPS',
      description: 'The site is served over unencrypted HTTP, exposing all traffic to interception',
      fix: 'Enable HTTPS with a valid SSL certificate (use Let\'s Encrypt for free certificates)'
    });

    return {
      name: 'SSL/TLS',
      passed: false,
      issues,
      details
    };
  }

  try {
    const sslDetails = await getSSLDetails(parsedUrl.hostname, parsedUrl.port ? parseInt(parsedUrl.port) : 443);
    Object.assign(details, sslDetails);

    // Check certificate expiry
    if (sslDetails.daysUntilExpiry !== undefined) {
      if (sslDetails.daysUntilExpiry < 0) {
        issues.push({
          id: 'ssl-expired',
          severity: 'critical',
          category: 'SSL/TLS',
          title: 'SSL certificate has expired',
          description: `Certificate expired ${Math.abs(sslDetails.daysUntilExpiry)} days ago`,
          fix: 'Renew your SSL certificate immediately'
        });
      } else if (sslDetails.daysUntilExpiry < 7) {
        issues.push({
          id: 'ssl-expiring-soon',
          severity: 'high',
          category: 'SSL/TLS',
          title: 'SSL certificate expiring very soon',
          description: `Certificate expires in ${sslDetails.daysUntilExpiry} days`,
          fix: 'Renew your SSL certificate before it expires'
        });
      } else if (sslDetails.daysUntilExpiry < 30) {
        const expiryDate = sslDetails.validTo ? new Date(sslDetails.validTo).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' }) : 'soon';
        issues.push({
          id: 'ssl-expiring',
          severity: 'medium',
          category: 'SSL/TLS',
          title: 'SSL certificate expiring soon',
          description: `Certificate expires on ${expiryDate} (${sslDetails.daysUntilExpiry} days). Most hosting auto-renews, but worth checking.`,
          fix: 'Check your hosting provider for auto-renewal settings, or manually renew before expiry'
        });
      }
    }

    // Check TLS version
    if (sslDetails.protocol) {
      const weakProtocols = ['TLSv1', 'TLSv1.1', 'SSLv3', 'SSLv2'];
      if (weakProtocols.includes(sslDetails.protocol)) {
        issues.push({
          id: 'weak-tls',
          severity: 'high',
          category: 'SSL/TLS',
          title: `Outdated TLS version: ${sslDetails.protocol}`,
          description: 'Using an outdated TLS version that has known vulnerabilities',
          fix: 'Configure your server to use TLS 1.2 or TLS 1.3 only'
        });
      }
    }

  } catch (error) {
    details.error = error instanceof Error ? error.message : 'Unknown SSL error';
    issues.push({
      id: 'ssl-error',
      severity: 'high',
      category: 'SSL/TLS',
      title: 'SSL certificate validation failed',
      description: details.error,
      fix: 'Ensure you have a valid SSL certificate from a trusted CA'
    });
  }

  return {
    name: 'SSL/TLS',
    passed: issues.length === 0,
    issues,
    details
  };
}

function getSSLDetails(hostname: string, port: number): Promise<SSLDetails> {
  return new Promise((resolve, reject) => {
    const options: tls.ConnectionOptions = {
      host: hostname,
      port: port,
      servername: hostname,
      rejectUnauthorized: true
    };

    const socket = tls.connect(options, () => {
      const cert = socket.getPeerCertificate();
      const protocol = socket.getProtocol();
      const cipher = socket.getCipher();

      if (!cert || Object.keys(cert).length === 0) {
        socket.destroy();
        reject(new Error('No certificate found'));
        return;
      }

      const validTo = new Date(cert.valid_to);
      const now = new Date();
      const daysUntilExpiry = Math.floor((validTo.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));

      const details: SSLDetails = {
        valid: true,
        issuer: cert.issuer?.O || cert.issuer?.CN || 'Unknown',
        subject: cert.subject?.CN || 'Unknown',
        validFrom: cert.valid_from,
        validTo: cert.valid_to,
        daysUntilExpiry,
        protocol: protocol || undefined,
        cipher: cipher?.name
      };

      socket.destroy();
      resolve(details);
    });

    socket.on('error', (err) => {
      socket.destroy();
      reject(err);
    });

    socket.setTimeout(10000, () => {
      socket.destroy();
      reject(new Error('SSL connection timeout'));
    });
  });
}
