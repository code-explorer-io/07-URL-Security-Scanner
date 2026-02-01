import { execSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

/**
 * Check if GitHub CLI is available and authenticated
 */
export function isGhAvailable(): boolean {
  try {
    execSync('gh auth status', { stdio: 'pipe' });
    return true;
  } catch {
    return false;
  }
}

/**
 * Create a public gist with the report files
 */
export async function createGist(
  humanReport: string,
  agentReport: string,
  domain: string
): Promise<{ url: string; id: string } | null> {
  if (!isGhAvailable()) {
    console.error('GitHub CLI not available or not authenticated.');
    console.error('Install with: winget install GitHub.cli');
    console.error('Then run: gh auth login');
    return null;
  }

  // Create temp directory for files
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'security-scan-'));

  try {
    // Write report files
    const humanPath = path.join(tempDir, `security-report-${domain}.md`);
    const agentPath = path.join(tempDir, `security-fixes-${domain}.md`);

    fs.writeFileSync(humanPath, humanReport);
    fs.writeFileSync(agentPath, agentReport);

    // Create gist with both files
    const description = `Security Checkup for ${domain}`;
    const cmd = `gh gist create "${humanPath}" "${agentPath}" --public --desc "${description}"`;

    const output = execSync(cmd, { encoding: 'utf-8' }).trim();

    // Parse gist URL from output
    const gistUrl = output.split('\n').find(line => line.startsWith('https://gist.github.com'));

    if (gistUrl) {
      // Extract gist ID from URL
      const gistId = gistUrl.split('/').pop() || '';
      return { url: gistUrl, id: gistId };
    }

    return null;
  } catch (error) {
    console.error('Failed to create gist:', error instanceof Error ? error.message : 'Unknown error');
    return null;
  } finally {
    // Cleanup temp files
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // Ignore cleanup errors
    }
  }
}

/**
 * Delete a gist by ID
 */
export function deleteGist(gistId: string): boolean {
  try {
    execSync(`gh gist delete ${gistId} --yes`, { stdio: 'pipe' });
    return true;
  } catch {
    return false;
  }
}
