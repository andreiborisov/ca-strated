import { execFile } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { existsSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { promisify } from 'node:util';

import { CaStratedError } from './error.js';

const execFileAsync = promisify(execFile);

export type OpenSslResult = {
  code: number;
  stdout: string;
  stderr: string;
};

let cachedBin: string | undefined;

function isOpenSsl3(versionLine: string): boolean {
  return /^OpenSSL 3\./u.test(versionLine.trim());
}

async function readVersion(bin: string): Promise<string | undefined> {
  try {
    const { stdout, stderr } = await execFileAsync(bin, ['version'], { encoding: 'utf8' });
    return `${stdout}${stderr}`.trim().split('\n')[0];
  } catch {
    return undefined;
  }
}

async function brewOpenSsl3Bin(): Promise<string | undefined> {
  try {
    const { stdout } = await execFileAsync('brew', ['--prefix', 'openssl@3'], { encoding: 'utf8' });
    const bin = join(stdout.trim(), 'bin', 'openssl');
    return existsSync(bin) ? bin : undefined;
  } catch {
    return undefined;
  }
}

export async function resolveOpenSsl(): Promise<string> {
  if (cachedBin) {
    return cachedBin;
  }

  const candidates: string[] = [];
  if (process.env.OPENSSL_BIN) {
    candidates.push(process.env.OPENSSL_BIN);
  }
  const brewBin = await brewOpenSsl3Bin();
  if (brewBin) {
    candidates.push(brewBin);
  }
  const homebrewOpt = join('/opt/homebrew/opt/openssl@3/bin/openssl');
  const usrLocalOpt = join('/usr/local/opt/openssl@3/bin/openssl');
  const linuxBrewOpt = join(homedir(), '.linuxbrew/opt/openssl@3/bin/openssl');
  candidates.push(homebrewOpt, usrLocalOpt, linuxBrewOpt, 'openssl');

  const seen = new Set<string>();
  const tried: string[] = [];
  for (const candidate of candidates) {
    if (seen.has(candidate)) {
      continue;
    }
    seen.add(candidate);
    if (candidate !== 'openssl' && !existsSync(candidate)) {
      continue;
    }
    const version = await readVersion(candidate);
    if (!version) {
      continue;
    }
    tried.push(`${candidate} (${version})`);
    if (isOpenSsl3(version)) {
      cachedBin = candidate;
      return candidate;
    }
  }

  throw new CaStratedError(
    [
      'OpenSSL 3 is required (macOS /usr/bin/openssl is LibreSSL and cannot issue these certs).',
      'Install via the Brewfile (`brew bundle`) or set OPENSSL_BIN to the openssl@3 binary.',
      tried.length > 0 ? `Tried: ${tried.join('; ')}` : 'No openssl binary found.',
    ].join('\n'),
  );
}

export async function runOpenSsl(
  args: readonly string[],
  options: { allowFailure?: boolean } = {},
): Promise<OpenSslResult> {
  const bin = await resolveOpenSsl();
  try {
    const { stdout, stderr } = await execFileAsync(bin, [...args], {
      encoding: 'utf8',
      maxBuffer: 20 * 1024 * 1024,
    });
    return { code: 0, stdout, stderr };
  } catch (error) {
    const err = error as { code?: number; stdout?: string; stderr?: string; message?: string };
    const result: OpenSslResult = {
      code: typeof err.code === 'number' ? err.code : 1,
      stdout: err.stdout ?? '',
      stderr: err.stderr ?? err.message ?? String(error),
    };
    if (options.allowFailure) {
      return result;
    }
    throw new CaStratedError(
      `openssl ${args.join(' ')} failed (exit ${result.code}):\n${result.stderr || result.stdout}`,
    );
  }
}

export async function opensslVersion(): Promise<string> {
  const { stdout } = await runOpenSsl(['version']);
  return stdout.trim();
}

export async function certField(certPath: string, extraArgs: readonly string[]): Promise<string> {
  const { stdout } = await runOpenSsl(['x509', '-in', certPath, '-noout', ...extraArgs]);
  return stdout.trim();
}

export async function certDates(certPath: string): Promise<{ notBefore: string; notAfter: string }> {
  const output = await certField(certPath, ['-startdate', '-enddate']);
  const notBefore = output.match(/^notBefore=(.+)$/m)?.[1];
  const notAfter = output.match(/^notAfter=(.+)$/m)?.[1];
  if (!notBefore || !notAfter) {
    throw new CaStratedError(`Could not parse dates from ${certPath}:\n${output}`);
  }
  return { notBefore, notAfter };
}

export function randomSerialHex(): string {
  const bytes = randomBytes(16);
  bytes[0] = (bytes[0] ?? 0) & 0x7f || 0x01;
  return bytes.toString('hex');
}
