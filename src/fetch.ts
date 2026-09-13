import { createHash } from 'node:crypto';
import { mkdir, writeFile } from 'node:fs/promises';

import type { CertSource, Config, Paths } from './config.js';
import { CaStratedError } from './error.js';

const USER_AGENT = 'Mozilla/5.0 (compatible; ca-strated/0.1)';

export function sha256Hex(data: Uint8Array): string {
  return createHash('sha256').update(data).digest('hex');
}

async function downloadPinned(source: CertSource, destPath: string): Promise<void> {
  let response: Response;
  try {
    response = await fetch(source.url, {
      headers: {
        accept: 'application/x-x509-ca-cert,application/pkix-cert,*/*',
        'user-agent': USER_AGENT,
      },
      redirect: 'follow',
      signal: AbortSignal.timeout(30_000),
    });
  } catch (error) {
    throw new CaStratedError(
      `Failed to download ${source.url}: ${error instanceof Error ? error.message : String(error)}`,
    );
  }

  if (!response.ok) {
    throw new CaStratedError(`Failed to download ${source.url}: HTTP ${response.status} ${response.statusText}`);
  }

  const buffer = Buffer.from(await response.arrayBuffer());
  const actual = sha256Hex(buffer);
  if (actual !== source.sha256) {
    throw new CaStratedError(
      `SHA-256 mismatch for ${source.url}\n  expected ${source.sha256}\n  actual   ${actual}`,
    );
  }

  const text = buffer.toString('utf8');
  if (!text.includes('-----BEGIN CERTIFICATE-----')) {
    throw new CaStratedError(`Downloaded ${source.url} is not a PEM certificate`);
  }

  await writeFile(destPath, buffer);
  console.log(`fetched ${destPath} (${actual})`);
}

export async function fetchCertificates(config: Config, paths: Paths): Promise<void> {
  await mkdir(paths.vendorDir, { recursive: true });
  await downloadPinned(config.sources.root, paths.vendorRootCert);

  for (const [index, source] of config.sources.intermediates.entries()) {
    const dest = paths.vendorIntermediateCerts[index];
    if (!dest) {
      throw new CaStratedError(`Missing vendor path for intermediate ${index}`);
    }
    await downloadPinned(source, dest);
  }
}
