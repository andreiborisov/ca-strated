import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

import type { CertSource, Config, Paths } from './config.js';
import { CaStratedError } from './error.js';
import { certDates, certField, runOpenSsl } from './openssl.js';

function fileSha256(path: string): string {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

function requireIncludes(haystack: string, needle: string, label: string): void {
  if (!haystack.includes(needle)) {
    throw new CaStratedError(`${label} does not contain ${JSON.stringify(needle)}:\n${haystack}`);
  }
}

async function inspectOne(label: string, certPath: string, source: CertSource): Promise<void> {
  const actualHash = fileSha256(certPath);
  if (actualHash !== source.sha256) {
    throw new CaStratedError(
      `SHA-256 mismatch for ${label} (${certPath})\n  expected ${source.sha256}\n  actual   ${actualHash}`,
    );
  }

  const subject = await certField(certPath, ['-subject']);
  const issuer = await certField(certPath, ['-issuer']);
  const fingerprint = await certField(certPath, ['-fingerprint', '-sha256']);
  const dates = await certDates(certPath);
  const basicConstraints = await certField(certPath, ['-ext', 'basicConstraints']);
  const keyUsage = await certField(certPath, ['-ext', 'keyUsage']);
  const text = (await runOpenSsl(['x509', '-in', certPath, '-noout', '-text'])).stdout;

  requireIncludes(subject, source.subjectContains, `${label} subject`);
  if (!/CA:TRUE/u.test(basicConstraints)) {
    throw new CaStratedError(`${label} is not a CA:\n${basicConstraints}`);
  }
  if (!/Certificate Sign/u.test(keyUsage)) {
    throw new CaStratedError(`${label} is missing keyCertSign:\n${keyUsage}`);
  }
  if (!/rsaEncryption/u.test(text)) {
    throw new CaStratedError(`${label} is not RSA (GOST and other algorithms are out of scope):\n${certPath}`);
  }

  const expired = await runOpenSsl(['x509', '-in', certPath, '-noout', '-checkend', '0'], { allowFailure: true });
  if (expired.code !== 0) {
    throw new CaStratedError(`${label} is expired (${dates.notAfter})`);
  }

  console.log(
    [
      `${label}: ${certPath}`,
      `  file sha256: ${actualHash}`,
      `  ${subject}`,
      `  ${issuer}`,
      `  notBefore=${dates.notBefore}`,
      `  notAfter=${dates.notAfter}`,
      `  ${fingerprint}`,
      `  ${basicConstraints.replaceAll('\n', '\n  ')}`,
      `  ${keyUsage.replaceAll('\n', '\n  ')}`,
    ].join('\n'),
  );
}

export async function inspectCertificates(config: Config, paths: Paths): Promise<void> {
  await inspectOne('root', paths.vendorRootCert, config.sources.root);

  const rootSubject = await certField(paths.vendorRootCert, ['-subject']);
  const rootIssuer = await certField(paths.vendorRootCert, ['-issuer']);
  if (rootSubject.replace(/^subject=/u, '') !== rootIssuer.replace(/^issuer=/u, '')) {
    throw new CaStratedError('Root certificate is not self-issued');
  }

  for (const [index, source] of config.sources.intermediates.entries()) {
    const certPath = paths.vendorIntermediateCerts[index];
    if (!certPath) {
      throw new CaStratedError(`Missing vendor path for intermediate ${index}`);
    }
    await inspectOne(`intermediate-${index}`, certPath, source);

    const verified = await runOpenSsl(['verify', '-CAfile', paths.vendorRootCert, certPath], {
      allowFailure: true,
    });
    if (verified.code !== 0 || !verified.stdout.includes('OK')) {
      throw new CaStratedError(
        `intermediate-${index} is not signed by the configured root:\n${verified.stdout}${verified.stderr}`,
      );
    }
    console.log(`  chain: intermediate-${index} verifies against root`);
  }
}
