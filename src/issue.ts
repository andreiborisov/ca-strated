import { chmodSync, existsSync, renameSync } from 'node:fs';
import { copyFile, mkdir, unlink, writeFile } from 'node:fs/promises';
import { basename, join } from 'node:path';

import type { Config, Paths } from './config.js';
import {
  excludesAllIpAddresses,
  isNameConstraintsCritical,
  issueExtensionsConf,
  LOCAL_ROOT_PATHLEN,
  WRAP_PATHLEN,
} from './constraints.js';
import { CaStratedError } from './error.js';
import { certDates, certField, randomSerialHex, runOpenSsl } from './openssl.js';
import { packInstallBundle } from './pack.js';

async function assertCopiedDates(sourcePath: string, issuedPath: string, label: string): Promise<void> {
  const source = await certDates(sourcePath);
  const issued = await certDates(issuedPath);
  if (source.notBefore !== issued.notBefore || source.notAfter !== issued.notAfter) {
    throw new CaStratedError(
      `${label} validity does not match the source root\n  source  ${source.notBefore} .. ${source.notAfter}\n  issued  ${issued.notBefore} .. ${issued.notAfter}`,
    );
  }
}

async function assertConstrainedCa(certPath: string, label: string, pathlen: number): Promise<void> {
  const constraints = await certField(certPath, ['-ext', 'nameConstraints']);
  if (!isNameConstraintsCritical(constraints)) {
    throw new CaStratedError(`${label} is missing a critical nameConstraints extension:\n${constraints}`);
  }
  if (!excludesAllIpAddresses(constraints)) {
    throw new CaStratedError(`${label} must exclude all IPv4 and IPv6 addresses:\n${constraints}`);
  }
  const basic = await certField(certPath, ['-ext', 'basicConstraints']);
  const pathlenRe = new RegExp(`pathlen:${pathlen}\\b`, 'u');
  if (!/CA:TRUE/u.test(basic) || !pathlenRe.test(basic)) {
    throw new CaStratedError(`${label} must be CA:TRUE pathlen:${pathlen}:\n${basic}`);
  }
}

async function removeIfExists(path: string): Promise<void> {
  if (existsSync(path)) {
    await unlink(path);
  }
}

export async function assertIssuedCertificates(paths: Paths): Promise<void> {
  const anchor = basename(paths.localRootCert);
  const wrap = basename(paths.constrainedCert);
  await assertCopiedDates(paths.vendorRootCert, paths.localRootCert, anchor);
  await assertCopiedDates(paths.vendorRootCert, paths.constrainedCert, wrap);
  await assertConstrainedCa(paths.localRootCert, anchor, LOCAL_ROOT_PATHLEN);
  await assertConstrainedCa(paths.constrainedCert, wrap, WRAP_PATHLEN);

  for (const dest of paths.untrustedIntermediateCerts) {
    if (!existsSync(dest)) {
      throw new CaStratedError(`Missing ${dest}; run issue to copy vendor intermediates into out/untrusted`);
    }
  }
}

function reuseOrCreateKey(paths: Paths): { action: 'reuse' | 'migrate' | 'create'; from?: string } {
  if (existsSync(paths.localKey)) {
    return { action: 'reuse' };
  }
  for (const legacy of paths.legacyLocalKeys) {
    if (existsSync(legacy)) {
      renameSync(legacy, paths.localKey);
      return { action: 'migrate', from: legacy };
    }
  }
  return { action: 'create' };
}

export async function issueCertificates(config: Config, paths: Paths): Promise<void> {
  if (!existsSync(paths.vendorRootCert)) {
    throw new CaStratedError(`Missing ${paths.vendorRootCert}; run fetch first`);
  }
  for (const vendorIntermediate of paths.vendorIntermediateCerts) {
    if (!existsSync(vendorIntermediate)) {
      throw new CaStratedError(`Missing ${vendorIntermediate}; run fetch first`);
    }
  }

  await mkdir(paths.trustedDir, { recursive: true });
  await mkdir(paths.untrustedDir, { recursive: true });
  await writeFile(paths.extensionsConf, issueExtensionsConf(config.permittedDns));

  const keyAction = reuseOrCreateKey(paths);
  if (keyAction.action === 'reuse') {
    console.log(`reusing ${paths.localKey}`);
  } else if (keyAction.action === 'migrate') {
    console.log(`moved ${keyAction.from} → ${paths.localKey}`);
  } else {
    await runOpenSsl(['genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:4096', '-out', paths.localKey]);
    console.log(`wrote ${paths.localKey}`);
  }
  chmodSync(paths.localKey, 0o600);

  await runOpenSsl([
    'x509',
    '-in',
    paths.vendorRootCert,
    '-signkey',
    paths.localKey,
    '-sha256',
    '-subj',
    config.localCa.subject,
    '-clrext',
    '-preserve_dates',
    '-set_serial',
    `0x${randomSerialHex()}`,
    '-extfile',
    paths.extensionsConf,
    '-extensions',
    'v3_local_root',
    '-out',
    paths.localRootCert,
  ]);
  console.log(`wrote ${paths.localRootCert}`);

  await runOpenSsl([
    'x509',
    '-in',
    paths.vendorRootCert,
    '-CA',
    paths.localRootCert,
    '-CAkey',
    paths.localKey,
    '-sha256',
    '-clrext',
    '-preserve_dates',
    '-set_serial',
    `0x${randomSerialHex()}`,
    '-extfile',
    paths.extensionsConf,
    '-extensions',
    'v3_wrap',
    '-out',
    paths.constrainedCert,
  ]);
  console.log(`wrote ${paths.constrainedCert}`);

  for (const [index, source] of paths.vendorIntermediateCerts.entries()) {
    const dest = paths.untrustedIntermediateCerts[index];
    if (!dest) {
      throw new CaStratedError(`Missing untrusted path for intermediate ${index}`);
    }
    await copyFile(source, dest);
    console.log(`copied ${dest}`);
  }

  await removeIfExists(join(paths.outDir, 'local-root.crt'));
  await removeIfExists(join(paths.outDir, 'local-root.srl'));
  await removeIfExists(join(paths.outDir, 'mincifry-constrained.crt'));
  await removeIfExists(join(paths.trustedDir, 'castrated_russian_trusted_root_pem.crt'));

  await assertIssuedCertificates(paths);

  const dates = await certDates(paths.constrainedCert);
  console.log(`validity copied from source root: ${dates.notBefore} .. ${dates.notAfter}`);

  await packInstallBundle(paths);
}
