import { chmodSync, existsSync } from 'node:fs';
import { mkdir, writeFile } from 'node:fs/promises';

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

export async function assertIssuedCertificates(paths: Paths): Promise<void> {
  await assertCopiedDates(paths.vendorRootCert, paths.localRootCert, 'local-root.crt');
  await assertCopiedDates(paths.vendorRootCert, paths.constrainedCert, 'mincifry-constrained.crt');
  await assertConstrainedCa(paths.localRootCert, 'local-root.crt', LOCAL_ROOT_PATHLEN);
  await assertConstrainedCa(paths.constrainedCert, 'mincifry-constrained.crt', WRAP_PATHLEN);
}

export async function issueCertificates(config: Config, paths: Paths): Promise<void> {
  if (!existsSync(paths.vendorRootCert)) {
    throw new CaStratedError(`Missing ${paths.vendorRootCert}; run fetch first`);
  }

  await mkdir(paths.outDir, { recursive: true });
  await writeFile(paths.extensionsConf, issueExtensionsConf(config.permittedDns));

  if (existsSync(paths.localKey)) {
    console.log(`reusing ${paths.localKey}`);
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

  await assertIssuedCertificates(paths);

  const dates = await certDates(paths.constrainedCert);
  console.log(`validity copied from source root: ${dates.notBefore} .. ${dates.notAfter}`);
}
