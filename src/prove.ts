import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, join } from 'node:path';

import type { Config, Paths } from './config.js';
import { caExtensionsConf, issueExtensionsConf, permittedDnsNames } from './constraints.js';
import { CaStratedError } from './error.js';
import { assertIssuedCertificates } from './issue.js';
import { certField, runOpenSsl } from './openssl.js';

const DENIED_DNS = 'not-permitted.invalid';

async function dumpNameConstraints(label: string, certPath: string): Promise<void> {
  const ext = await certField(certPath, ['-ext', 'nameConstraints']);
  console.log(`${label} nameConstraints:\n${ext}`);
}

async function proveSynthetic(config: Config): Promise<void> {
  const allowed = permittedDnsNames(config.permittedDns)[0];
  if (!allowed) {
    throw new CaStratedError('permittedDns is empty');
  }
  if (allowed === DENIED_DNS || allowed.endsWith(`.${DENIED_DNS}`)) {
    throw new CaStratedError(`permittedDns must not include the prove negative name ${DENIED_DNS}`);
  }

  const dir = await mkdtemp(join(tmpdir(), 'ca-strated-prove-'));
  try {
    const caKey = join(dir, 'ca.key');
    const caCert = join(dir, 'ca.crt');
    const leafKey = join(dir, 'leaf.key');
    const leafCsr = join(dir, 'leaf.csr');
    const allowedCert = join(dir, 'allowed.crt');
    const deniedCert = join(dir, 'denied.crt');
    const ipCert = join(dir, 'ip.crt');
    const ipv6Cert = join(dir, 'ipv6.crt');
    const extFile = join(dir, 'ca.cnf');
    const allowedExt = join(dir, 'allowed.cnf');
    const deniedExt = join(dir, 'denied.cnf');
    const ipExt = join(dir, 'ip.cnf');
    const ipv6Ext = join(dir, 'ipv6.cnf');

    await writeFile(extFile, caExtensionsConf(config.permittedDns));
    await writeFile(
      allowedExt,
      [
        '[v3_ee]',
        'basicConstraints = CA:FALSE',
        'keyUsage = critical,digitalSignature,keyEncipherment',
        'extendedKeyUsage = serverAuth',
        `subjectAltName = DNS:${allowed}`,
        '',
      ].join('\n'),
    );
    await writeFile(
      deniedExt,
      [
        '[v3_ee]',
        'basicConstraints = CA:FALSE',
        'keyUsage = critical,digitalSignature,keyEncipherment',
        'extendedKeyUsage = serverAuth',
        `subjectAltName = DNS:${DENIED_DNS}`,
        '',
      ].join('\n'),
    );
    await writeFile(
      ipExt,
      [
        '[v3_ee]',
        'basicConstraints = CA:FALSE',
        'keyUsage = critical,digitalSignature,keyEncipherment',
        'extendedKeyUsage = serverAuth',
        'subjectAltName = IP:192.0.2.1',
        '',
      ].join('\n'),
    );
    await writeFile(
      ipv6Ext,
      [
        '[v3_ee]',
        'basicConstraints = CA:FALSE',
        'keyUsage = critical,digitalSignature,keyEncipherment',
        'extendedKeyUsage = serverAuth',
        'subjectAltName = IP:2001:db8::1',
        '',
      ].join('\n'),
    );

    await runOpenSsl(['genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048', '-out', caKey]);
    await runOpenSsl([
      'x509',
      '-new',
      '-key',
      caKey,
      '-subj',
      '/CN=ca-strated prove CA',
      '-days',
      '2',
      '-extfile',
      extFile,
      '-extensions',
      'v3_ca',
      '-out',
      caCert,
    ]);
    await runOpenSsl(['genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048', '-out', leafKey]);
    await runOpenSsl(['req', '-new', '-key', leafKey, '-subj', '/CN=leaf', '-out', leafCsr]);
    await runOpenSsl([
      'x509',
      '-req',
      '-in',
      leafCsr,
      '-CA',
      caCert,
      '-CAkey',
      caKey,
      '-CAcreateserial',
      '-days',
      '1',
      '-extfile',
      allowedExt,
      '-extensions',
      'v3_ee',
      '-out',
      allowedCert,
    ]);
    await runOpenSsl([
      'x509',
      '-req',
      '-in',
      leafCsr,
      '-CA',
      caCert,
      '-CAkey',
      caKey,
      '-days',
      '1',
      '-extfile',
      deniedExt,
      '-extensions',
      'v3_ee',
      '-out',
      deniedCert,
    ]);
    await runOpenSsl([
      'x509',
      '-req',
      '-in',
      leafCsr,
      '-CA',
      caCert,
      '-CAkey',
      caKey,
      '-days',
      '1',
      '-extfile',
      ipExt,
      '-extensions',
      'v3_ee',
      '-out',
      ipCert,
    ]);
    await runOpenSsl([
      'x509',
      '-req',
      '-in',
      leafCsr,
      '-CA',
      caCert,
      '-CAkey',
      caKey,
      '-days',
      '1',
      '-extfile',
      ipv6Ext,
      '-extensions',
      'v3_ee',
      '-out',
      ipv6Cert,
    ]);

    const allowedVerify = await runOpenSsl(['verify', '-CAfile', caCert, allowedCert], { allowFailure: true });
    if (allowedVerify.code !== 0 || !allowedVerify.stdout.includes('OK')) {
      throw new CaStratedError(
        `synthetic allowed leaf (${allowed}) failed to verify:\n${allowedVerify.stdout}${allowedVerify.stderr}`,
      );
    }
    console.log(`prove: allowed leaf ${allowed} verifies`);

    const deniedVerify = await runOpenSsl(['verify', '-CAfile', caCert, deniedCert], { allowFailure: true });
    const deniedText = `${deniedVerify.stdout}${deniedVerify.stderr}`;
    if (deniedVerify.code === 0 || !/permitted subtree violation/iu.test(deniedText)) {
      throw new CaStratedError(
        `synthetic denied leaf (${DENIED_DNS}) must fail with a permitted subtree violation:\n${deniedText}`,
      );
    }
    console.log(`prove: denied leaf ${DENIED_DNS} fails with permitted subtree violation`);

    for (const [label, cert] of [
      ['IPv4 192.0.2.1', ipCert],
      ['IPv6 2001:db8::1', ipv6Cert],
    ] as const) {
      const ipVerify = await runOpenSsl(['verify', '-CAfile', caCert, cert], { allowFailure: true });
      const ipText = `${ipVerify.stdout}${ipVerify.stderr}`;
      if (ipVerify.code === 0 || !/excluded subtree violation/iu.test(ipText)) {
        throw new CaStratedError(`synthetic IP leaf (${label}) must fail with an excluded subtree violation:\n${ipText}`);
      }
      console.log(`prove: denied IP leaf ${label} fails with excluded subtree violation`);
    }
  } finally {
    await rm(dir, { force: true, recursive: true });
  }
}

async function proveTwoIntermediatePath(config: Config): Promise<void> {
  const allowed = permittedDnsNames(config.permittedDns)[0];
  if (!allowed) {
    throw new CaStratedError('permittedDns is empty');
  }

  const dir = await mkdtemp(join(tmpdir(), 'ca-strated-pathlen-'));
  try {
    const localKey = join(dir, 'local.key');
    const wrapKey = join(dir, 'wrap.key');
    const subKey = join(dir, 'sub.key');
    const leafKey = join(dir, 'leaf.key');
    const localCert = join(dir, 'local.crt');
    const wrapCert = join(dir, 'wrap.crt');
    const subCert = join(dir, 'sub.crt');
    const leafCsr = join(dir, 'leaf.csr');
    const leafCert = join(dir, 'leaf.crt');
    const extFile = join(dir, 'ca.cnf');
    const subExt = join(dir, 'sub.cnf');
    const leafExt = join(dir, 'leaf.cnf');

    await writeFile(extFile, issueExtensionsConf(config.permittedDns));
    await writeFile(
      subExt,
      [
        '[v3_sub]',
        'basicConstraints = critical,CA:TRUE,pathlen:0',
        'keyUsage = critical,keyCertSign,cRLSign',
        'subjectKeyIdentifier = hash',
        'authorityKeyIdentifier = keyid:always,issuer:always',
        '',
      ].join('\n'),
    );
    await writeFile(
      leafExt,
      [
        '[v3_ee]',
        'basicConstraints = CA:FALSE',
        'keyUsage = critical,digitalSignature,keyEncipherment',
        'extendedKeyUsage = serverAuth',
        `subjectAltName = DNS:${allowed}, DNS:*.${allowed}`,
        '',
      ].join('\n'),
    );

    await runOpenSsl(['genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048', '-out', localKey]);
    await runOpenSsl(['genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048', '-out', wrapKey]);
    await runOpenSsl(['genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048', '-out', subKey]);
    await runOpenSsl(['genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048', '-out', leafKey]);

    await runOpenSsl([
      'x509',
      '-new',
      '-key',
      localKey,
      '-subj',
      '/CN=prove-local',
      '-days',
      '2',
      '-extfile',
      extFile,
      '-extensions',
      'v3_local_root',
      '-out',
      localCert,
    ]);
    await runOpenSsl(['req', '-new', '-key', wrapKey, '-subj', '/CN=prove-wrap', '-out', join(dir, 'wrap.csr')]);
    await runOpenSsl([
      'x509',
      '-req',
      '-in',
      join(dir, 'wrap.csr'),
      '-CA',
      localCert,
      '-CAkey',
      localKey,
      '-CAcreateserial',
      '-days',
      '1',
      '-extfile',
      extFile,
      '-extensions',
      'v3_wrap',
      '-out',
      wrapCert,
    ]);
    await runOpenSsl(['req', '-new', '-key', subKey, '-subj', '/CN=prove-sub', '-out', join(dir, 'sub.csr')]);
    await runOpenSsl([
      'x509',
      '-req',
      '-in',
      join(dir, 'sub.csr'),
      '-CA',
      wrapCert,
      '-CAkey',
      wrapKey,
      '-days',
      '1',
      '-extfile',
      subExt,
      '-extensions',
      'v3_sub',
      '-out',
      subCert,
    ]);
    await runOpenSsl(['req', '-new', '-key', leafKey, '-subj', `/CN=${allowed}`, '-out', leafCsr]);
    await runOpenSsl([
      'x509',
      '-req',
      '-in',
      leafCsr,
      '-CA',
      subCert,
      '-CAkey',
      subKey,
      '-days',
      '1',
      '-extfile',
      leafExt,
      '-extensions',
      'v3_ee',
      '-out',
      leafCert,
    ]);

    const untrusted = join(dir, 'untrusted.pem');
    await writeFile(untrusted, `${await readFile(wrapCert, 'utf8')}${await readFile(subCert, 'utf8')}`);

    const verified = await runOpenSsl(
      ['verify', '-CAfile', localCert, '-untrusted', untrusted, '-verify_hostname', allowed, leafCert],
      { allowFailure: true },
    );
    if (verified.code !== 0 || !verified.stdout.includes('OK')) {
      throw new CaStratedError(
        `synthetic leaf → sub → wrap → local-root chain failed (pathlen):\n${verified.stdout}${verified.stderr}`,
      );
    }
    console.log(`prove: two-intermediate chain (leaf → sub → wrap → root) verifies for ${allowed}`);
  } finally {
    await rm(dir, { force: true, recursive: true });
  }
}

export async function prove(config: Config, paths: Paths): Promise<void> {
  await assertIssuedCertificates(paths);
  console.log('prove: issued cert dates match the source root; nameConstraints are critical');

  await dumpNameConstraints(basename(paths.localRootCert), paths.localRootCert);
  await dumpNameConstraints(basename(paths.constrainedCert), paths.constrainedCert);

  for (const intermediate of paths.untrustedIntermediateCerts) {
    const verified = await runOpenSsl(
      ['verify', '-CAfile', paths.localRootCert, '-untrusted', paths.constrainedCert, intermediate],
      { allowFailure: true },
    );
    if (verified.code !== 0 || !verified.stdout.includes('OK')) {
      throw new CaStratedError(
        `${basename(intermediate)} does not verify through the constrained wrap:\n${verified.stdout}${verified.stderr}`,
      );
    }
    console.log(`prove: ${basename(intermediate)} verifies through ${basename(paths.constrainedCert)}`);
  }

  await proveSynthetic(config);
  await proveTwoIntermediatePath(config);
}
