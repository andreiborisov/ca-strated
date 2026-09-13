import { domainToASCII } from 'node:url';

import { CaStratedError } from './error.js';

export function normalizeDnsName(raw: string): string {
  const trimmed = raw.trim().replace(/\.+$/u, '').replace(/^\.+/u, '');
  if (trimmed.length === 0) {
    throw new CaStratedError('permittedDns entries must not be empty');
  }
  if (/^dns:/iu.test(trimmed)) {
    throw new CaStratedError(
      `permittedDns must be a bare domain, not an OpenSSL DNS: value (${raw})`,
    );
  }
  if (trimmed.includes('*')) {
    throw new CaStratedError(
      `nameConstraints must not contain wildcards (${raw}); use example.com for apex + subdomains`,
    );
  }
  if (/[,\s;]/u.test(trimmed)) {
    throw new CaStratedError(`invalid domain name: ${raw}`);
  }

  const ascii = domainToASCII(trimmed);
  if (ascii.length === 0) {
    throw new CaStratedError(`could not convert domain to ASCII: ${raw}`);
  }
  return ascii;
}

export function permittedDnsNames(rawNames: readonly string[]): string[] {
  const seen = new Set<string>();
  const names: string[] = [];
  for (const raw of rawNames) {
    const name = normalizeDnsName(raw);
    if (seen.has(name)) {
      continue;
    }
    seen.add(name);
    names.push(name);
  }
  if (names.length === 0) {
    throw new CaStratedError('permittedDns must contain at least one domain');
  }
  return names;
}

/** OpenSSL nameConstraints tokens that exclude every IPv4 and IPv6 address. */
export const EXCLUDED_ALL_IPS = [
  'excluded;IP:0.0.0.0/0.0.0.0',
  'excluded;IP:0:0:0:0:0:0:0:0/0:0:0:0:0:0:0:0',
] as const;

export function nameConstraintsValue(rawNames: readonly string[]): string {
  const permitted = permittedDnsNames(rawNames).map((name) => `permitted;DNS:${name}`);
  // RFC 5280 only constrains name forms that appear. DNS permitted trees leave
  // IP SANs open unless an IP tree is present; exclude IPv4 and IPv6 /0 so an
  // IP-literal leaf cannot bypass the allowlist. OpenSSL 3 wants address/mask,
  // not CIDR prefix length.
  return ['critical', ...permitted, ...EXCLUDED_ALL_IPS].join(',');
}

export const LOCAL_ROOT_PATHLEN = 2;
export const WRAP_PATHLEN = 1;

function caSection(section: string, pathlen: number, rawNames: readonly string[]): string[] {
  return [
    `[${section}]`,
    `basicConstraints = critical,CA:TRUE,pathlen:${pathlen}`,
    'keyUsage = critical,keyCertSign,cRLSign',
    'subjectKeyIdentifier = hash',
    'authorityKeyIdentifier = keyid:always',
    `nameConstraints = ${nameConstraintsValue(rawNames)}`,
    '',
  ];
}

export function caExtensionsConf(
  rawNames: readonly string[],
  options: { pathlen?: number; section?: string } = {},
): string {
  return caSection(options.section ?? 'v3_ca', options.pathlen ?? WRAP_PATHLEN, rawNames).join('\n');
}

export function issueExtensionsConf(rawNames: readonly string[]): string {
  return [
    ...caSection('v3_local_root', LOCAL_ROOT_PATHLEN, rawNames),
    ...caSection('v3_wrap', WRAP_PATHLEN, rawNames),
  ].join('\n');
}

export function isNameConstraintsCritical(extText: string): boolean {
  return /Name Constraints:\s*critical/u.test(extText);
}

/** True when OpenSSL `-ext nameConstraints` dump excludes IPv4 and IPv6 /0. */
export function excludesAllIpAddresses(extText: string): boolean {
  const ipv4 = /IP:\s*0\.0\.0\.0\/0\.0\.0\.0\b/u.test(extText);
  const ipv6Colon = /IP:\s*(?:0:){7}0\/(?:0:){7}0\b/u.test(extText);
  const ipv6Dotted = /IP:\s*(?:0\.){15}0\/(?:0\.){15}0\b/u.test(extText);
  return ipv4 && (ipv6Colon || ipv6Dotted);
}
