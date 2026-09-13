import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import {
  caExtensionsConf,
  excludesAllIpAddresses,
  EXCLUDED_ALL_IPS,
  isNameConstraintsCritical,
  issueExtensionsConf,
  nameConstraintsValue,
  normalizeDnsName,
  permittedDnsNames,
} from './constraints.js';

describe('normalizeDnsName', () => {
  it('keeps ASCII apex names', () => {
    assert.equal(normalizeDnsName('gosuslugi.ru'), 'gosuslugi.ru');
  });

  it('strips leading dots so constraints cover apex and subdomains', () => {
    assert.equal(normalizeDnsName('.gosuslugi.ru'), 'gosuslugi.ru');
  });

  it('converts IDN to ASCII', () => {
    assert.equal(normalizeDnsName('госуслуги.рф'), 'xn--c1aapkosapc.xn--p1ai');
  });

  it('rejects wildcards', () => {
    assert.throws(() => normalizeDnsName('*.gosuslugi.ru'), /wildcards/);
  });

  it('rejects OpenSSL DNS: prefixes', () => {
    assert.throws(() => normalizeDnsName('DNS:gosuslugi.ru'), /bare domain/);
  });
});

describe('nameConstraintsValue', () => {
  it('marks the extension critical, permits DNS, and excludes all IPs', () => {
    assert.equal(
      nameConstraintsValue(['gosuslugi.ru', 'госуслуги.рф', 'gosuslugi.ru']),
      [
        'critical',
        'permitted;DNS:gosuslugi.ru',
        'permitted;DNS:xn--c1aapkosapc.xn--p1ai',
        ...EXCLUDED_ALL_IPS,
      ].join(','),
    );
  });

  it('emits IPv4 and IPv6 /0 exclusions as address/mask', () => {
    const value = nameConstraintsValue(['rzd.ru']);
    assert.match(value, /excluded;IP:0\.0\.0\.0\/0\.0\.0\.0/);
    assert.match(value, /excluded;IP:0:0:0:0:0:0:0:0\/0:0:0:0:0:0:0:0/);
  });

  it('deduplicates after IDN conversion', () => {
    assert.deepEqual(permittedDnsNames(['госуслуги.рф', 'xn--c1aapkosapc.xn--p1ai']), [
      'xn--c1aapkosapc.xn--p1ai',
    ]);
  });
});

describe('caExtensionsConf', () => {
  it('defaults the wrap to pathlen 1', () => {
    const conf = caExtensionsConf(['nalog.gov.ru']);
    assert.match(conf, /^\[v3_ca\]$/m);
    assert.match(conf, /basicConstraints = critical,CA:TRUE,pathlen:1/);
    assert.match(
      conf,
      /nameConstraints = critical,permitted;DNS:nalog\.gov\.ru,excluded;IP:0\.0\.0\.0\/0\.0\.0\.0,excluded;IP:0:0:0:0:0:0:0:0\/0:0:0:0:0:0:0:0$/m,
    );
  });
});

describe('issueExtensionsConf', () => {
  it('uses pathlen 2 on the local root and pathlen 1 on the wrap', () => {
    const conf = issueExtensionsConf(['rzd.ru']);
    assert.match(conf, /\[v3_local_root\][\s\S]*basicConstraints = critical,CA:TRUE,pathlen:2/);
    assert.match(conf, /\[v3_wrap\][\s\S]*basicConstraints = critical,CA:TRUE,pathlen:1/);
  });
});

describe('isNameConstraintsCritical', () => {
  it('detects OpenSSL -ext output', () => {
    assert.equal(
      isNameConstraintsCritical('X509v3 Name Constraints: critical\n    Permitted:\n      DNS:gosuslugi.ru\n'),
      true,
    );
    assert.equal(isNameConstraintsCritical('X509v3 Name Constraints:\n    Permitted:\n      DNS:gosuslugi.ru\n'), false);
  });
});

describe('excludesAllIpAddresses', () => {
  it('accepts OpenSSL dotted IPv4 and IPv6 /0 dumps', () => {
    assert.equal(
      excludesAllIpAddresses(
        [
          'X509v3 Name Constraints: critical',
          '    Excluded:',
          '      IP:0.0.0.0/0.0.0.0',
          '      IP:0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0/0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0',
        ].join('\n'),
      ),
      true,
    );
  });

  it('accepts OpenSSL colon-hex IPv6 /0 dumps', () => {
    assert.equal(
      excludesAllIpAddresses(
        [
          'X509v3 Name Constraints: critical',
          '    Excluded:',
          '      IP:0.0.0.0/0.0.0.0',
          '      IP:0:0:0:0:0:0:0:0/0:0:0:0:0:0:0:0',
        ].join('\n'),
      ),
      true,
    );
  });

  it('rejects DNS-only constraints', () => {
    assert.equal(
      excludesAllIpAddresses('X509v3 Name Constraints: critical\n    Permitted:\n      DNS:gosuslugi.ru\n'),
      false,
    );
  });
});
