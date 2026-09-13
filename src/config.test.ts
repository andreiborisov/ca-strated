import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { ANCHOR_CERT_FILENAME, WRAP_CERT_FILENAME, upstreamCertFilename } from './config.js';

describe('upstreamCertFilename', () => {
  it('takes the .crt basename from a source URL', () => {
    assert.equal(
      upstreamCertFilename('https://gu-st.ru/content/lending/russian_trusted_sub_ca_2024_pem.crt'),
      'russian_trusted_sub_ca_2024_pem.crt',
    );
  });

  it('rejects URLs without a .crt filename', () => {
    assert.throws(() => upstreamCertFilename('https://gu-st.ru/content/lending/'), /end with a \.crt filename/);
  });
});

describe('install filenames', () => {
  it('keeps the wrap name distinct from the official root PEM', () => {
    assert.equal(WRAP_CERT_FILENAME, 'russian_trusted_root_castrated_pem.crt');
    assert.equal(ANCHOR_CERT_FILENAME, 'castrated_constrained_anchor.crt');
  });
});
