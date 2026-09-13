# ca-strated

Cross-sign the Минцифры / НУЦ RSA root so browsers only accept it for DNS names you list. The original root is **never** a trust anchor. Validity of the local root and the wrap is copied from the НУЦ root (`-preserve_dates`); there is no day count in config.

```text
leaf → Russian Trusted Sub CA → russian_trusted_root_castrated_pem.crt → castrated_constrained_anchor.crt
                                      ↑ critical nameConstraints                    ↑ CN=CAstrated Constrained Anchor
```

Install **only** files under `out/trusted/` and `out/untrusted/`. Trust **only** the anchor in `out/trusted/`. Import everything in `out/untrusted/` as intermediates **without** “Always Trust”. If the unconstrained НУЦ root is trusted, this tool does nothing useful.

## Setup

```sh
brew bundle
mise install
pnpm install
```

Requires OpenSSL 3 from the Brewfile (`openssl@3`, keg-only). macOS `/usr/bin/openssl` is LibreSSL and will be rejected. Override with `OPENSSL_BIN` if needed.

## Config

[`config.json`](config.json) pins the official PEM files from [gosuslugi.ru/crt](https://www.gosuslugi.ru/crt) (currently served at `https://gu-st.ru/content/lending/…`) and allows `rzd.ru`, `gosuslugi.ru`, `gov.ru`, `sberbank.ru`, and `sbrf.ru` (apex and subdomains). The Sberbank leaf SAN also names `sbrf.ru`; every DNS SAN on a leaf must be permitted or the chain fails.

| Field | Meaning |
| --- | --- |
| `sources.*.sha256` | SHA-256 of the **file bytes**, not the cert fingerprint |
| `permittedDns` | Apex names; `example.com` allows `example.com` and subdomains. IDN is converted to ASCII. No `*.` wildcards. All DNS SANs on a leaf must match |
| `localCa.subject` | OpenSSL subject for the local trust anchor (`/CN=…`). This is the Keychain display name |

All IPv4 and IPv6 addresses are excluded (`0.0.0.0/0.0.0.0` and `::/0`) so an IP SAN cannot bypass the DNS allowlist. A leaf that also has an IP SAN fails name constraints even if its DNS names are permitted. Apple’s cert UI may render those IP trees poorly; that is display-only.

Pins recorded from a live download (update them when НУЦ rotates files):

| File | SHA-256 |
| --- | --- |
| `russian_trusted_root_ca_pem.crt` | `936a43fea6e8e525bcc0f81acd9c3d21b4fc4b9b68acea7906d698005afc6504` |
| `russian_trusted_sub_ca_pem.crt` | `f0ae589f36774f29ef3648f7984b08d42fcce6f1ffeeb6236d773daeb2744ea6` |
| `russian_trusted_sub_ca_2024_pem.crt` | `6f9d829c8e6712444fce3624658d8788672849c5d5b7b53fd9cf7e83eac4193e` |

Root certificate fingerprint (SHA-256): `D2:6D:2D:02:31:B7:C3:9F:92:CC:73:85:12:BA:54:10:35:19:E4:40:5D:68:B5:BD:70:3E:97:88:CA:8E:CF:31`.

GOST PEMs are out of scope.

## Usage

```sh
pnpm ca-strated              # fetch → inspect → issue → prove
pnpm ca-strated fetch
pnpm ca-strated inspect
pnpm ca-strated issue
pnpm ca-strated prove
pnpm test
```

`--config`, `--vendor`, and `--out` override default paths. The default config is [`config.json`](config.json).

Outputs (gitignored):

- `vendor/` — pinned upstream PEMs (fetch cache, not for install)
- `out/castrated_constrained_anchor.key` — mode `0600`; reused on later `issue` runs. This key can mint trusted certs for every allowed name. Keep it offline.
- `out/trusted/castrated_constrained_anchor.crt` — the only trust anchor (`CN=CAstrated Constrained Anchor`)
- `out/untrusted/russian_trusted_root_castrated_pem.crt` — НУЦ root public key, signed by the local root, **not** a trust anchor. Subject stays `Russian Trusted Root CA` so the Sub CAs chain
- `out/untrusted/russian_trusted_sub_ca_pem.crt` and `russian_trusted_sub_ca_2024_pem.crt` — copies of the vendor Sub CAs, upstream filenames
- `out/extensions.cnf` — OpenSSL extensions used for the last issue

Changing `permittedDns` requires `issue` again, then re-import the certs under `out/trusted/` and `out/untrusted/`. The local root is `pathlen:2` because the real chain is leaf → Sub CA → wrap → local root. Upstream root rotation requires updating pins, then `fetch` and `issue`.

## Trust-store notes

Do not run `update-ca-certificates` / Keychain “Always Trust” on the original НУЦ root or on anything in `out/untrusted/`.

**macOS Keychain:** import `out/trusted/*.crt` and enable trust for SSL. Import every file in `out/untrusted/` as certificates only. The wrap still appears as “Russian Trusted Root CA”; the anchor appears as “CAstrated Constrained Anchor”.

**Firefox** uses its own NSS database (`certutil`). Trust bits for the local root are `C,,`; the wrap and Sub CAs are `,,`.

A local HTTPS-inspecting antivirus proxy ignores these constraints. Re-issue does not install anything; it only writes files under `out/`.

**Safari / Chrome / Dia “View Certificate”:** Apple’s `SFCertificatePanel` crashes (`attributedCertificateName`) on typical Минцифры OV leaves. Those subjects include OGRN (`1.2.643.100.1`) and INN (`1.2.643.100.4`) as `NUMERICSTRING`; SecurityInterface fails to parse the name and then traps while drawing the chain table. The same OIDs as UTF-8 parse. This is the site leaf, not the wrap or local root. HTTPS still works. Dump the leaf with `openssl x509 -text` instead of the browser viewer.
