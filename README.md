# ✂️ CAstrated

> Need a few Минцифры sites without trusting the whole Russian Trusted Root CA?

> CAstrated clips that CA down to the DNS names you list. Browsers still see a normal chain — they just will not accept it for anything else. The original root is **never** a trust anchor.

## 🧠 How it works

The official НУЦ RSA root is downloaded, pinned, and **cross-signed** by a local CA (`CAstrated Constrained Anchor`). The wrap keeps the original subject and public key so Russian Trusted Sub CA still chains, and adds critical `nameConstraints` (your DNS allowlist, no IP SANs).

```text
site leaf → Russian Trusted Sub CA → clipped НУЦ root → CAstrated Constrained Anchor
```

Trust **only** the last cert. Everything else is an intermediate. If the unconstrained НУЦ root is in the trust store, this does nothing useful.

Validity of the anchor and the wrap is copied from the official root (`-preserve_dates`). GOST PEMs are out of scope.

## 💾 Setup

```sh
brew bundle
mise install
pnpm install
pnpm ca-strated    # fetch → inspect → issue → prove
```

Needs OpenSSL 3 from the Brewfile (`openssl@3`, keg-only). macOS `/usr/bin/openssl` is LibreSSL and will be rejected. Override with `OPENSSL_BIN` if you must.

```sh
pnpm ca-strated fetch
pnpm ca-strated inspect
pnpm ca-strated issue
pnpm ca-strated prove
pnpm test
```

`--config`, `--vendor`, and `--out` override the default paths. Config is [`config.json`](config.json).

`issue` writes the install set under `out/` and packs **`CAstrated Russian Certificates.zip`** (trusted + untrusted + install READMEs). Share the zip, not the private key.

## ⚙️ Config

[`config.json`](config.json) pins the PEMs from [gosuslugi.ru/crt](https://www.gosuslugi.ru/crt) (served at `https://gu-st.ru/content/lending/…`) and allows `rzd.ru`, `gosuslugi.ru`, `gov.ru`, `sberbank.ru`, and `sbrf.ru` (apex and subdomains).

| Field | Meaning |
| --- | --- |
| `sources.*.sha256` | SHA-256 of the **file bytes**, not the cert fingerprint |
| `permittedDns` | Apex names. `example.com` covers itself and subdomains. IDN → ASCII. No `*.` wildcards. **Every DNS SAN on a leaf must match** (Sberbank also names `sbrf.ru`) |
| `localCa.subject` | OpenSSL subject for the local anchor — this is the Keychain / iOS display name |

Change `permittedDns`, run `issue` again, then re-import the zip. The local root is `pathlen:2` because the live chain is leaf → Sub CA → wrap → anchor. When НУЦ rotates files, update the pins, then `fetch` and `issue`.

File pins (update when НУЦ publishes new PEMs):

| File | SHA-256 |
| --- | --- |
| `russian_trusted_root_ca_pem.crt` | `936a43fea6e8e525bcc0f81acd9c3d21b4fc4b9b68acea7906d698005afc6504` |
| `russian_trusted_sub_ca_pem.crt` | `f0ae589f36774f29ef3648f7984b08d42fcce6f1ffeeb6236d773daeb2744ea6` |
| `russian_trusted_sub_ca_2024_pem.crt` | `6f9d829c8e6712444fce3624658d8788672849c5d5b7b53fd9cf7e83eac4193e` |

Official root fingerprint (SHA-256): `D2:6D:2D:02:31:B7:C3:9F:92:CC:73:85:12:BA:54:10:35:19:E4:40:5D:68:B5:BD:70:3E:97:88:CA:8E:CF:31`.

## 📦 What to install

Give people the zip. Instructions inside (`README.md` / `README.ru.md`) cover macOS and iOS.

- **`trusted/`** — Always Trust for SSL. One cert: `CAstrated Constrained Anchor`
- **`untrusted/`** — certificate only, never Always Trust: clipped root + both Sub CAs

Keep `out/castrated_constrained_anchor.key` offline. It can mint trusted certs for every allowed name.

**Firefox** has its own store (`certutil`): `C,,` on the anchor, `,,` on everything in `untrusted/`.

A local HTTPS-inspecting antivirus proxy ignores these constraints. `issue` only writes files; it does not touch Keychain.

Safari / Chrome / Dia **View Certificate** may crash on typical Минцифры OV leaves (OGRN / INN as `NUMERICSTRING`). HTTPS still works. Use `openssl x509 -text` if you need to inspect the leaf.

## 🗂️ Structure

```
config.json                     # pins, allowlist, local CN
install/                        # copied into the zip
  README.md
  README.ru.md
src/                            # fetch, inspect, issue, prove
out/                            # gitignored
  CAstrated Russian Certificates.zip
  trusted/                      # the only trust anchor
  untrusted/                    # wrap + Sub CAs
  castrated_constrained_anchor.key
vendor/                         # gitignored fetch cache (includes the original root — do not install it)
```
