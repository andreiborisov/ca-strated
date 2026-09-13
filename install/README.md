# CAstrated

Install these so a few Минцифры sites work **without** trusting the official Russian Trusted Root CA for the rest of the internet.

**Trust only the cert in `trusted/`.** Files in `untrusted/` are intermediates — install them, but do not turn on “Always Trust” / full root trust.

These certs allow `rzd.ru`, `gosuslugi.ru`, `gov.ru`, `sberbank.ru`, and `sbrf.ru` (including subdomains). A site whose certificate also names some other DNS name will still fail.

Русская версия: [README.ru.md](README.ru.md)

## macOS

1. Open **Keychain Access**. Use the **login** keychain.
2. Open every `.crt` in `trusted/` and in `untrusted/` (double-click or drop them onto Keychain Access).
3. Find **CAstrated Constrained Anchor**. Double-click it → expand **Trust** → set **Secure Sockets Layer (SSL)** to **Always Trust**. Leave other settings alone. Close and enter your password.
4. For **Russian Trusted Root CA** and both **Russian Trusted Sub CA** certs: leave trust on default (“Use System Defaults”). Do **not** Always Trust them.
5. If you previously installed the official Russian Trusted Root CA from gosuslugi.ru/crt, delete that one. Keeping it would bypass these limits.

Safari, Chrome, and Dia use this Keychain. Firefox does not — skip Firefox or add the same certs in its own settings (`CAstrated Constrained Anchor` trusted for websites; the others untrusted).

## iOS

AirDrop the `.crt` files, or share the unzipped folder and open each cert in **Files**.

1. Install **CAstrated Constrained Anchor** from `trusted/` first. iOS shows a profile under **Settings → General → VPN & Device Management**. Tap it and install.
2. Then install every `.crt` in `untrusted/` the same way (clipped root + both Sub CAs).
3. Enable full trust **only** for the anchor: **Settings → General → About → Certificate Trust Settings** → turn on **CAstrated Constrained Anchor**.
4. Leave the Russian Trusted Root / Sub CA profiles installed, but do **not** enable them under Certificate Trust Settings.
5. Remove any older “Russian Trusted Root CA” profile you installed from the official Минцифры site.

iOS Safari (and Chrome / Dia, which use it) picks this up after trust is enabled. A reboot is rarely needed; if a site still fails, toggle the trust switch off and on.

## If a site still fails

- Confirm SSL Always Trust / Certificate Trust is on **only** for CAstrated Constrained Anchor.
- Confirm the official unconstrained root is **not** trusted.
- “View Certificate” in Safari or Chrome may crash on these sites. That is an Apple bug in the viewer, not a sign the page is untrusted. The padlock can still be fine.
