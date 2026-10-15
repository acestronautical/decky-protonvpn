# Proton VPN for Decky

A Decky Quick Access plugin for viewing and toggling Proton VPN connections created by Proton VPN for Linux.

## Status

Earlier backend integration checks were performed on a Steam Deck running SteamOS 3.8.28, in Desktop Mode. The encrypted Gaming Mode sign-in flow has automated backend and Web Crypto/OpenSSL interoperability tests, also run on macOS. The Gaming Mode panel, actual Proton authentication, and keyring behavior still need manual testing on the target Deck and Decky Loader version. This is an experimental prototype, not a security certification.

## Requirements

- Steam Deck with Decky Loader installed
- Proton VPN installed from Discover in Desktop Mode
- A current Proton VPN Flatpak CLI with `signin --totp` support
- For Gaming Mode sign-in: Web Crypto in Steam's browser, `/usr/bin/openssl`, and writable `/dev/shm` on SteamOS

The Proton VPN Flatpak includes the official Linux CLI. The plugin does not install Proton VPN. Install or update the Flatpak from Discover, then close its GUI before using the plugin; Proton does not support running the GUI and CLI concurrently.

## Sign In

In Gaming Mode, open **... > Decky > Proton VPN** and enter your Proton username, password, and authenticator or recovery code if required. Leave the code empty for accounts without 2FA. Select **Sign in**. Password and code fields clear on submission; failed attempts require re-entry. A missing or expired code requires a new attempt, not an automatic retry. Security-key interaction and other interactive challenges are not supported by this form.

For security-key authentication, unsupported CLI versions, unavailable Web Crypto/keyring, or oversized credentials, open Konsole in Desktop Mode and run `flatpak run --command=protonvpn com.protonvpn.www signin <username>`. Enter secrets only at Proton's prompts, never as command arguments. Afterwards, refresh the plugin's status. This fallback keeps credentials out of the plugin entirely.

Closing the panel cancels unused encryption sessions, but cannot undo a sign-in already submitted to Proton. After closing during sign-in, a timeout, or losing the Decky connection, refresh status before retrying. Do not assume a missing response means authentication failed.

If the CLI completes sign-in but a follow-up check fails, the panel reports a verification failure instead of treating it as a rejected password. A failed connection-status check preserves a previously confirmed signed-in state; an unsuccessful account check leaves authentication unknown and hides the login form until refresh confirms that you are signed out. CLI failures identify the operation, a sanitized error category, and exit code. Report that message, not passwords, codes, account names, or raw CLI logs.

## Security Boundaries

- The frontend encrypts the username, password, and code with a fresh RSA-4096 OAEP key using SHA-256/MGF1-SHA-256 before calling Decky's completion RPC. Only the session ID and ciphertext are sent in that RPC; there is no plaintext fallback.
- Sessions are one-use, including failed decryption attempts, and expire after five minutes. At most four pending keys and one key generation are allowed. Expired keys are cleared by periodic cleanup, cancellation, submission, and plugin unload. CLI operations cannot overlap through the plugin.
- The plugin passes the password and code through the CLI's stdin, not argv, environment variables, or credential files. The CLI requires the username as an argument, so it can be visible to local process inspection. CLI output is captured and errors exposed by the plugin are sanitized.
- During decryption, OpenSSL reads the private key through an inherited file descriptor referring to an anonymous temporary file in `/dev/shm`. It has no directory entry and closes after decryption. There is no production fallback to a disk-backed directory. `/dev/shm` is normally RAM-backed but may be swapped.
- Password/code fields and mutable plaintext/key buffers are cleared on the relevant completion and cleanup paths. Python and JavaScript strings, subprocess buffers, browser internals, and OS memory cannot be reliably zeroized, so this is best-effort lifetime reduction, not a guarantee against memory or disk forensics.
- Encryption limits exposure in Decky RPC payloads/logs. It does not authenticate the key exchange against an active attacker or protect against malicious plugins, a compromised Steam/Decky process, root, or someone controlling the local account. The plugin necessarily handles plaintext credentials in memory. Only install trusted plugins; keep remote debugging and Decky access restricted.
- The RSA envelope holds at most 446 UTF-8 bytes including JSON field names and escaping. Oversized credentials are rejected without truncation. Use Desktop Mode for these credentials rather than shortening your password.

The supported prompt sequence was checked against [Proton's CLI account command](https://github.com/ProtonVPN/proton-vpn-cli/blob/7958dd7982a2dbbd4b1d089818ae9079a3fe8f7d/proton/vpn/cli/commands/account.py). The installed Flatpak version can differ; verify it on the Deck.

## Usage

Open **... > Decky > Proton VPN** in Gaming Mode. The panel shows CLI connection status and an authenticated country selector. Connect, switch, and disconnect actions all go through Proton's own CLI so it can keep its connection and kill-switch state synchronized.

The Proton VPN GUI and CLI cannot run at the same time. Close the GUI before using the Decky CLI controls. Proton documents the CLI as terminal-oriented and says headless use is not currently supported, so this Decky integration is experimental.

The CLI manages its own authentication persistence through Proton's Linux keyring integration. The plugin does not persist passwords, codes, or Proton session tokens. Its cleanup does not sign out or revoke the CLI session. Steam Deck user accounts normally have no login password, so do not assume locally stored sessions are protected against someone with physical access to the device. Proton CLI sign-out is available with `flatpak run --command=protonvpn com.protonvpn.www signout`; use it when the Deck is shared. Proton's own logging and keyring implementation are outside this plugin's control.

The plugin does not install the Flatpak automatically. Installing applications from Gaming Mode requires package-manager permissions and user confirmation; use Discover in Desktop Mode for this one-time setup.

The VPN applies to Deck traffic generally, not only Stremio.

## Flatpak Detection Troubleshooting

A system-wide Proton installation does not require running the plugin as root. Check it from Desktop Mode Konsole with `flatpak info com.protonvpn.www`. A terminal inside VS Code's Flatpak may require `flatpak-spawn --host flatpak info com.protonvpn.www` instead; that does not mean Decky also runs inside that sandbox.

Installation checks distinguish a missing app from a failed Flatpak command. Failures display a sanitized category and exit code, not raw CLI output. Report that exact message when troubleshooting.

When running inside a PyInstaller-frozen loader, the plugin restores `LD_LIBRARY_PATH_ORIG` (or removes `LD_LIBRARY_PATH` if no original exists) in the environment passed to Flatpak and OpenSSL. This follows [PyInstaller's guidance for launching system programs](https://pyinstaller.org/en/stable/common-issues-and-pitfalls.html#launching-external-programs-from-the-frozen-application) and avoids loading incompatible bundled libraries. It does not modify Decky's process environment, change user privileges, or replace the user's D-Bus settings. A passing local test does not confirm that library conflicts caused a particular on-device failure.

## Gaming Mode Keyring Diagnostics

When a status or account check fails with a keyring-related CLI error, the panel automatically collects and displays a sanitized report from inside Proton's Flatpak, using the same child environment as the failing command. Install the current ZIP, open the panel in Gaming Mode, and capture the error and diagnostic rows together. There is no need to sign in again or switch modes to run individual checks. The same report is written to Decky's plugin log with the prefix `Proton VPN keyring diagnostics:`.

The report includes user privilege level, whether the bus address matches the standard user-session address, display/Proton-loader/Snap environment flags, registered Proton keyring drivers, available CLI/keyring package versions, session-bus reachability, Secret Service availability/provider, default collection lock state, and recognized CLI exception names. It never reports environment values, account names, collection labels, secret contents, or raw CLI output. Unknown provider/driver names are reported as `other`.

The probe only checks a running Secret Service; it does not explicitly activate an inactive service, create a collection, request an unlock, read credential items, change permissions, select a new backend, or retry authentication. Registered drivers are not proof of which backend Proton selected: Proton's backend validation performs a credential lookup, so the probe deliberately does not invoke it. An unlocked default collection also does not prove that Proton's particular credential items are accessible.

Each probe has a 10-second subprocess timeout. If the inherited runtime directory or session-bus address differs from the standard address for the plugin's effective user, a second probe compares the standard environment without changing normal CLI execution. Probe failures remain diagnostic information and do not replace the original error. These checks narrow the on-device cause; their simulated tests on macOS do not establish a working Gaming Mode keyring.

The report also checks the host user bus using `/usr/bin/busctl`, because Flatpak filters service names other than those it is allowed to access. Each host query has a five-second D-Bus timeout and a six-second subprocess timeout. When no host Secret Service is running and an unambiguous existing provider is activatable, the panel offers **Start existing keyring service**. This explicitly requests D-Bus activation of the registered service and then checks Proton's status again. It supports the canonical Secret Service name, KDE's `ksecretd` compatibility service, KWallet 6/5, and GNOME Keyring. It refuses to choose between competing KDE and GNOME providers without a canonical Secret Service registration.

Activation runs as the Deck user, never root. It does not install packages, enable persistent services, replace a running provider, change Flatpak permissions, force Proton's JSON backend, or handle the wallet password. A provider may still need its normal unlock prompt; starting it is not proof that Proton can use its credentials. If no provider is registered, or startup fails, the panel reports that outcome instead of silently weakening storage security. A host service that is running but invisible inside Flatpak is reported separately and is not replaced.

## Development on Steam Deck

The workflow below was tested from Desktop Mode. On systems with Node.js and pnpm 9 available, the script uses them. If those commands are unavailable but VS Code's Flatpak is installed, it uses VS Code's bundled Node and caches pnpm 9.15.9 under `~/.cache/decky-protonvpn`; it does not install packages into SteamOS.

```sh
./scripts/decky-dev.sh install
./scripts/decky-dev.sh test
./scripts/decky-dev.sh build
```

The VS Code **Decky: Install dependencies**, **Decky: Test**, and **Decky: Build** tasks call the same script.

The full test suite requires Python 3.10+, Node.js 18+, installed JavaScript dependencies, and `/usr/bin/openssl`. It uses dummy credentials and never contacts Proton. On macOS the interoperability test alone substitutes a normal temporary directory for missing `/dev/shm`; production retains its SteamOS-only path. Backend-only checks remain available with `python3 -m unittest discover -s tests`.

With Node/npm installed but no global pnpm, local validation can use:

```sh
npx --yes pnpm@9.15.9 install --frozen-lockfile
npm test
npx --yes pnpm@9.15.9 exec tsc --noEmit --skipLibCheck
npm run build
npx --yes --package pnpm@9.15.9 -- ./scripts/decky-dev.sh package
```

`--skipLibCheck` skips existing upstream Decky/react-icons declaration issues (missing `react-router` declarations and React JSX namespace mismatches), not project source checks. Decky provides the Python `decky` module and the Steam UI runtime on-device; they are not standalone macOS services.

## Manual Gaming Mode Test

1. In Desktop Mode, run `./scripts/decky-dev.sh package`. This builds `out/decky-protonvpn-dev.zip` in Decky's expected ZIP layout.
2. In Gaming Mode, open **... > Decky > Settings > General > Manual Plugin Install > Load from ZIP file** and select the ZIP.
3. Close Proton's GUI and test signed-out login in the panel with the Steam keyboard/controller. Verify password/code masking, focus, long error wrapping, and no overlapping controls. Test accounts without 2FA and with an authenticator; only test recovery codes with permission to consume one.
4. Test an incorrect password, missing/expired code, offline network, GUI already running, and unavailable/locked keyring. Errors must not display credentials. Verify retry works without overlapping CLI processes.
5. Close/reopen the panel during key generation and during submitted sign-in. Refresh to discover the final state. Test plugin reload, a five-minute abandoned session, and timeout recovery. Confirm no abandoned key files or sign-in processes remain after normal completion/failure.
6. Using disposable test credentials, inspect Decky's logs and RPC requests locally: only the encrypted envelope should cross the completion RPC, and passwords/codes must not appear in logs or process arguments. Do not upload unredacted logs. Review Proton's own logs separately.
7. Confirm authentication persists through a plugin reload and Gaming Mode restart without re-entering credentials. Sign out from Konsole and refresh to verify the plugin returns to its signed-out state.
8. Connect or switch countries from the plugin. Disconnect from the plugin to verify Proton CLI restores networking and clears its kill switch; then verify Stremio can connect.
9. Rebuild and reinstall the ZIP after code changes. Record SteamOS, Decky, Proton Flatpak, and CLI versions with the results.

`out/`, `dist/`, dependencies, and Python caches are ignored by Git; the test ZIP is not committed.
