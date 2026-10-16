# Proton VPN for Decky

A Decky Quick Access plugin for viewing and toggling Proton VPN connections created by Proton VPN for Linux.

## Status

Backend integration checks were performed on a Steam Deck running SteamOS 3.8.28. On-device investigation verified Gaming Mode keyring startup and a route-snapshot compatibility fix: the CLI connected successfully, a fresh CLI process recognized the connection, and external IPv4 traffic used the VPN. The encrypted sign-in flow also has automated backend and Web Crypto/OpenSSL interoperability tests. Full Gaming Mode UI testing, reboot/session transitions, and comprehensive IPv6/DNS leak testing remain required. This is an experimental prototype, not a security certification.

## Requirements

- Steam Deck with Decky Loader installed
- Proton VPN installed from Discover in Desktop Mode
- A current Proton VPN Flatpak CLI with `signin --totp` support
- For Gaming Mode sign-in: Web Crypto in Steam's browser, `/usr/bin/openssl`, and writable `/dev/shm` on SteamOS

The Proton VPN Flatpak includes the official Linux CLI. The plugin does not install Proton VPN. Install or update the Flatpak from Discover, then close its GUI before using the plugin; Proton does not support running the GUI and CLI concurrently.

## Sign In

In Gaming Mode, open **... > Decky > Proton VPN** and enter your Proton username, password, and authenticator or recovery code if required. Leave the code empty for accounts without 2FA. Select **Sign in**. Password and code fields clear on submission; failed attempts require re-entry. A missing or expired code requires a new attempt, not an automatic retry. Security-key interaction and other interactive challenges are not supported by this form.

Only the validated username is remembered in the browser's plugin-scoped local storage, including after sign-out. It is not secret or encrypted storage. Passwords and 2FA/recovery codes are never cached. If browser storage is unavailable, sign-in still works without remembering the username.

For security-key authentication, unsupported CLI versions, unavailable Web Crypto/keyring, or oversized credentials, open Konsole in Desktop Mode and run `flatpak run --command=protonvpn com.protonvpn.www signin <username>`. Enter secrets only at Proton's prompts, never as command arguments. Afterwards, refresh the plugin's status. This fallback keeps credentials out of the plugin entirely.

Closing the panel cancels unused encryption sessions, but cannot undo a sign-in already submitted to Proton. After closing during sign-in, a timeout, or losing the Decky connection, refresh status before retrying. Do not assume a missing response means authentication failed.

If the CLI completes sign-in but a follow-up check fails, the panel reports a verification failure instead of treating it as a rejected password. A failed connection-status check preserves a previously confirmed signed-in state; an unsuccessful account check leaves authentication unknown and hides the login form until refresh confirms that you are signed out. CLI failures identify the operation, a sanitized error category, and exit code. Report that message, not passwords, codes, account names, or raw CLI logs.

A successful CLI exit without a verified signed-in account is reported as incomplete sign-in, not silent success. The plugin log records fixed sign-in stages with the prefix `Proton VPN sign-in:`: session requested/ready/failed, encrypted submission received, completion outcome, and unused-session cleanup requested. These events do not contain usernames, passwords, codes, session IDs, keys, ciphertext, or raw errors. Cleanup is also requested after normal completion; it does not indicate that authentication was cancelled. Missing stages can help locate an interrupted request, but do not prove why it stopped.

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

Open **... > Decky > Proton VPN** in Gaming Mode. Native **Connection | Settings | Account** tabs use Decky's L1/R1 navigation, following MagicPods. The selected tab and pending country survive panel remounts. The connection summary is a focusable top-of-panel target. The supplied `protonvpn-dark.png` inherits native sidebar icon sizing.

Viewing **Connection**, including its error-only **Retry**, runs only a bounded NetworkManager query: no Proton CLI, account check, keyring startup, or settings query. It reports the activated WireGuard tunnel on `proton0`, protocol, and a server identifier when present in the connection name. Unknown/transitioning states remain unknown. It does not fetch city, server load, account details, or a server list, and an active tunnel alone does not prove VPN egress or leak protection.

Opening **Settings** or **Account** lazily reads account state and the exposed settings in one guarded Flatpak process. Rapid tab changes share the in-flight request. This read avoids the normal Proton `status` command and its server-list refresh. Connect, switch, disconnect, sign-in/out, and setting changes still invoke Proton explicitly. Actions remain blocked during an outstanding account/settings read. Errors expose **Retry** and optional diagnostic details; there is no normal debug refresh button.

- **Quick connect** uses Proton's fastest-server selection with no country argument. Choose a country under **Location** for a specific destination; while connected, **Switch server** applies that selection.
- **Disconnect** is the primary action while connected.
- **Kill switch** reflects Proton's actual `off` or `standard` setting, not a cached preference. Proton requires disconnection before changes: the toggle is disabled while connected or tunnel state is unknown. The plugin never disconnects automatically to change this setting. Disabling it requires confirmation. Standard mode blocks traffic after an unexpected VPN drop, but restores internet after intentional disconnection. A changed setting is read back before the toggle updates.
- **NetShield** offers Off, malware blocking, or malware/ad/tracker blocking. Selecting an option only changes the pending choice; **Apply NetShield** commits it.
- **VPN Accelerator** and **Moderate NAT** use native toggles and verified readback. Unavailable paid-plan settings are disabled and labeled **VPN Plus required**. Proton's reconnect requirements are surfaced without automatically reconnecting.
- **Sign out** requires confirmation, verifies disconnection first, then asks Proton to clear the session. Failure to verify tunnel removal stops sign-out. The saved username remains available for the next sign-in.

The country dropdown and backend validation share a bundled snapshot in `py_modules/protonvpn/countries.json`, based on [Proton's public server list](https://protonvpn.com/vpn-servers). Opening the country list and validating a selection run no country-list CLI command and make no online country request. The snapshot is maintained with plugin releases; account restrictions and temporary server availability are checked by Proton when connecting. Quick Connect remains available without selecting a country.

Sign Out and setting changes use the same bounded user-service launcher as Connect and Disconnect. Country loading and connection-only viewing do not start or access the keyring; only account-dependent operations need wallet preflight.

All plugin CLI calls use a small compatibility launcher inside Proton's Flatpak. Before running the CLI, it installs a non-destructive getter for the verified Secret Service backend: malformed JSON raises a sanitized keyring error instead of deleting the saved record. Valid reads, missing records, and the existing newline workaround retain their behavior. This guard requires an exact source SHA-256 match; an unknown getter blocks CLI execution rather than risking deletion. It does not repair malformed data or missing account indexes, and does not protect commands launched outside the plugin.

For Connect and Disconnect, the launcher also fixes a verified upstream WireGuard implementation that can reapply stale route settings after an asynchronous NetworkManager callback. Cleanup then times out before saving connection metadata, leaving an active tunnel that a fresh CLI process reports as disconnected. The launcher snapshots the requested configuration before the callback. It applies this change only when the upstream method's source SHA-256 matches the implementation verified on the Deck; different route implementations run unchanged. It does not modify installed Proton files, bypass route checks, disable leak protection, or retry failed operations. Sign-in still receives secrets only through stdin.

Network commands run through `systemd-run --user` in a transient `decky-protonvpn-network.service`. An actual Gaming Mode connection attempt failed NetworkManager's `connection-add` permission check even though SSH integration tests succeeded. One actual Gaming Mode Connect/Disconnect cycle subsequently passed with this user-service launcher and retained authentication. It requires the standard user bus, refuses root, preserves command output and exit status, and never retries or falls back to elevated privileges. The service has an 85-second runtime limit and three-second stop timeout, is collected after exit, and installs no persistent unit or policy changes. Only that service receives the fixed locale/user-bus environment and cleared library overrides; the global user-manager environment is unchanged.

The launcher also guards the verified upstream disconnect cleanup against cancelled background tasks, such as the server ping stopped during disconnection. Without this fix, the CLI can print `Disconnected.` but exit with code 1 after successfully removing the tunnel. This fix has its own source fingerprint and applies only to Disconnect. Real task failures, the cleanup deadline, and cancellation of the command itself still propagate as errors; the launcher does not infer success from printed output.

After an interrupted or failed connection, CLI status alone may be insufficient to establish whether a tunnel is active. NetworkManager is now the authoritative connection-state source, with a five-second timeout; Proton account/settings reads cannot override it. An activated tunnel stays visible even when the account check fails. This is not a traffic or leak-protection test. The plugin does not automatically reconstruct missing connection metadata, delete orphaned NetworkManager profiles, or repair Proton's saved-account index. On-device logs confirmed Proton deleting a saved record after JSON decoding failed; why the wallet returned invalid data remains unresolved. Earlier failed connection attempts also left temporary autoconnect profiles that required explicitly approved cleanup before testing.

A saved account does not establish that Secret Service is running; the wallet service may have exited since sign-in or a mode switch. The development Deck's wallet journal recorded `The X11 connection broke`. Account-dependent operations check and, if needed, start the existing provider through the guarded launcher, discovering Steam's current display when KDE needs restarting. Country loading is entirely offline and does not access the wallet. A running service is not replaced. If startup fails, account reads and credential submission do not proceed. Proton may still need a native wallet unlock prompt; service startup alone does not prove credential access. Connect/disconnect failures return a readable error rather than Decky's generic Python exception. Reopen the panel or use error-only **Retry** to check status before retrying an action, especially after a timeout; the plugin does not automatically retry a VPN operation.

The candidate backend was exercised from memory on the Deck: it restarted an absent wallet, reported an active tunnel despite a missing account index, and passed one explicitly approved Disconnect/Connect cycle with consistent fresh status after a separately approved one-time index restoration. The new guard and recovery behavior still require installed Gaming Mode and reboot/session-transition verification. No password or account-record changes were part of that test.

Sign-in logging also records fixed keyring-preparation and CLI-start stages and the numeric CLI exit code. Unrecognized sign-in failures report a sanitized CLI category, not raw output. Gaming Mode wallet-prompt visibility and an observed UI freeze remain under investigation; switching graphical sessions restored the UI but did not establish the cause.

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

The report also checks the host user bus using `/usr/bin/busctl`, because Flatpak filters service names other than those it is allowed to access. Each host query has a five-second D-Bus timeout and a six-second subprocess timeout. When no host Secret Service is running and an unambiguous existing provider is activatable, the panel offers **Start existing keyring service**. This explicitly starts the registered provider and then checks Proton's status again. It supports the canonical Secret Service name, KDE's `ksecretd` compatibility service, KWallet 6/5, and GNOME Keyring. It refuses to choose between competing KDE and GNOME providers without a canonical Secret Service registration.

KDE's `org.kde.secretservicecompat` provider needs a graphical display even before a wallet unlock is requested. On-device logs confirmed that ordinary D-Bus activation can crash `ksecretd` in Gaming Mode with `qt.qpa.xcb: could not connect to display`: Steam had `DISPLAY=:0`, while the user service manager had no display settings. For this provider, the explicit start action discovers `DISPLAY` and optional `XAUTHORITY` from a running `steam` process owned by the current user. It accepts only a local X11 display with an existing socket, validates any explicit authority-file path and ownership without reading the file, and refuses missing or ambiguous displays. The process scan has a two-second budget, a 4096-entry limit, and a 128 KiB environment-read limit per candidate. Other environment values are not forwarded or logged.

The plugin starts `/usr/bin/ksecretd` through `systemd-run --user` as the transient `decky-protonvpn-keyring.service`, with Steam's display and Qt's `xcb` backend. Only that service's environment is changed; stale Wayland, Qt plugin-path, and library-path overrides are removed there. The standard user bus is required. No unit file or autostart setting is installed, and the unit is collected when it exits. Startup waits for `org.freedesktop.secrets` with a ten-second service-start timeout and a fifteen-second launcher timeout. Other providers retain normal D-Bus activation. A running Secret Service is never replaced. This launch was verified in Gaming Mode on a Steam Deck: Secret Service became visible inside Proton's Flatpak and CLI status returned `Disconnected` without a keyring error. This does not establish native unlock-prompt visibility, VPN connection success, or behavior across reboot and session changes.

Activation runs as the Deck user, never root. It does not install packages, enable persistent services, replace a running provider, change Flatpak permissions, force Proton's JSON backend, or handle the wallet password. A provider may still need its normal unlock prompt; starting it is not proof that Proton can use its credentials. If no provider is registered, or startup fails, the panel reports that outcome instead of silently weakening storage security. A host service that is running but invisible inside Flatpak is reported separately and is not replaced.

If an activation request fails, the panel preserves recognized D-Bus startup errors (including process termination signals) and reads at most 40 recent KDE wallet journal entries from the current boot, current user, and activation time onward. This extra read has a six-second timeout. Only fixed descriptions of recognized Qt display/platform failures, disabled-wallet configuration, library failures, or PAM unlock failures are displayed; raw messages are never displayed or logged by the plugin. Missing or inaccessible journal entries are reported as missing evidence, not a healthy service. These findings do not trigger a headless wallet or automatic retries. The activation stage and startup report are also logged with the prefix `Proton VPN keyring activation:` so they can be inspected after switching modes. A failure before launch explicitly reports that activation was not attempted.

## Development on Steam Deck

### Backend Layout

- `main.py`: Decky RPCs, operation serialization, encrypted sign-in sessions, and status/recovery orchestration.
- `py_modules/protonvpn/proton_cli.py`: subprocess environment, Flatpak detection, CLI execution, sanitized errors, and output parsing.
- `py_modules/protonvpn/cli_compat.py`: source-gated route-snapshot and disconnect-cleanup fixes, executed inside Proton's Flatpak for network commands.
- `py_modules/protonvpn/keyring.py`: read-only probes, provider selection, service activation, and sanitized startup diagnostics.

Decky adds `py_modules` to Python's module search path. The helper package does not import `main.py` or Decky; status verification after activation stays in `main.py`. Packaging includes the helper sources, tests reproduce Decky's import path, and `pyrightconfig.json` supplies the same path for editor analysis.

### Local Commands

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
