# Proton VPN for Decky

A Decky Quick Access plugin for viewing and toggling Proton VPN connections created by Proton VPN for Linux.

## Status

Development and backend integration checks were performed on a Steam Deck running SteamOS 3.8.28, in Desktop Mode. The Gaming Mode panel still needs manual testing on the target Deck and Decky Loader version. This is an initial prototype.

## Requirements

- Steam Deck with Decky Loader installed
- Proton VPN installed from Discover in Desktop Mode
- Proton CLI signed in at least once in Desktop Mode

The Proton VPN Flatpak includes the official Linux CLI. The plugin does not install Proton VPN or handle account sign-in. Install the Flatpak from Discover, then close its GUI before using the CLI; Proton does not support running the GUI and CLI concurrently.

For first-time sign-in, open Konsole in Desktop Mode and run `flatpak run --command=protonvpn com.protonvpn.www signin <username>`. Proton CLI handles the password and any 2FA/security-key prompts in its terminal. Decky never receives or stores those secrets.

## Usage

Open **... > Decky > Proton VPN** in Gaming Mode. The panel shows CLI connection status and an authenticated country selector. Connect, switch, and disconnect actions all go through Proton's own CLI so it can keep its connection and kill-switch state synchronized.

The Proton VPN GUI and CLI cannot run at the same time. Close the GUI before using the Decky CLI controls. Proton documents the CLI as terminal-oriented and says headless use is not currently supported, so this Decky integration is experimental.

The CLI manages its own authentication persistence through Proton's Linux keyring integration. The plugin does not cache credentials. Steam Deck user accounts normally have no login password, so do not assume locally stored sessions are protected against someone with physical access to the device. Proton CLI sign-out is available with `flatpak run --command=protonvpn com.protonvpn.www signout`; use it when the Deck is shared.

The plugin does not install the Flatpak automatically. Installing applications from Gaming Mode requires package-manager permissions and user confirmation; use Discover in Desktop Mode for this one-time setup.

The VPN applies to Deck traffic generally, not only Stremio.

## Development on Steam Deck

The workflow below was tested from Desktop Mode. On systems with Node.js and pnpm 9 available, the script uses them. If those commands are unavailable but VS Code's Flatpak is installed, it uses VS Code's bundled Node and caches pnpm 9.15.9 under `~/.cache/decky-protonvpn`; it does not install packages into SteamOS.

```sh
./scripts/decky-dev.sh install
./scripts/decky-dev.sh test
./scripts/decky-dev.sh build
```

The VS Code **Decky: Install dependencies**, **Decky: Test**, and **Decky: Build** tasks call the same script.

## Manual Gaming Mode Test

1. In Desktop Mode, run `./scripts/decky-dev.sh package`. This builds `out/decky-protonvpn-dev.zip` in Decky's expected ZIP layout.
2. In Gaming Mode, open **... > Decky > Settings > General > Manual Plugin Install > Load from ZIP file** and select the ZIP.
3. If the CLI is signed out, close Proton VPN, sign in from Konsole as described above, then use **Refresh Proton VPN status** in the plugin.
4. Connect or switch countries from the plugin. Disconnect from the plugin to verify Proton CLI restores networking and clears its kill switch; then verify Stremio can connect.
5. Rebuild and reinstall the ZIP after code changes.

`out/`, `dist/`, dependencies, and Python caches are ignored by Git; the test ZIP is not committed.
