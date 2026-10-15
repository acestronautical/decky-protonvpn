# Proton VPN for Decky

A Decky Quick Access plugin for viewing and toggling Proton VPN connections created by Proton VPN for Linux.

## Status

Development and backend integration checks were performed on a Steam Deck running SteamOS 3.8.28, in Desktop Mode. The Gaming Mode panel still needs manual testing on the target Deck and Decky Loader version. This is an initial prototype.

## Requirements

- Steam Deck with Decky Loader installed
- Proton VPN installed from Discover in Desktop Mode
- A Proton VPN connection created at least once in Desktop Mode

The plugin does not install Proton VPN or handle account sign-in. If the app is missing, install it from Discover. If no Proton profile is found, open Proton VPN in Desktop Mode, sign in if needed, and connect once.

## Usage

Open **... > Decky > Proton VPN** in Gaming Mode. The panel shows connection status and saved profiles. It only controls NetworkManager VPN or WireGuard profiles whose names begin with `ProtonVPN` (case-insensitive).

The plugin can select only profiles already created by Proton VPN; it does not fetch Proton's server catalog or create country profiles. It refuses to switch profiles while another Proton profile is active. Disconnect the active profile before connecting a different one.

The NetworkManager connection routes Deck traffic, not only Stremio. This plugin does not provide a kill switch. The backend runs as root because NetworkManager needs elevated access to manage the tunnel; review the code before installing.

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
2. Run `./scripts/decky-dev.sh serve` in a terminal and leave it running. It serves the ZIP on the Deck's loopback interface at `http://127.0.0.1:8765/decky-protonvpn-dev.zip`.
3. Switch to Gaming Mode. Open **... > Decky > Settings > General > Manual Plugin Install**, enter that URL, and install.
4. Open **... > Decky > Proton VPN**. Verify the active profile is shown, toggle it off and back on, then verify Stremio can connect.
5. Stop the local server with Ctrl+C after Decky has downloaded the ZIP. Rebuild and reinstall after code changes.

The server is intentionally bound to `127.0.0.1` and is only for local testing. `out/`, `dist/`, dependencies, and Python caches are ignored by Git; the test ZIP is not committed.
