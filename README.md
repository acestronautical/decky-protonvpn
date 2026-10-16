# Proton VPN for Decky (Unofficial)

Control Proton VPN from Steam Deck Gaming Mode. Independent community project; not affiliated with, sponsored by, or endorsed by Proton AG. Proton VPN is a trademark of Proton AG.

**Experimental prerelease.** Reboot/session-transition reliability, live first-install testing, and comprehensive IPv6/DNS leak testing remain outstanding.

## Install

Requires a Steam Deck with Decky Loader and a compatible Proton VPN Flatpak CLI.

1. Download the plugin ZIP from [GitHub Releases](https://github.com/acestronautical/decky-protonvpn/releases), not the source archives.
2. In Decky settings, select **Manual Plugin Install > Load from ZIP file**.
3. Open **Proton VPN (Unofficial) > Account**. If Proton VPN is missing, select **Install Proton VPN** and confirm, or install it through Discover in Desktop Mode.
4. Close Proton's desktop app before signing in or using the plugin; its GUI and CLI cannot run together.

## Use

Switch tabs with **L1/R1**:

- **Connection:** Quick connect, choose a country, switch servers, or disconnect. Viewing this tab uses NetworkManager only, with no Proton CLI or account queries.
- **Settings:** Kill switch, NetShield, VPN Accelerator, and Moderate NAT. Disconnect before changing the kill switch. Paid-plan features require the appropriate Proton subscription.
- **Account:** Sign in with your username, password, and 2FA/recovery code if required; view your authenticated username or sign out. Sign-out requires confirmation and disconnects first.

Only your username is remembered by the plugin. Passwords and codes are never cached; Proton manages its saved session through the system keyring.

## :warning: Disclaimer :warning:

Using a VPN to access Steam is **against their terms of service** While it's unlikely that you will be banned, I at least recommend avoiding purchasing games while connected to the VPN.


## Troubleshooting and Safety

- After a timeout or interrupted action, reopen Account or use **Retry** to check status before repeating the action.
- Keyring errors may require unlocking your wallet in Desktop Mode. Compatibility checks can block unsupported Proton versions; the plugin does not bypass them or repair account records automatically.
- For unsupported sign-in challenges, use Desktop Mode: `flatpak run --command=protonvpn com.protonvpn.www signin <username>`. Enter passwords and codes only at the prompts.
- Report the displayed error and software versions in [Issues](https://github.com/acestronautical/decky-protonvpn/issues), not credentials or raw account logs.
- An active tunnel is not proof of leak protection. Encrypted sign-in transport does not protect against a compromised Deck or malicious plugins.

## Development

Requires Node.js 18+, pnpm 9, Python 3.10+, and OpenSSL. Tests use dummy credentials and do not contact Proton.

```sh
./scripts/decky-dev.sh install
./scripts/decky-dev.sh test
pnpm exec tsc --noEmit --skipLibCheck
./scripts/decky-dev.sh package
```

The package command builds the frontend and writes the installable ZIP under `out/`.

## License

[BSD-3-Clause](LICENSE), with Steam Deck Homebrew attribution retained. Third-party software and artwork retain their respective rights; no trademark rights are granted. See [NOTICE.md](NOTICE.md).