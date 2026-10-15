import asyncio
import subprocess

import decky


FLATPAK = "/usr/bin/flatpak"
NMCLI = "/usr/bin/nmcli"
PROTON_APP_ID = "com.protonvpn.www"
PROTON_PROFILE_PREFIX = "protonvpn"
SUPPORTED_CONNECTION_TYPES = {"vpn", "wireguard"}


def _run_nmcli(arguments: list[str]) -> str:
    result = subprocess.run(
        [NMCLI, "--terse", "--colors", "no", *arguments],
        capture_output=True,
        check=False,
        stdin=subprocess.DEVNULL,
        text=True,
        timeout=10,
        env={"LC_ALL": "C", "PATH": "/usr/bin:/bin"},
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "NetworkManager command failed")
    return result.stdout


def _flatpak_installed() -> bool:
    try:
        result = subprocess.run(
            [FLATPAK, "info", "--system", "--show-ref", PROTON_APP_ID],
            capture_output=True,
            check=False,
            stdin=subprocess.DEVNULL,
            text=True,
            timeout=10,
            env={"LC_ALL": "C", "PATH": "/usr/bin:/bin"},
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


def _split_nmcli_fields(line: str) -> list[str]:
    fields = []
    field = []
    escaped = False
    for character in line:
        if escaped:
            field.append(character)
            escaped = False
        elif character == "\\":
            escaped = True
        elif character == ":":
            fields.append("".join(field))
            field = []
        else:
            field.append(character)
    if escaped:
        field.append("\\")
    fields.append("".join(field))
    return fields


def _proton_profiles() -> list[dict[str, str]]:
    output = _run_nmcli(["--fields", "UUID,NAME,TYPE", "connection", "show"])
    profiles = []
    for line in output.splitlines():
        fields = _split_nmcli_fields(line)
        if len(fields) != 3:
            continue
        profile_uuid, name, connection_type = fields
        if (
            name.casefold().startswith(PROTON_PROFILE_PREFIX)
            and connection_type in SUPPORTED_CONNECTION_TYPES
        ):
            profiles.append(
                {"uuid": profile_uuid, "name": name, "type": connection_type}
            )
    return profiles


def _active_uuids() -> set[str]:
    output = _run_nmcli(["--fields", "UUID", "connection", "show", "--active"])
    return {line.strip() for line in output.splitlines() if line.strip()}


def _get_connections() -> dict:
    installed = _flatpak_installed()
    if not installed:
        return {"installed": False, "connected": False, "connections": []}

    try:
        profiles = _proton_profiles()
        active = _active_uuids()
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
        return {
            "installed": True,
            "connected": False,
            "connections": [],
            "error": str(error),
        }

    connections = [
        {**profile, "active": profile["uuid"] in active} for profile in profiles
    ]
    return {
        "installed": True,
        "connected": any(connection["active"] for connection in connections),
        "connections": connections,
    }


def _toggle_connection(profile_uuid: str) -> dict:
    if not isinstance(profile_uuid, str):
        raise ValueError("Invalid Proton VPN profile")
    if not _flatpak_installed():
        raise RuntimeError("Install Proton VPN from Discover in Desktop Mode first")

    profiles = _proton_profiles()
    profile = next((item for item in profiles if item["uuid"] == profile_uuid), None)
    if profile is None:
        raise ValueError("That Proton VPN profile is not available")

    active = _active_uuids()
    if profile_uuid in active:
        _run_nmcli(["connection", "down", "uuid", profile_uuid])
    else:
        active_proton_uuids = {
            item["uuid"] for item in profiles if item["uuid"] in active
        }
        if active_proton_uuids:
            raise RuntimeError(
                "Disconnect the active Proton VPN connection before switching servers"
            )
        _run_nmcli(["connection", "up", "uuid", profile_uuid])
    return _get_connections()


class Plugin:
    async def _main(self):
        decky.logger.info("Proton VPN Decky plugin loaded")

    async def _unload(self):
        decky.logger.info("Proton VPN Decky plugin unloaded")

    async def get_connections(self) -> dict:
        return await asyncio.to_thread(_get_connections)

    async def toggle_connection(self, profile_uuid: str) -> dict:
        return await asyncio.to_thread(_toggle_connection, profile_uuid)
