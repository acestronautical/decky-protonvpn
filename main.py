import asyncio
import os
import re
import subprocess

import decky


FLATPAK = "/usr/bin/flatpak"
PROTON_APP_ID = "com.protonvpn.www"
PROTON_CLI_COMMAND = [
    FLATPAK,
    "run",
    "--command=protonvpn",
    PROTON_APP_ID,
]
CLI_TIMEOUT_SECONDS = 90


def _cli_environment() -> dict[str, str]:
    environment = os.environ.copy()
    environment["LC_ALL"] = "C"
    runtime_dir = environment.setdefault("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}")
    environment.setdefault(
        "DBUS_SESSION_BUS_ADDRESS", f"unix:path={runtime_dir}/bus"
    )
    return environment


def _run_cli(arguments: list[str]) -> str:
    result = subprocess.run(
        [*PROTON_CLI_COMMAND, *arguments],
        capture_output=True,
        check=False,
        stdin=subprocess.DEVNULL,
        text=True,
        timeout=CLI_TIMEOUT_SECONDS,
        env=_cli_environment(),
    )
    if result.returncode != 0:
        message = (result.stderr or result.stdout).strip()
        lowered = message.casefold()
        if "desktop app is currently running" in lowered or "cannot run alongside" in lowered:
            raise RuntimeError(
                "Close the Proton VPN desktop app before using the Decky CLI controls"
            )
        if "authentication required" in lowered or "please sign in" in lowered:
            raise RuntimeError("Proton CLI is signed out; sign in from Desktop Mode first")
        raise RuntimeError(message or "Proton VPN CLI command failed")
    return result.stdout.strip()


def _flatpak_installed() -> bool:
    try:
        result = subprocess.run(
            [FLATPAK, "info", "--show-ref", PROTON_APP_ID],
            capture_output=True,
            check=False,
            stdin=subprocess.DEVNULL,
            text=True,
            timeout=10,
            env=_cli_environment(),
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


def _signed_in() -> bool:
    output = _run_cli(["info"])
    account_line = next(
        (line for line in output.splitlines() if line.startswith("Account:")),
        "",
    )
    account = account_line.partition(":")[2].strip().strip("'\"")
    return bool(account and account.casefold() != "none")


def _parse_status(output: str) -> dict[str, str | bool]:
    values: dict[str, str | bool] = {
        "connected": False,
        "server": "",
        "protocol": "",
    }
    for line in output.splitlines():
        label, separator, value = line.partition(":")
        if not separator:
            continue
        key = label.strip().casefold()
        value = value.strip()
        if key == "status":
            values["connected"] = value.casefold() == "connected"
        elif key == "server":
            values["server"] = value
        elif key == "protocol":
            values["protocol"] = value
    return values


def _get_status() -> dict:
    if not _flatpak_installed():
        return {"installed": False, "signed_in": False, "connected": False}
    try:
        signed_in = _signed_in()
        if not signed_in:
            return {
                "installed": True,
                "signed_in": False,
                "connected": False,
                "server": "",
                "protocol": "",
            }
        status = _parse_status(_run_cli(["status"]))
        return {"installed": True, "signed_in": signed_in, **status}
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
        return {
            "installed": True,
            "signed_in": False,
            "connected": False,
            "server": "",
            "protocol": "",
            "error": str(error),
        }


def _parse_countries(output: str) -> list[dict[str, str]]:
    countries = []
    for line in output.splitlines():
        match = re.match(r"^\s*(.+?)\s{2,}([A-Z]{2})\s*$", line)
        if not match:
            continue
        name, country_code = match.groups()
        if name.casefold() != "country":
            countries.append({"name": name.strip(), "code": country_code})
    return countries


def _get_countries() -> dict:
    if not _flatpak_installed():
        return {"signed_in": False, "countries": []}
    try:
        if not _signed_in():
            return {"signed_in": False, "countries": []}
        return {
            "signed_in": True,
            "countries": _parse_countries(_run_cli(["countries", "list"])),
        }
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
        return {"signed_in": False, "countries": [], "error": str(error)}


def _connect_country(country_code: str) -> dict:
    if not isinstance(country_code, str) or not re.fullmatch(r"[A-Z]{2}", country_code):
        raise ValueError("Choose a valid Proton VPN country")
    country_data = _get_countries()
    if country_data.get("error"):
        raise RuntimeError(country_data["error"])
    if not country_data["signed_in"]:
        raise RuntimeError("Sign in to the Proton VPN CLI from Desktop Mode first")
    if country_code not in {country["code"] for country in country_data["countries"]}:
        raise ValueError("That country is not in Proton VPN's available country list")
    _run_cli(["connect", "--country", country_code])
    return _get_status()


def _disconnect() -> dict:
    if not _flatpak_installed():
        raise RuntimeError("Proton VPN is not installed")
    if not _signed_in():
        raise RuntimeError("Sign in to the Proton VPN CLI from Desktop Mode first")
    _run_cli(["disconnect"])
    return _get_status()


class Plugin:
    async def _main(self):
        decky.logger.info("Proton VPN Decky plugin loaded")

    async def _unload(self):
        decky.logger.info("Proton VPN Decky plugin unloaded")

    async def get_status(self) -> dict:
        return await asyncio.to_thread(_get_status)

    async def get_countries(self) -> dict:
        return await asyncio.to_thread(_get_countries)

    async def connect_country(self, country_code: str) -> dict:
        return await asyncio.to_thread(_connect_country, country_code)

    async def disconnect(self) -> dict:
        return await asyncio.to_thread(_disconnect)
