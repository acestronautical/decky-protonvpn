import json
import os
import re
import subprocess
import sys
from pathlib import Path


FLATPAK = "/usr/bin/flatpak"


PROTON_APP_ID = "com.protonvpn.www"


PROTON_CLI_COMMAND = [
    FLATPAK,
    "run",
    "--command=protonvpn",
    PROTON_APP_ID,
]


CLI_TIMEOUT_SECONDS = 90
COUNTRIES: dict[str, str] = json.loads(Path(__file__).with_name("countries.json").read_text(encoding="utf-8"))
SETTING_VALUES = {
    "kill-switch": ("off", "standard"),
    "netshield": ("off", "malware-only", "malware-ads-trackers"),
    "vpn-accelerator": ("off", "on"),
    "moderate-nat": ("off", "on"),
}


def panel_snapshot() -> dict:
    try:
        result = json.loads(run_cli(["panel-snapshot"]))
        if not isinstance(result, dict) or type(result.get("signed_in")) is not bool:
            raise ValueError()
        settings = result.get("settings", {})
        if not isinstance(settings, dict) or any(name not in SETTING_VALUES or value not in (*SETTING_VALUES[name], None) for name, value in settings.items()):
            raise ValueError()
        mode = settings.get("kill-switch")
        result["kill_switch"] = mode == "standard" if mode is not None else None
        account_name = result.get("account_name")
        result["account_name"] = account_name if result["signed_in"] and isinstance(account_name, str) and re.fullmatch(r"[A-Za-z0-9._+@-]{1,254}", account_name) else None
        return {name: result[name] for name in ("signed_in", "account_name", "settings", "settings_error", "requires_upgrade", "requires_reconnect", "kill_switch") if name in result}
    except (ValueError, TypeError):
        raise RuntimeError("Proton returned an unsupported panel snapshot") from None


def connection_status() -> dict:
    unknown = {"connected": None, "tunnel_active": None, "server": "", "protocol": "", "error": "NetworkManager connection state is unavailable"}
    try:
        result = subprocess.run(
            ["/usr/bin/nmcli", "-t", "-f", "TYPE,DEVICE,STATE,NAME", "connection", "show", "--active"],
            capture_output=True, check=False, stdin=subprocess.DEVNULL, text=True,
            timeout=5, env=cli_environment(), start_new_session=True,
        )
        if result.returncode != 0:
            return unknown
        for line in result.stdout.splitlines():
            fields = line.split(":", 3)
            if len(fields) != 4 or fields[:2] != ["wireguard", "proton0"]:
                continue
            if fields[2] != "activated":
                return unknown
            server = re.search(r"\b[A-Z]{2}(?:-[A-Z0-9]+)?#\d+\b", fields[3])
            return {"connected": True, "tunnel_active": True, "server": server.group() if server else "", "protocol": "WireGuard"}
        return {"connected": False, "tunnel_active": False, "server": "", "protocol": ""}
    except (OSError, subprocess.SubprocessError, UnicodeError):
        return unknown


def cli_environment() -> dict[str, str]:
    environment = os.environ.copy()
    if getattr(sys, "frozen", False):
        original_library_path = environment.pop("LD_LIBRARY_PATH_ORIG", None)
        if original_library_path:
            environment["LD_LIBRARY_PATH"] = original_library_path
        else:
            environment.pop("LD_LIBRARY_PATH", None)
    environment["LC_ALL"] = "C"
    runtime_dir = environment.setdefault("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}")
    environment.setdefault(
        "DBUS_SESSION_BUS_ADDRESS", f"unix:path={runtime_dir}/bus"
    )
    return environment


def command_failure_category(output: str) -> str:
    output = output.casefold()
    if any(message in output for message in (
        "symbol lookup error", "error while loading shared libraries", "version `",
    )):
        return "shared-library error"
    if any(message in output for message in ("keyring", "secretstorage", "secretservice", "secret service", "org.freedesktop.secrets")):
        if any(message in output for message in ("keyringlocked", "lockedexception", "collection is locked", "keyring is locked")):
            return "keyring locked"
        if "dismissed" in output:
            return "keyring unlock dismissed"
        if "nokeyringerror" in output or "no recommended backend" in output:
            return "keyring backend unavailable"
        if "secretservicenotavailableexception" in output or "serviceunknown" in output:
            return "Secret Service unavailable"
        return "keyring error"
    if "networkmanager" in output or "org.freedesktop.networkmanager" in output:
        return "NetworkManager error"
    if "permission denied" in output or "operation not permitted" in output:
        return "permission denied"
    if "d-bus" in output or "dbus" in output:
        return "D-Bus error"
    if "unknown option" in output or "no such option" in output:
        return "unsupported option"
    if "no such command" in output or "unknown action" in output:
        return "unsupported command"
    return "unclassified error"


class CLICommandError(RuntimeError):
    def __init__(self, message: str, category: str, identifiers: str = "not reported"):
        super().__init__(message)
        self.category = category
        self.identifiers = identifiers


def cli_command(arguments: list[str]) -> list[str]:
    launcher = Path(__file__).with_name("cli_compat.py").read_text(encoding="utf-8")
    return [FLATPAK, "run", "--command=python3", PROTON_APP_ID, "-c", launcher, *arguments]


def run_cli(arguments: list[str]) -> str:
    operation = {
        "info": "account check",
        "status": "connection status",
        "panel-snapshot": "account and settings",
        "countries": "country list",
        "connect": "connection",
        "disconnect": "disconnection",
        "signout": "sign-out",
        "config": "configuration",
    }.get(arguments[0] if arguments else "", "command")
    try:
        environment = cli_environment()
        command = cli_command(arguments)
        if arguments and (arguments[0] in ("connect", "disconnect", "signout") or arguments[:2] == ["config", "set"]):
            runtime_dir = f"/run/user/{os.getuid()}"
            bus_address = f"unix:path={runtime_dir}/bus"
            if os.getuid() == 0:
                raise RuntimeError("VPN controls must run as the Deck user, not root")
            if environment.get("XDG_RUNTIME_DIR") != runtime_dir or environment.get("DBUS_SESSION_BUS_ADDRESS") != bus_address:
                raise RuntimeError("VPN controls require the standard user bus; no operation was started")
            command = [
                "/usr/bin/systemd-run", "--user", "--wait", "--pipe", "--collect", "--quiet",
                "--unit=decky-protonvpn-network", "--expand-environment=no",
                "--property=Type=exec", "--property=Restart=no",
                f"--property=RuntimeMaxSec={CLI_TIMEOUT_SECONDS - 5}s",
                "--property=TimeoutStopSec=3s", "--property=KillMode=control-group",
                "--property=UnsetEnvironment=LD_LIBRARY_PATH LD_PRELOAD",
                "--setenv=LC_ALL=C", f"--setenv=XDG_RUNTIME_DIR={runtime_dir}",
                f"--setenv=DBUS_SESSION_BUS_ADDRESS={bus_address}",
                "--", *command,
            ]
        result = subprocess.run(
            command,
            capture_output=True,
            check=False,
            stdin=subprocess.DEVNULL,
            text=True,
            timeout=CLI_TIMEOUT_SECONDS,
            env=environment,
            start_new_session=True,
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"Proton VPN {operation} timed out; refresh status before retrying") from None
    except (OSError, subprocess.SubprocessError, UnicodeError):
        raise RuntimeError("Proton VPN CLI is unavailable") from None
    if result.returncode != 0:
        message = f"{result.stderr}\n{result.stdout}".strip()
        lowered = message.casefold()
        if "desktop app is currently running" in lowered or "cannot run alongside" in lowered:
            raise RuntimeError(
                "Close the Proton VPN desktop app before using the Decky CLI controls"
            )
        if "authentication required" in lowered or "please sign in" in lowered:
            raise RuntimeError("Proton CLI is signed out; sign in first")
        if "disconnect before changing kill switch" in lowered:
            raise RuntimeError("Disconnect the VPN before changing the kill switch")
        if "not available on your current subscription plan" in lowered:
            raise RuntimeError("This setting requires Proton VPN Plus")
        category = command_failure_category(message)
        identifiers = ", ".join(identifier for identifier in (
            "InitError", "KeyringLocked", "KeyringError", "NoKeyringError",
            "LockedException", "PromptDismissedException", "ItemNotFoundException",
            "SecretServiceNotAvailableException", "ServiceUnknown", "NoReply", "AccessDenied",
        ) if re.search(rf"\b{identifier}\b", message)) or "not reported"
        raise CLICommandError(
            f"Proton VPN {operation} failed: {category} (exit {result.returncode})",
            category,
            identifiers,
        )
    return result.stdout.strip()


def flatpak_installed() -> bool:
    try:
        result = subprocess.run(
            [FLATPAK, "list", "--app", "--columns=application"],
            capture_output=True,
            check=False,
            stdin=subprocess.DEVNULL,
            text=True,
            timeout=10,
            env=cli_environment(),
        )
    except FileNotFoundError:
        raise RuntimeError("Flatpak is unavailable to Decky; check the plugin's runtime environment") from None
    except subprocess.TimeoutExpired:
        raise RuntimeError("Flatpak installation check timed out; refresh status") from None
    except (OSError, UnicodeError):
        raise RuntimeError("Decky could not run Flatpak; check user permissions") from None
    if result.returncode != 0:
        output = f"{result.stderr}\n{result.stdout}".casefold()
        category = command_failure_category(output)
        raise RuntimeError(f"Flatpak installation check failed: {category} (exit {result.returncode})")
    return PROTON_APP_ID in {line.strip() for line in result.stdout.splitlines()}


def install_flatpak(report_progress) -> None:
    if os.getuid() == 0:
        raise RuntimeError("Install Proton VPN as the Deck user, not root")
    report_progress("checking")
    if flatpak_installed():
        return

    def command(arguments: list[str], timeout: int = 60) -> str:
        try:
            result = subprocess.run(
                [FLATPAK, *arguments], capture_output=True, check=False,
                stdin=subprocess.DEVNULL, text=True, timeout=timeout,
                env=cli_environment(), start_new_session=True,
            )
        except subprocess.TimeoutExpired:
            raise RuntimeError("Flatpak installation timed out; check installation status before retrying") from None
        except (OSError, subprocess.SubprocessError, UnicodeError):
            raise RuntimeError("Flatpak installation could not run") from None
        if result.returncode != 0:
            raise RuntimeError(f"Flatpak installation failed (exit {result.returncode}); check connectivity and free disk space")
        return result.stdout

    def trusted_remote() -> bool:
        output = command(["remotes", "--user", "--columns=name,url,options"])
        for line in output.splitlines():
            fields = line.split("\t")
            if fields[0] != "flathub":
                continue
            if len(fields) < 2 or fields[1] not in ("https://dl.flathub.org/repo/", "https://flathub.org/repo/") or any("no-gpg-verify" in field for field in fields[2:]):
                raise RuntimeError("The user Flathub repository is not trusted; check it in Desktop Mode")
            return True
        return False

    report_progress("repository")
    if not trusted_remote():
        command(["remote-add", "--user", "--if-not-exists", "flathub", "https://dl.flathub.org/repo/flathub.flatpakrepo"])
        if not trusted_remote():
            raise RuntimeError("The user Flathub repository could not be verified")
    report_progress("installing")
    command(["install", "--user", "--noninteractive", "--assumeyes", "flathub", f"{PROTON_APP_ID}//stable"], timeout=1800)
    report_progress("verifying")
    if not flatpak_installed():
        raise RuntimeError("Flatpak finished but Proton VPN installation could not be verified")


def tunnel_active() -> bool | None:
    try:
        result = subprocess.run(
            ["/usr/bin/nmcli", "-t", "-f", "TYPE,DEVICE", "connection", "show", "--active"],
            capture_output=True, check=False, stdin=subprocess.DEVNULL, text=True,
            timeout=5, env=cli_environment(), start_new_session=True,
        )
    except (OSError, subprocess.SubprocessError, UnicodeError):
        return None
    if result.returncode != 0:
        return None
    return "wireguard:proton0" in result.stdout.splitlines()


def signed_in() -> bool:
    output = run_cli(["info"])
    account_line = next(
        (line for line in output.splitlines() if line.startswith("Account:")),
        "",
    )
    account = account_line.partition(":")[2].strip().strip("'\"")
    return bool(account and account.casefold() != "none")


def parse_status(output: str) -> dict[str, str | bool]:
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


def parse_countries(output: str) -> list[dict[str, str]]:
    countries = []
    for line in output.splitlines():
        match = re.match(r"^\s*(.+?)\s{2,}([A-Z]{2})\s*$", line)
        if not match:
            continue
        name, country_code = match.groups()
        if name.casefold() != "country":
            countries.append({"name": name.strip(), "code": country_code})
    return countries
