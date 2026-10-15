import os
import re
import subprocess
import sys


FLATPAK = "/usr/bin/flatpak"


PROTON_APP_ID = "com.protonvpn.www"


PROTON_CLI_COMMAND = [
    FLATPAK,
    "run",
    "--command=protonvpn",
    PROTON_APP_ID,
]


CLI_TIMEOUT_SECONDS = 90


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


def run_cli(arguments: list[str]) -> str:
    operation = {
        "info": "account check",
        "status": "connection status",
        "countries": "country list",
        "connect": "connection",
        "disconnect": "disconnection",
    }.get(arguments[0] if arguments else "", "command")
    try:
        result = subprocess.run(
            [*PROTON_CLI_COMMAND, *arguments],
            capture_output=True,
            check=False,
            stdin=subprocess.DEVNULL,
            text=True,
            timeout=CLI_TIMEOUT_SECONDS,
            env=cli_environment(),
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
