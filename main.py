import asyncio
import base64
import json
import os
import re
import subprocess
import sys
import tempfile
import threading
import time
import uuid

import decky


FLATPAK = "/usr/bin/flatpak"
BUSCTL = "/usr/bin/busctl"
PROTON_APP_ID = "com.protonvpn.www"
PROTON_CLI_COMMAND = [
    FLATPAK,
    "run",
    "--command=protonvpn",
    PROTON_APP_ID,
]
CLI_TIMEOUT_SECONDS = 90
SIGNIN_TIMEOUT_SECONDS = 180
SIGNIN_SESSION_TTL_SECONDS = 300
SIGNIN_SESSIONS: dict[str, tuple[bytearray, float]] = {}
SIGNIN_SESSIONS_LOCK = threading.Lock()
CLI_OPERATION_LOCK = threading.Lock()

KEYRING_PROBE_CODE = """
import json
from contextlib import closing
from importlib import metadata

report = {}
try:
    entries = metadata.entry_points(group="proton_loader_keyring")
    report["drivers"] = sorted({entry.name if entry.name in ("secret_service", "libsecret", "json") else "other" for entry in entries})
    for field, package in (("cli_version", "proton-vpn-cli"), ("keyring_version", "proton-keyring-linux")):
        try:
            report[field] = metadata.version(package)
        except metadata.PackageNotFoundError:
            pass
except Exception:
    pass
try:
    import secretstorage
    from jeepney.bus_messages import message_bus
    from jeepney.io.blocking import Proxy
except ImportError:
    report["probe"] = "dependencies missing"
else:
    try:
        connection = secretstorage.dbus_init()
    except Exception:
        report["bus"] = "unreachable"
    else:
        report["bus"] = "reachable"
        with closing(connection):
            try:
                bus = Proxy(message_bus, connection)
                names = set(bus.ListNames()[0])
                if "org.freedesktop.secrets" not in names:
                    available = bus.ListActivatableNames()[0]
                    report["service"] = "inactive" if "org.freedesktop.secrets" in available else "absent"
                else:
                    report["service"] = "running"
                    report["provider"] = "other"
                    owner = bus.GetNameOwner("org.freedesktop.secrets")[0]
                    for name, provider in (
                        ("org.kde.kwalletd6", "KWallet"),
                        ("org.kde.kwalletd5", "KWallet"),
                        ("org.gnome.keyring", "GNOME Keyring"),
                    ):
                        if name in names and bus.GetNameOwner(name)[0] == owner:
                            report["provider"] = provider
                            break
                    try:
                        collection = secretstorage.Collection(connection)
                        report["collection"] = "locked" if collection.is_locked() else "unlocked"
                    except secretstorage.ItemNotFoundException:
                        report["collection"] = "missing"
                    except secretstorage.SecretServiceNotAvailableException:
                        report["collection"] = "unavailable"
                    except Exception:
                        report["collection"] = "check failed"
            except Exception:
                report["service"] = "check failed"
print(json.dumps(report))
"""


def _clear_signin_sessions(expired_only: bool = False) -> None:
    with SIGNIN_SESSIONS_LOCK:
        now = time.monotonic()
        for session_id, (private_key, expires_at) in list(SIGNIN_SESSIONS.items()):
            if not expired_only or expires_at <= now:
                SIGNIN_SESSIONS.pop(session_id)
                private_key[:] = b"\0" * len(private_key)


def _cancel_signin(session_id: str) -> None:
    if not isinstance(session_id, str):
        return
    with SIGNIN_SESSIONS_LOCK:
        session = SIGNIN_SESSIONS.pop(session_id, None)
        if session is not None:
            session[0][:] = b"\0" * len(session[0])


def _cli_operation(operation, *arguments):
    if not CLI_OPERATION_LOCK.acquire(blocking=False):
        raise RuntimeError("A Proton VPN operation is in progress; try again shortly")
    try:
        return operation(*arguments)
    finally:
        CLI_OPERATION_LOCK.release()


def _signin_result(operation, *arguments) -> dict:
    try:
        return operation(*arguments)
    except (ValueError, RuntimeError) as error:
        return {"error": str(error)}


def _generate_signin_keypair() -> tuple[bytearray, str]:
    private_result = subprocess.run(
        [
            "/usr/bin/openssl",
            "genpkey",
            "-algorithm",
            "RSA",
            "-pkeyopt",
            "rsa_keygen_bits:4096",
        ],
        capture_output=True,
        check=False,
        stdin=subprocess.DEVNULL,
        timeout=30,
        env=_cli_environment(),
    )
    if private_result.returncode != 0:
        raise RuntimeError("Could not start a secure sign-in session")

    public_result = subprocess.run(
        ["/usr/bin/openssl", "pkey", "-pubout"],
        capture_output=True,
        check=False,
        input=private_result.stdout,
        timeout=10,
        env=_cli_environment(),
    )
    if public_result.returncode != 0:
        raise RuntimeError("Could not start a secure sign-in session")
    return bytearray(private_result.stdout), public_result.stdout.decode("ascii")


def _begin_signin() -> dict[str, str]:
    if not _flatpak_installed():
        raise RuntimeError("Install Proton VPN from Discover in Desktop Mode first")

    if not SIGNIN_SESSIONS_LOCK.acquire(blocking=False):
        raise RuntimeError("A sign-in is already in progress; try again shortly")
    try:
        now = time.monotonic()
        expired = [
            key
            for key, (_, expires_at) in SIGNIN_SESSIONS.items()
            if expires_at <= now
        ]
        for key in expired:
            old_key, _ = SIGNIN_SESSIONS.pop(key)
            old_key[:] = b"\0" * len(old_key)
        if len(SIGNIN_SESSIONS) >= 4:
            raise RuntimeError("A sign-in is already in progress; try again shortly")
        try:
            private_key, public_key = _generate_signin_keypair()
        except (OSError, subprocess.SubprocessError, UnicodeError):
            raise RuntimeError("Could not start a secure sign-in session") from None
        session_id = uuid.uuid4().hex
        SIGNIN_SESSIONS[session_id] = (
            private_key,
            time.monotonic() + SIGNIN_SESSION_TTL_SECONDS,
        )
    finally:
        SIGNIN_SESSIONS_LOCK.release()
    return {"session_id": session_id, "public_key": public_key}


def _decrypt_signin_payload(private_key: bytearray, ciphertext: str) -> dict[str, str]:
    if not isinstance(ciphertext, str) or len(ciphertext) != 684:
        raise ValueError("Invalid sign-in request")
    try:
        encrypted = base64.b64decode(ciphertext, validate=True)
    except (ValueError, base64.binascii.Error) as error:
        raise ValueError("Invalid sign-in request") from error
    if len(encrypted) != 512:
        raise ValueError("Invalid sign-in request")

    try:
        with tempfile.TemporaryFile(
            mode="wb", prefix="decky-protonvpn-", dir="/dev/shm"
        ) as key_file:
            key_file.write(private_key)
            key_file.flush()
            key_file.seek(0)
            result = subprocess.run(
                [
                    "/usr/bin/openssl",
                    "pkeyutl",
                    "-decrypt",
                    "-inkey",
                    f"/dev/fd/{key_file.fileno()}",
                    "-pkeyopt",
                    "rsa_padding_mode:oaep",
                    "-pkeyopt",
                    "rsa_oaep_md:sha256",
                    "-pkeyopt",
                    "rsa_mgf1_md:sha256",
                ],
                input=encrypted,
                capture_output=True,
                check=False,
                timeout=10,
                pass_fds=(key_file.fileno(),),
                env=_cli_environment(),
            )
    except (OSError, subprocess.SubprocessError):
        raise RuntimeError("Secure sign-in could not be completed") from None
    if result.returncode != 0 or len(result.stdout) > 446:
        raise ValueError("Invalid sign-in request")
    try:
        payload = json.loads(result.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError("Invalid sign-in request") from None
    if not isinstance(payload, dict) or set(payload) != {"username", "password", "totp"}:
        raise ValueError("Invalid sign-in request")
    return payload


def _run_cli_signin(credentials: dict[str, str]) -> dict:
    username = credentials.get("username", "")
    password = credentials.get("password", "")
    totp = credentials.get("totp", "")
    if (
        not isinstance(username, str)
        or not re.fullmatch(r"[A-Za-z0-9._+@-]{1,254}", username)
        or not isinstance(password, str)
        or not password
        or any(character in password for character in "\0\n\r")
        or not isinstance(totp, str)
        or any(character in totp for character in "\0\n\r")
    ):
        raise ValueError("Enter a valid Proton username and password")

    try:
        result = subprocess.run(
            [*PROTON_CLI_COMMAND, "signin", "--totp", "--", username],
            input=f"{password}\n{totp}\n",
            capture_output=True,
            check=False,
            text=True,
            timeout=SIGNIN_TIMEOUT_SECONDS,
            env=_cli_environment(),
            start_new_session=True,
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError("Proton CLI sign-in timed out; refresh status before retrying") from None
    except (OSError, subprocess.SubprocessError, UnicodeError):
        raise RuntimeError("Proton CLI sign-in could not be started") from None

    output = f"{result.stdout}\n{result.stderr}".casefold()
    if result.returncode != 0:
        if "desktop app is currently running" in output or "cannot run alongside" in output:
            raise RuntimeError("Close the Proton VPN desktop app before signing in here")
        if "already signed in" in output:
            raise RuntimeError("Proton CLI is already signed in; refresh status")
        if "authentication failed" in output or "invalid two-factor" in output:
            raise RuntimeError("Proton rejected the sign-in; check the credentials and 2FA code")
        if "2fa token" in output or "two-factor" in output:
            raise RuntimeError("Proton sign-in needs a valid authenticator or recovery code")
        if "no such option" in output and "--totp" in output:
            raise RuntimeError("Update Proton VPN in Discover or sign in from Desktop Mode")
        raise RuntimeError("Proton CLI sign-in failed; finish sign-in in Desktop Mode")
    status = _get_status()
    if status.get("error"):
        status["error"] = "Proton CLI completed sign-in, but verification failed. " + status["error"]
    return status


def _complete_signin(session_id: str, ciphertext: str) -> dict:
    if not isinstance(session_id, str):
        raise ValueError("Sign-in session expired; try again")
    with SIGNIN_SESSIONS_LOCK:
        session = SIGNIN_SESSIONS.pop(session_id, None)
    if session is None:
        raise ValueError("Sign-in session expired; try again")

    private_key = session[0]
    credentials = None
    try:
        if session[1] <= time.monotonic():
            raise ValueError("Sign-in session expired; try again")
        credentials = _decrypt_signin_payload(private_key, ciphertext)
        return _run_cli_signin(credentials)
    finally:
        if credentials is not None:
            credentials.clear()
        private_key[:] = b"\0" * len(private_key)


def _cli_environment() -> dict[str, str]:
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


def _command_failure_category(output: str) -> str:
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


def _probe_keyring(environment: dict[str, str]) -> dict[str, str]:
    try:
        result = subprocess.run(
            [FLATPAK, "run", "--command=python3", PROTON_APP_ID, "-c", KEYRING_PROBE_CODE],
            capture_output=True,
            check=False,
            stdin=subprocess.DEVNULL,
            text=True,
            timeout=10,
            env=environment,
            start_new_session=True,
        )
        if result.returncode != 0:
            return {"probe": "unavailable"}
        report = json.loads(result.stdout)
    except subprocess.TimeoutExpired:
        return {"probe": "timed out"}
    except (OSError, subprocess.SubprocessError, UnicodeError, ValueError):
        return {"probe": "unavailable"}
    if not isinstance(report, dict):
        return {"probe": "unavailable"}
    allowed = {
        "probe": ("dependencies missing",),
        "bus": ("reachable", "unreachable"),
        "service": ("running", "inactive", "absent", "check failed"),
        "provider": ("KWallet", "GNOME Keyring", "other"),
        "collection": ("locked", "unlocked", "missing", "unavailable", "check failed"),
    }
    filtered = {key: value for key, value in report.items() if key in allowed and value in allowed[key]}
    drivers = report.get("drivers")
    if isinstance(drivers, list) and all(driver in ("secret_service", "libsecret", "json", "other") for driver in drivers):
        filtered["drivers"] = ", ".join(sorted(set(drivers))) or "none"
    for field in ("cli_version", "keyring_version"):
        version = report.get(field)
        if isinstance(version, str) and len(version) <= 32 and re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,3}", version):
            filtered[field] = version
    return filtered or {"probe": "unavailable"}


def _keyring_diagnostics() -> dict[str, str]:
    environment = _cli_environment()
    runtime_dir = f"/run/user/{os.getuid()}"
    bus_address = f"unix:path={runtime_dir}/bus"
    canonical = dict(environment, XDG_RUNTIME_DIR=runtime_dir, DBUS_SESSION_BUS_ADDRESS=bus_address)
    same_bus = all(environment.get(key) == canonical[key] for key in ("XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS"))
    report = {
        "User": "root" if os.getuid() == 0 else "non-root",
        "User bus environment": "standard" if same_bus else "nonstandard",
        "Display environment": "present" if environment.get("DISPLAY") or environment.get("WAYLAND_DISPLAY") else "absent",
        "Proton loader override": "set" if environment.get("PROTON_LOADER_OVERRIDES") else "unset",
        "Snap environment": "present" if "SNAP" in environment else "absent",
    }
    labels = {
        "probe": "Probe", "bus": "Session bus", "service": "Secret Service",
        "provider": "Service provider", "collection": "Default collection",
        "drivers": "Registered Proton drivers", "cli_version": "CLI version",
        "keyring_version": "Proton keyring version",
    }
    report.update({labels[key]: value for key, value in _probe_keyring(environment).items()})
    if not same_bus:
        report.update({f"Standard bus: {labels[key]}": value for key, value in _probe_keyring(canonical).items()})
    report.update(_host_keyring_diagnostics())
    return report


def _user_bus_call(method: str, service: str | None = None) -> set[str]:
    if method not in ("ListNames", "ListActivatableNames", "StartServiceByName"):
        raise ValueError("Unsupported user-bus operation")
    command = [
        BUSCTL, "--user", "--timeout=5", "--json=short", "call",
        "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", method,
    ]
    if method == "StartServiceByName":
        if service not in (
            "org.freedesktop.secrets", "org.kde.secretservicecompat",
            "org.kde.kwalletd6", "org.kde.kwalletd5", "org.gnome.keyring",
        ):
            raise ValueError("Unsupported keyring service")
        command.extend(["su", service, "0"])
    try:
        result = subprocess.run(
            command, capture_output=True, check=False, stdin=subprocess.DEVNULL,
            text=True, timeout=6, env=_cli_environment(), start_new_session=True,
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError("User-session keyring service check or activation timed out") from None
    except (OSError, subprocess.SubprocessError, UnicodeError):
        raise RuntimeError("User-session D-Bus tool is unavailable") from None
    if result.returncode != 0:
        output = f"{result.stderr}\n{result.stdout}".casefold()
        category = next((label for marker, label in (
            ("serviceunknown", "service not registered"),
            ("accessdenied", "access denied"),
            ("permission denied", "access denied"),
            ("noreply", "service did not respond"),
            ("timed out", "service timed out"),
            ("childexited", "service exited during startup"),
            ("exited with", "service exited during startup"),
            ("display", "display unavailable"),
        ) if marker in output), "service operation failed")
        raise RuntimeError(f"User-session keyring service: {category} (exit {result.returncode})")
    try:
        response = json.loads(result.stdout)
        if not isinstance(response, dict):
            raise ValueError()
        data = response.get("data")
        if not isinstance(data, list) or len(data) != 1:
            raise ValueError()
        if method == "StartServiceByName":
            if response.get("type") != "u" or type(data[0]) is not int or data[0] not in (1, 2):
                raise ValueError()
            return set()
        if response.get("type") != "as" or not isinstance(data[0], list) or not all(isinstance(name, str) for name in data[0]):
            raise ValueError()
        return set(data[0])
    except (ValueError, TypeError):
        raise RuntimeError("User-session D-Bus returned an invalid response") from None


def _select_keyring_service(names: set[str]) -> str | None:
    if "org.freedesktop.secrets" in names:
        return "org.freedesktop.secrets"
    kde_service = next((name for name in (
        "org.kde.secretservicecompat", "org.kde.kwalletd6", "org.kde.kwalletd5",
    ) if name in names), None)
    gnome_service = "org.gnome.keyring" if "org.gnome.keyring" in names else None
    if kde_service and gnome_service:
        raise RuntimeError("Multiple keyring providers are available; select the existing provider in Desktop Mode")
    return kde_service or gnome_service


def _host_keyring_diagnostics() -> dict[str, str]:
    try:
        names = _user_bus_call("ListNames")
        if "org.freedesktop.secrets" in names:
            return {"Host Secret Service": "running", "Keyring service activation": "not needed"}
        available = _user_bus_call("ListActivatableNames")
        service = _select_keyring_service(available)
        provider = {
            "org.freedesktop.secrets": "Secret Service",
            "org.kde.secretservicecompat": "KDE Secret Service",
            "org.kde.kwalletd6": "KWallet 6",
            "org.kde.kwalletd5": "KWallet 5",
            "org.gnome.keyring": "GNOME Keyring",
        }.get(service, "none")
        return {
            "Host Secret Service": "absent",
            "Activatable host provider": provider,
            "Keyring service activation": "available" if service and os.getuid() != 0 else "unavailable",
        }
    except RuntimeError as error:
        return {"Host keyring check": str(error), "Keyring service activation": "unavailable"}


def _start_keyring_service() -> dict:
    if os.getuid() == 0:
        return {"installed": None, "signed_in": None, "connected": None, "error": "Keyring activation must run as the Deck user, not root"}
    failure = None
    try:
        names = _user_bus_call("ListNames")
        if "org.freedesktop.secrets" not in names:
            service = _select_keyring_service(_user_bus_call("ListActivatableNames"))
            if service is None:
                raise RuntimeError("No existing keyring provider is registered on the user bus; Desktop Mode keyring setup is required")
            _user_bus_call("StartServiceByName", service)
    except RuntimeError as error:
        failure = str(error)
    result = _get_status()
    if failure:
        result["error"] = failure
        result.setdefault("diagnostics", {})["Service activation result"] = "failed"
    elif result.get("error"):
        result.setdefault("diagnostics", {})["Service activation result"] = "request accepted; Proton verification failed"
    return result


class _CLICommandError(RuntimeError):
    def __init__(self, message: str, category: str, identifiers: str = "not reported"):
        super().__init__(message)
        self.category = category
        self.identifiers = identifiers


def _run_cli(arguments: list[str]) -> str:
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
            env=_cli_environment(),
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
        category = _command_failure_category(message)
        identifiers = ", ".join(identifier for identifier in (
            "InitError", "KeyringLocked", "KeyringError", "NoKeyringError",
            "LockedException", "PromptDismissedException", "ItemNotFoundException",
            "SecretServiceNotAvailableException", "ServiceUnknown", "NoReply", "AccessDenied",
        ) if re.search(rf"\b{identifier}\b", message)) or "not reported"
        raise _CLICommandError(
            f"Proton VPN {operation} failed: {category} (exit {result.returncode})",
            category,
            identifiers,
        )
    return result.stdout.strip()


def _flatpak_installed() -> bool:
    try:
        result = subprocess.run(
            [FLATPAK, "list", "--app", "--columns=application"],
            capture_output=True,
            check=False,
            stdin=subprocess.DEVNULL,
            text=True,
            timeout=10,
            env=_cli_environment(),
        )
    except FileNotFoundError:
        raise RuntimeError("Flatpak is unavailable to Decky; check the plugin's runtime environment") from None
    except subprocess.TimeoutExpired:
        raise RuntimeError("Flatpak installation check timed out; refresh status") from None
    except (OSError, UnicodeError):
        raise RuntimeError("Decky could not run Flatpak; check user permissions") from None
    if result.returncode != 0:
        output = f"{result.stderr}\n{result.stdout}".casefold()
        category = _command_failure_category(output)
        raise RuntimeError(f"Flatpak installation check failed: {category} (exit {result.returncode})")
    return PROTON_APP_ID in {line.strip() for line in result.stdout.splitlines()}


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
    installed = None
    signed_in = None
    try:
        installed = _flatpak_installed()
        if not installed:
            return {"installed": False, "signed_in": False, "connected": False}
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
        result = {
            "installed": installed,
            "signed_in": signed_in,
            "connected": None,
            "server": "",
            "protocol": "",
            "error": str(error),
        }
        if isinstance(error, _CLICommandError) and error.category in (
            "keyring error", "keyring locked", "keyring unlock dismissed",
            "keyring backend unavailable", "Secret Service unavailable",
        ):
            try:
                result["diagnostics"] = _keyring_diagnostics()
            except Exception:
                result["diagnostics"] = {"Probe": "unavailable"}
            result["diagnostics"]["CLI exception types"] = error.identifiers
            result["can_start_keyring"] = result["diagnostics"].get("Keyring service activation") == "available"
            decky.logger.warning("Proton VPN keyring diagnostics: %s", json.dumps(result["diagnostics"], sort_keys=True))
        return result


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
    try:
        if not _flatpak_installed():
            return {"signed_in": False, "countries": []}
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
    _cleanup_task: asyncio.Task | None = None

    async def _expire_sessions(self):
        while True:
            await asyncio.sleep(30)
            await asyncio.to_thread(_clear_signin_sessions, True)

    async def _main(self):
        self._cleanup_task = asyncio.create_task(self._expire_sessions())
        decky.logger.info("Proton VPN Decky plugin loaded")

    async def _unload(self):
        if self._cleanup_task is not None:
            self._cleanup_task.cancel()
            await asyncio.gather(self._cleanup_task, return_exceptions=True)
            self._cleanup_task = None
        await asyncio.to_thread(_clear_signin_sessions)
        decky.logger.info("Proton VPN Decky plugin unloaded")

    async def get_status(self) -> dict:
        return await asyncio.to_thread(_cli_operation, _get_status)

    async def start_keyring(self) -> dict:
        try:
            return await asyncio.to_thread(_cli_operation, _start_keyring_service)
        except RuntimeError as error:
            return {"installed": None, "signed_in": None, "connected": None, "error": str(error)}

    async def begin_signin(self) -> dict[str, str]:
        return await asyncio.to_thread(_signin_result, _begin_signin)

    async def complete_signin(self, session_id: str, ciphertext: str) -> dict:
        return await asyncio.to_thread(_signin_result, _cli_operation, _complete_signin, session_id, ciphertext)

    async def cancel_signin(self, session_id: str) -> None:
        await asyncio.to_thread(_cancel_signin, session_id)

    async def get_countries(self) -> dict:
        return await asyncio.to_thread(_cli_operation, _get_countries)

    async def connect_country(self, country_code: str) -> dict:
        return await asyncio.to_thread(_cli_operation, _connect_country, country_code)

    async def disconnect(self) -> dict:
        return await asyncio.to_thread(_cli_operation, _disconnect)
