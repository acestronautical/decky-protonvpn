import json
import os
import re
import subprocess
import time
from itertools import islice
from pathlib import Path

from . import proton_cli


BUSCTL = "/usr/bin/busctl"


JOURNALCTL = "/usr/bin/journalctl"
SYSTEMD_RUN = "/usr/bin/systemd-run"
KSECRET_SERVICE = "/usr/bin/ksecretd"


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


def probe_keyring(environment: dict[str, str]) -> dict[str, str]:
    try:
        result = subprocess.run(
            [proton_cli.FLATPAK, "run", "--command=python3", proton_cli.PROTON_APP_ID, "-c", KEYRING_PROBE_CODE],
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


def diagnostics() -> dict[str, str]:
    environment = proton_cli.cli_environment()
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
    report.update({labels[key]: value for key, value in probe_keyring(environment).items()})
    if not same_bus:
        report.update({f"Standard bus: {labels[key]}": value for key, value in probe_keyring(canonical).items()})
    report.update(host_diagnostics())
    return report


def user_bus_call(method: str, service: str | None = None) -> set[str]:
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
            text=True, timeout=6, env=proton_cli.cli_environment(), start_new_session=True,
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
            ("childsignaled", "service terminated by a signal during startup"),
            ("received signal", "service terminated by a signal during startup"),
            ("execfailed", "service executable could not be started"),
            ("failed to execute", "service executable could not be started"),
            ("exited abnormally", "service exited abnormally during startup"),
            ("childexited", "service exited during startup"),
            ("exited with", "service exited during startup"),
            ("display", "display unavailable"),
        ) if marker in output), "service operation failed")
        signal_match = re.search(r"\breceived signal ([0-9]{1,2})\b", output)
        if signal_match and 1 <= int(signal_match[1]) <= 64:
            category += f"; signal {int(signal_match[1])}"
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


def select_service(names: set[str]) -> str | None:
    if "org.freedesktop.secrets" in names:
        return "org.freedesktop.secrets"
    kde_service = next((name for name in (
        "org.kde.secretservicecompat", "org.kde.kwalletd6", "org.kde.kwalletd5",
    ) if name in names), None)
    gnome_service = "org.gnome.keyring" if "org.gnome.keyring" in names else None
    if kde_service and gnome_service:
        raise RuntimeError("Multiple keyring providers are available; select the existing provider in Desktop Mode")
    return kde_service or gnome_service


def host_diagnostics() -> dict[str, str]:
    try:
        names = user_bus_call("ListNames")
        if "org.freedesktop.secrets" in names:
            return {"Host Secret Service": "running", "Keyring service activation": "not needed"}
        available = user_bus_call("ListActivatableNames")
        service = select_service(available)
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


def startup_diagnostics(started_at: float) -> dict[str, str]:
    try:
        result = subprocess.run(
            [
                JOURNALCTL, "--quiet", "--no-pager", "--boot",
                f"--since=@{started_at:.6f}", "--lines=40", "--output=json",
                "--output-fields=MESSAGE", f"_UID={os.getuid()}",
                "_COMM=ksecretd", "_COMM=kwalletd6", "_COMM=kwalletd5",
            ],
            capture_output=True, check=False, stdin=subprocess.DEVNULL,
            text=True, timeout=6, env=proton_cli.cli_environment(), start_new_session=True,
        )
    except subprocess.TimeoutExpired:
        return {"KDE startup log": "check timed out"}
    except (OSError, subprocess.SubprocessError, UnicodeError):
        return {"KDE startup log": "unavailable"}
    if result.returncode != 0:
        return {"KDE startup log": "unavailable"}
    findings = set()
    messages = 0
    malformed = False
    for line in result.stdout.splitlines():
        try:
            record = json.loads(line)
        except ValueError:
            malformed = True
            continue
        if not isinstance(record, dict) or not isinstance(record.get("MESSAGE"), str):
            malformed = True
            continue
        messages += 1
        message = record["MESSAGE"].casefold()
        for marker, label in (
            ("could not connect to display", "Qt could not connect to a display"),
            ("failed to create wl_display", "Qt could not connect to Wayland"),
            ("could not load the qt platform plugin", "Qt platform plugin could not load"),
            ("no qt platform plugin could be initialized", "Qt platform initialization failed"),
            ("ksecretd is disabled", "KDE wallet disabled in configuration"),
            ("kwalletd is disabled", "KDE wallet disabled in configuration"),
            ("error while loading shared libraries", "service shared library unavailable"),
            ("wallet failed to get opened by pam", "PAM did not unlock the wallet"),
        ):
            if marker in message:
                findings.add(label)
    if not messages:
        return {"KDE startup log": "unreadable entries" if malformed else "no matching entries"}
    return {"KDE startup log": "; ".join(sorted(findings)) if findings else "no recognized failure in recent entries"}


def steam_display_environment(proc_root: Path = Path("/proc")) -> dict[str, str]:
    candidates = set()
    deadline = time.monotonic() + 2
    try:
        with os.scandir(proc_root) as processes:
            for index, process in enumerate(islice(processes, 4097)):
                if index == 4096:
                    raise RuntimeError("Steam display discovery limit reached; no keyring service was started")
                if time.monotonic() >= deadline:
                    raise RuntimeError("Steam display discovery timed out; no keyring service was started")
                if not process.name.isdecimal():
                    continue
                directory = Path(process.path)
                try:
                    if directory.stat().st_uid != os.getuid():
                        continue
                    if (directory / "comm").read_text().strip() != "steam":
                        continue
                    with (directory / "environ").open("rb") as environment_file:
                        raw = environment_file.read(131073)
                    if len(raw) > 131072:
                        continue
                    environment = {}
                    for entry in raw.split(b"\0"):
                        name, separator, value = entry.partition(b"=")
                        if separator and name in (b"DISPLAY", b"XAUTHORITY"):
                            environment[name.decode("ascii")] = os.fsdecode(value)
                    display = environment.get("DISPLAY", "")
                    if not re.fullmatch(r":[0-9]{1,3}(?:\.[0-9]{1,2})?", display):
                        continue
                    display_number = display[1:].partition(".")[0]
                    if not Path(f"/tmp/.X11-unix/X{display_number}").is_socket():
                        continue
                    authority = environment.get("XAUTHORITY")
                    if authority:
                        authority_path = Path(authority)
                        if (
                            not authority_path.is_absolute()
                            or any(character in authority for character in "\0\n\r")
                            or not authority_path.is_file()
                            or authority_path.stat().st_uid != os.getuid()
                        ):
                            continue
                    else:
                        environment.pop("XAUTHORITY", None)
                    candidates.add(tuple(sorted(environment.items())))
                except (OSError, UnicodeError):
                    continue
            else:
                if len(candidates) == 1:
                    return dict(next(iter(candidates)))
    except OSError:
        raise RuntimeError("Steam display discovery is unavailable; no keyring service was started") from None
    if len(candidates) > 1:
        raise RuntimeError("Multiple Steam displays found; no keyring service was started")
    raise RuntimeError("No usable Steam display found; open Steam in the active graphical session before starting the keyring")


def start_kde_service(display_environment: dict[str, str]) -> None:
    if os.getuid() == 0:
        raise RuntimeError("Keyring activation must run as the Deck user, not root")
    environment = proton_cli.cli_environment()
    runtime_dir = f"/run/user/{os.getuid()}"
    bus_address = f"unix:path={runtime_dir}/bus"
    if environment.get("XDG_RUNTIME_DIR") != runtime_dir or environment.get("DBUS_SESSION_BUS_ADDRESS") != bus_address:
        raise RuntimeError("Session-scoped KDE startup requires the standard user bus; no service was started")
    unset = ["WAYLAND_DISPLAY", "QT_PLUGIN_PATH", "QT_QPA_PLATFORM_PLUGIN_PATH", "LD_LIBRARY_PATH", "LD_PRELOAD"]
    if "XAUTHORITY" not in display_environment:
        unset.append("XAUTHORITY")
    command = [
        SYSTEMD_RUN, "--user", "--collect", "--quiet",
        "--unit=decky-protonvpn-keyring",
        "--property=Type=dbus", "--property=BusName=org.freedesktop.secrets",
        "--property=TimeoutStartSec=10s", "--property=TimeoutStopSec=3s",
        "--property=Restart=no", "--property=StandardOutput=journal", "--property=StandardError=journal",
        f"--property=UnsetEnvironment={' '.join(unset)}",
        "--setenv=QT_QPA_PLATFORM=xcb", "--setenv=XDG_SESSION_TYPE=x11", "--setenv=LC_ALL=C",
        f"--setenv=XDG_RUNTIME_DIR={runtime_dir}", f"--setenv=DBUS_SESSION_BUS_ADDRESS={bus_address}",
    ]
    command.extend(f"--setenv={name}={display_environment[name]}" for name in ("DISPLAY", "XAUTHORITY") if name in display_environment)
    command.append(KSECRET_SERVICE)
    try:
        result = subprocess.run(
            command, capture_output=True, check=False, stdin=subprocess.DEVNULL,
            text=True, timeout=15, env=environment, start_new_session=True,
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError("KDE keyring startup timed out; refresh status before retrying") from None
    except (OSError, subprocess.SubprocessError, UnicodeError):
        raise RuntimeError("Session-scoped KDE keyring launcher is unavailable") from None
    if result.returncode != 0:
        raise RuntimeError(f"KDE keyring could not start on Steam's display (exit {result.returncode}); see startup diagnostics")


def start_service() -> tuple[str | None, dict[str, str]]:
    if os.getuid() == 0:
        raise RuntimeError("Keyring activation must run as the Deck user, not root")
    failure = None
    activation_started = None
    startup_report = {"Keyring activation stage": "checking user bus"}
    try:
        names = user_bus_call("ListNames")
        if "org.freedesktop.secrets" not in names:
            startup_report["Keyring activation stage"] = "selecting existing provider"
            service = select_service(user_bus_call("ListActivatableNames"))
            if service is None:
                raise RuntimeError("No existing keyring provider is registered on the user bus; Desktop Mode keyring setup is required")
            if service == "org.kde.secretservicecompat":
                startup_report["Keyring activation stage"] = "finding Steam display"
                display_environment = steam_display_environment()
                startup_report["Keyring activation stage"] = "starting KDE on Steam display"
                activation_started = time.time()
                start_kde_service(display_environment)
            else:
                startup_report["Keyring activation stage"] = "requesting D-Bus activation"
                activation_started = time.time()
                user_bus_call("StartServiceByName", service)
            startup_report["Keyring activation stage"] = "startup completed; checking Proton"
        else:
            startup_report["Keyring activation stage"] = "service already running"
    except RuntimeError as error:
        failure = str(error)
        if activation_started is not None:
            startup_report.update(startup_diagnostics(activation_started))
        else:
            startup_report["KDE startup log"] = "not checked; activation was not attempted"
    return failure, startup_report


def ensure_service() -> None:
    failure = start_service()[0]
    if failure:
        raise RuntimeError(f"Proton VPN keyring startup failed: {failure}")
