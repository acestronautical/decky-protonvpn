import asyncio
import base64
import binascii
import json
import re
import subprocess
import tempfile
import threading
import time
import uuid

import decky
from protonvpn import keyring, proton_cli


SIGNIN_TIMEOUT_SECONDS = 180
SIGNIN_SESSION_TTL_SECONDS = 300
SIGNIN_SESSIONS: dict[str, tuple[bytearray, float]] = {}
SIGNIN_SESSIONS_LOCK = threading.Lock()
CLI_OPERATION_LOCK = threading.Lock()

class OperationBusyError(RuntimeError):
    pass


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
        raise OperationBusyError("A Proton VPN operation is in progress; try again shortly")
    try:
        return operation(*arguments)
    finally:
        CLI_OPERATION_LOCK.release()


def _signin_result(operation, *arguments) -> dict:
    try:
        return operation(*arguments)
    except (ValueError, RuntimeError) as error:
        return {"error": str(error)}


def _status_result(operation, *arguments) -> dict:
    try:
        return operation(*arguments)
    except (ValueError, RuntimeError) as error:
        result = {"installed": None, "signed_in": None, "connected": None, "error": str(error)}
        if isinstance(error, OperationBusyError):
            result["busy"] = True
        return result


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
        env=proton_cli.cli_environment(),
    )
    if private_result.returncode != 0:
        raise RuntimeError("Could not start a secure sign-in session")

    public_result = subprocess.run(
        ["/usr/bin/openssl", "pkey", "-pubout"],
        capture_output=True,
        check=False,
        input=private_result.stdout,
        timeout=10,
        env=proton_cli.cli_environment(),
    )
    if public_result.returncode != 0:
        raise RuntimeError("Could not start a secure sign-in session")
    return bytearray(private_result.stdout), public_result.stdout.decode("ascii")


def _begin_signin() -> dict[str, str]:
    if not proton_cli.flatpak_installed():
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
    except (ValueError, binascii.Error) as error:
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
                env=proton_cli.cli_environment(),
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

    decky.logger.info("Proton VPN sign-in: preparing keyring")
    keyring.ensure_service()
    decky.logger.info("Proton VPN sign-in: starting CLI")
    try:
        result = subprocess.run(
            proton_cli.cli_command(["signin", "--totp", "--", username]),
            input=f"{password}\n{totp}\n",
            capture_output=True,
            check=False,
            text=True,
            timeout=SIGNIN_TIMEOUT_SECONDS,
            env=proton_cli.cli_environment(),
            start_new_session=True,
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError("Proton CLI sign-in timed out; refresh status before retrying") from None
    except (OSError, subprocess.SubprocessError, UnicodeError):
        raise RuntimeError("Proton CLI sign-in could not be started") from None

    decky.logger.info("Proton VPN sign-in: CLI returned; exit=%d", result.returncode)
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
        category = proton_cli.command_failure_category(output)
        raise RuntimeError(f"Proton CLI sign-in failed: {category} (exit {result.returncode})")
    status = _get_status()
    if status.get("error"):
        status["error"] = "Proton CLI completed sign-in, but verification failed. " + status["error"]
    elif status.get("signed_in") is not True:
        status["error"] = "Proton CLI exited without completing sign-in; no signed-in account was verified"
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


def _start_keyring_service() -> dict:
    try:
        failure, startup_report = keyring.start_service()
    except RuntimeError as error:
        return {"installed": None, "signed_in": None, "connected": None, "error": str(error)}
    result = _get_status()
    result.setdefault("diagnostics", {}).update(startup_report)
    if failure:
        result["error"] = failure
        result.setdefault("diagnostics", {})["Service activation result"] = "failed"
    elif result.get("error"):
        result.setdefault("diagnostics", {})["Service activation result"] = "request accepted; Proton verification failed"
    decky.logger.info("Proton VPN keyring activation: %s", json.dumps(result["diagnostics"], sort_keys=True))
    return result


def _get_status() -> dict:
    result = _get_cli_status()
    connection = proton_cli.connection_status()
    if connection.get("error"):
        result.setdefault("error", connection["error"])
    result.update({name: value for name, value in connection.items() if name != "error"})
    return result


def _get_cli_status() -> dict:
    installed = None
    signed_in = None
    try:
        installed = proton_cli.flatpak_installed()
        if not installed:
            return {"installed": False, "signed_in": False, "connected": False}
        keyring.ensure_service()
        return {"installed": True, **proton_cli.panel_snapshot()}
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
        result = {
            "installed": installed,
            "signed_in": signed_in,
            "connected": None,
            "server": "",
            "protocol": "",
            "error": str(error),
        }
        if isinstance(error, proton_cli.CLICommandError) and error.category in (
            "keyring error", "keyring locked", "keyring unlock dismissed",
            "keyring backend unavailable", "Secret Service unavailable",
        ):
            try:
                result["diagnostics"] = keyring.diagnostics()
            except Exception:
                result["diagnostics"] = {"Probe": "unavailable"}
            result["diagnostics"]["CLI exception types"] = error.identifiers
            result["can_start_keyring"] = result["diagnostics"].get("Keyring service activation") == "available"
            decky.logger.warning("Proton VPN keyring diagnostics: %s", json.dumps(result["diagnostics"], sort_keys=True))
        return result


def _get_countries() -> dict:
    return {"countries": [{"code": code, "name": name} for code, name in proton_cli.COUNTRIES.items()]}


def _connect_country(country_code: str) -> dict:
    if not isinstance(country_code, str) or not re.fullmatch(r"[A-Z]{2}", country_code):
        raise ValueError("Choose a valid Proton VPN country")
    country_data = _get_countries()
    if country_code not in {country["code"] for country in country_data["countries"]}:
        raise ValueError("That country is not in Proton VPN's available country list")
    _require_account()
    proton_cli.run_cli(["connect", "--country", country_code])
    return _get_status()


def _disconnect() -> dict:
    if not proton_cli.flatpak_installed():
        raise RuntimeError("Proton VPN is not installed")
    keyring.ensure_service()
    if not proton_cli.signed_in():
        raise RuntimeError("Sign in to the Proton VPN CLI from Desktop Mode first")
    proton_cli.run_cli(["disconnect"])
    return _get_status()


def _require_account() -> None:
    if not proton_cli.flatpak_installed():
        raise RuntimeError("Proton VPN is not installed")
    keyring.ensure_service()
    if not proton_cli.signed_in():
        raise RuntimeError("Sign in to Proton VPN first")


def _quick_connect() -> dict:
    _require_account()
    proton_cli.run_cli(["connect"])
    return _get_status()


def _get_settings() -> dict:
    _require_account()
    output = proton_cli.run_cli(["config", "list"])
    setting = re.search(r"^\s*kill-switch\s+(off|standard)\s*$", output, re.MULTILINE)
    if setting is None:
        return {"kill_switch": None, "error": "Proton did not report a supported kill-switch setting"}
    return {"kill_switch": setting.group(1) == "standard"}


def _set_kill_switch(enabled: bool) -> dict:
    if type(enabled) is not bool:
        raise ValueError("Choose a valid kill-switch setting")
    _require_account()
    active = proton_cli.tunnel_active()
    if active is None:
        raise RuntimeError("Cannot verify tunnel state; kill-switch setting was not changed")
    if active:
        raise RuntimeError("Disconnect the VPN before changing the kill switch")
    proton_cli.run_cli(["config", "set", "kill-switch", "standard" if enabled else "off"])
    setting = _get_settings()
    result = _get_status()
    result.update(setting)
    if setting.get("kill_switch") is not enabled:
        result["error"] = setting.get("error", "Proton did not confirm the requested kill-switch setting")
    return result


def _set_feature(name: str, value: str) -> dict:
    if not isinstance(name, str) or name == "kill-switch" or name not in proton_cli.SETTING_VALUES:
        raise ValueError("Choose a supported VPN setting")
    if not isinstance(value, str) or value not in proton_cli.SETTING_VALUES[name]:
        raise ValueError("Choose a supported setting value")
    _require_account()
    proton_cli.run_cli(["config", "set", name, value])
    result = _get_status()
    if result.get("settings", {}).get(name) != value:
        result.setdefault("error", "Proton did not confirm the requested setting")
    elif result.get("connected") and name in result.get("requires_reconnect", []):
        result["notice"] = "Setting saved; reconnect to apply it"
    return result


def _signout() -> dict:
    _require_account()
    active = proton_cli.tunnel_active()
    if active is None:
        raise RuntimeError("Cannot verify tunnel state; sign-out was not attempted")
    if active:
        result = _disconnect()
        if result.get("error") or result.get("tunnel_active") is not False:
            raise RuntimeError("Disconnect could not be verified; sign-out was not attempted")
    proton_cli.run_cli(["signout"])
    result = _get_status()
    if result.get("signed_in") is not False or result.get("tunnel_active") is not False:
        result["error"] = "Proton sign-out could not be verified; check account and tunnel status"
    return result


class Plugin:
    _cleanup_task: asyncio.Task | None = None

    async def get_connection_status(self) -> dict:
        return await asyncio.to_thread(proton_cli.connection_status)

    async def set_feature(self, name: str, value: str) -> dict:
        return await asyncio.to_thread(_status_result, _cli_operation, _set_feature, name, value)

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
        return await asyncio.to_thread(_status_result, _cli_operation, _get_status)

    async def start_keyring(self) -> dict:
        try:
            return await asyncio.to_thread(_cli_operation, _start_keyring_service)
        except RuntimeError as error:
            return {"installed": None, "signed_in": None, "connected": None, "error": str(error)}

    async def begin_signin(self) -> dict[str, str]:
        decky.logger.info("Proton VPN sign-in: secure session requested")
        result = await asyncio.to_thread(_signin_result, _begin_signin)
        decky.logger.info("Proton VPN sign-in: secure session %s", "failed" if "error" in result else "ready")
        return result

    async def complete_signin(self, session_id: str, ciphertext: str) -> dict:
        decky.logger.info("Proton VPN sign-in: encrypted submission received")
        result = await asyncio.to_thread(_signin_result, _cli_operation, _complete_signin, session_id, ciphertext)
        outcome = "error" if result.get("error") else "signed in" if result.get("signed_in") is True else "not verified"
        decky.logger.info("Proton VPN sign-in: completion returned; outcome=%s", outcome)
        return result

    async def cancel_signin(self, session_id: str) -> None:
        decky.logger.info("Proton VPN sign-in: unused session cleanup requested")
        await asyncio.to_thread(_cancel_signin, session_id)

    async def get_countries(self) -> dict:
        return await asyncio.to_thread(_cli_operation, _get_countries)

    async def connect_country(self, country_code: str) -> dict:
        return await asyncio.to_thread(_status_result, _cli_operation, _connect_country, country_code)

    async def disconnect(self) -> dict:
        return await asyncio.to_thread(_status_result, _cli_operation, _disconnect)

    async def quick_connect(self) -> dict:
        return await asyncio.to_thread(_status_result, _cli_operation, _quick_connect)

    async def get_settings(self) -> dict:
        try:
            return await asyncio.to_thread(_cli_operation, _get_settings)
        except (OSError, RuntimeError, subprocess.SubprocessError) as error:
            return {"kill_switch": None, "error": str(error)}

    async def set_kill_switch(self, enabled: bool) -> dict:
        return await asyncio.to_thread(_status_result, _cli_operation, _set_kill_switch, enabled)

    async def signout(self) -> dict:
        return await asyncio.to_thread(_status_result, _cli_operation, _signout)
