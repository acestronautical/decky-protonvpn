import asyncio
import base64
import builtins
import hashlib
import inspect
import io
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
import traceback
import types
import unittest
from contextlib import redirect_stdout
from concurrent.futures import Future
from importlib import metadata
from pathlib import Path
from unittest.mock import Mock, call, patch

sys.modules.setdefault("decky", types.ModuleType("decky"))

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "py_modules"))

import main
from protonvpn import cli_compat, keyring, proton_cli


class KeyringReadTests(unittest.TestCase):
    def setUp(self):
        class Backend:
            KEYRING_SERVICE = "ProtonVPN"

            def _get_item(self, key):
                raise AssertionError("Unpatched implementation")

        class LockedError(RuntimeError):
            pass

        self.original = Backend._get_item
        self.module = types.SimpleNamespace(
            KeyringBackendLinuxSecretService=Backend,
            keyring=types.SimpleNamespace(errors=types.SimpleNamespace(KeyringLocked=LockedError, KeyringError=RuntimeError)),
            KeyringLocked=LockedError, KeyringError=RuntimeError,
        )
        self.backend = Backend()
        self.backend._backend = Mock()
        self.backend._del_item = Mock()
        digest = hashlib.sha256(inspect.getsource(self.original).encode()).hexdigest()
        with patch.object(cli_compat, "UPSTREAM_KEYRING_GET_SHA256", digest):
            self.assertTrue(cli_compat.install_keyring_read_fix(self.module))

    def test_valid_json_and_existing_newline_workaround(self):
        for value, expected in (('["account"]', ["account"]), ('{"text":"first\nsecond"}', {"text": "first\nsecond"})):
            with self.subTest(value=value):
                self.backend._backend.get_password.return_value = value
                self.assertEqual(self.backend._get_item("proton-sso-accounts"), expected)
                self.backend._del_item.assert_not_called()

    def test_malformed_or_empty_read_never_deletes_credentials(self):
        for value in ("", "private-invalid-data", "{truncated"):
            with self.subTest(value=value):
                self.backend._backend.get_password.return_value = value
                with self.assertRaisesRegex(RuntimeError, "saved credentials were not changed") as raised:
                    self.backend._get_item("proton-sso-accounts")
                self.assertNotIn("private-invalid-data", str(raised.exception))
                self.backend._del_item.assert_not_called()

    def test_missing_item_remains_missing(self):
        self.backend._backend.get_password.return_value = None
        with self.assertRaises(KeyError):
            self.backend._get_item("missing")
        self.backend._del_item.assert_not_called()

    def test_locked_and_failed_reads_propagate_without_deletion(self):
        for error in (self.module.KeyringLocked("private-data"), RuntimeError("private-data")):
            with self.subTest(error=type(error)):
                self.backend._backend.get_password.side_effect = error
                with self.assertRaises(type(error)) as raised:
                    self.backend._get_item("proton-sso-accounts")
                self.assertNotIn("private-data", str(raised.exception))
                self.backend._del_item.assert_not_called()

    def test_unknown_source_is_not_replaced(self):
        self.module.KeyringBackendLinuxSecretService._get_item = self.original
        self.assertFalse(cli_compat.install_keyring_read_fix(self.module))
        self.assertIs(self.module.KeyringBackendLinuxSecretService._get_item, self.original)
        with patch.object(cli_compat.inspect, "getsource", side_effect=OSError):
            self.assertFalse(cli_compat.install_keyring_read_fix(self.module))

    def test_launcher_requires_guard_before_running_cli(self):
        original_import = builtins.__import__

        def import_backend(name, *arguments, **kwargs):
            if name == "proton.keyring_linux.secretservice":
                return types.SimpleNamespace(secretservice_backend=self.module)
            if name.startswith("proton.vpn"):
                raise AssertionError("Read-only operation imported network backend")
            return original_import(name, *arguments, **kwargs)

        for supported in (False, True):
            with (
                self.subTest(supported=supported),
                patch.object(builtins, "__import__", side_effect=import_backend),
                patch.object(cli_compat, "install_keyring_read_fix", return_value=supported) as guard,
                patch.object(cli_compat.sys, "argv", ["launcher", "info"]),
                patch.object(cli_compat.runpy, "run_path") as run,
            ):
                if supported:
                    cli_compat.main()
                    run.assert_called_once_with("/app/bin/protonvpn", run_name="__main__")
                else:
                    with self.assertRaisesRegex(RuntimeError, "no CLI command was run"):
                        cli_compat.main()
                    run.assert_not_called()
                guard.assert_called_once_with(self.module)


class ReliabilityTests(unittest.TestCase):
    def test_signin_uses_guard_without_putting_password_in_arguments(self):
        with (
            patch.object(keyring, "ensure_service"),
            patch.object(main.decky, "logger", create=True),
            patch.object(main, "_get_status", return_value={"signed_in": True}),
            patch.object(subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "", "")) as run,
        ):
            main._run_cli_signin({"username": "test-user", "password": "private-password", "totp": ""})
        command = run.call_args.args[0]
        self.assertEqual(command, proton_cli.cli_command(["signin", "--totp", "--", "test-user"]))
        self.assertNotIn("private-password", " ".join(command))
        self.assertEqual(run.call_args.kwargs["input"], "private-password\n\n")

    def test_failed_wallet_start_prevents_account_reads(self):
        with (
            patch.object(proton_cli, "flatpak_installed", return_value=True),
            patch.object(keyring, "ensure_service", side_effect=RuntimeError("Wallet unavailable")),
            patch.object(proton_cli, "panel_snapshot") as account,
        ):
            result = main._get_cli_status()
        self.assertIsNone(result["signed_in"])
        self.assertEqual(result["error"], "Wallet unavailable")
        account.assert_not_called()

    def test_account_operations_prepare_wallet_before_account_read(self):
        for operation in (main._get_cli_status, main._disconnect):
            calls = Mock()
            calls.account.return_value = True
            with (
                self.subTest(operation=operation.__name__),
                patch.object(proton_cli, "flatpak_installed", return_value=True),
                patch.object(keyring, "ensure_service", side_effect=calls.wallet),
                patch.object(proton_cli, "signed_in", side_effect=calls.account),
                patch.object(proton_cli, "panel_snapshot", side_effect=lambda: calls.account() and {"signed_in": True}),
                patch.object(proton_cli, "run_cli", return_value="Status: Disconnected"),
                patch.object(main, "_get_status", return_value={}),
            ):
                operation()
            self.assertEqual(calls.mock_calls[:2], [call.wallet(), call.account()])

    def test_active_tunnel_remains_visible_when_keyring_fails(self):
        with (
            patch.object(proton_cli, "connection_status", return_value={"connected": True, "tunnel_active": True}),
            patch.object(main, "_get_cli_status", return_value={"connected": None, "signed_in": None, "error": "Keyring unavailable"}),
        ):
            result = main._get_status()
        self.assertTrue(result["tunnel_active"])
        self.assertTrue(result["connected"])
        self.assertEqual(result["error"], "Keyring unavailable")

    def test_networkmanager_is_authoritative_in_both_directions(self):
        for active in (True, False):
            with (
                self.subTest(active=active),
                patch.object(proton_cli, "connection_status", return_value={"connected": active, "tunnel_active": active}),
                patch.object(main, "_get_cli_status", return_value={"connected": not active, "signed_in": True}),
            ):
                result = main._get_status()
            self.assertIs(result["tunnel_active"], active)
            self.assertIs(result["connected"], active)
            self.assertNotIn("error", result)

    def test_tunnel_probe_is_bounded_and_ignores_unrelated_interfaces(self):
        for output, expected in (("wireguard:proton0\n", True), ("802-11-wireless:wlan0\nwireguard:other\n", False)):
            with self.subTest(output=output), patch.object(subprocess, "run", return_value=subprocess.CompletedProcess([], 0, output, "")) as run:
                self.assertIs(proton_cli.tunnel_active(), expected)
                self.assertEqual(run.call_args.args[0], ["/usr/bin/nmcli", "-t", "-f", "TYPE,DEVICE", "connection", "show", "--active"])
                self.assertEqual(run.call_args.kwargs["timeout"], 5)
                self.assertEqual(run.call_args.kwargs["stdin"], subprocess.DEVNULL)
        for failure in (OSError("private-data"), subprocess.TimeoutExpired([], 5)):
            with patch.object(subprocess, "run", side_effect=failure):
                self.assertIsNone(proton_cli.tunnel_active())
        with patch.object(subprocess, "run", return_value=subprocess.CompletedProcess([], 1, "", "private-data")):
            self.assertIsNone(proton_cli.tunnel_active())


class InstallationJobTests(unittest.TestCase):
    def setUp(self):
        self.job = patch.object(main, "INSTALL_JOB", {"state": "idle"})
        self.job.start()
        self.addCleanup(self.job.stop)

    def test_duplicate_requests_share_one_job_and_status_does_not_run_cli(self):
        with patch.object(main.threading, "Thread") as thread, patch.object(main, "_get_status") as status:
            first = asyncio.run(main.Plugin().install_proton())
            try:
                second = asyncio.run(main.Plugin().install_proton())
                snapshot = main._status_with_installation()
                self.assertEqual(first, second)
                self.assertEqual(snapshot["installation"]["state"], "running")
                thread.assert_called_once()
                status.assert_not_called()
            finally:
                main.CLI_OPERATION_LOCK.release()

    def test_busy_operation_prevents_job_start(self):
        with main.CLI_OPERATION_LOCK, patch.object(main.threading, "Thread") as thread:
            self.assertEqual(main._start_installation()["state"], "blocked")
        thread.assert_not_called()

    def test_worker_verifies_cli_and_releases_lock_on_success_and_failure(self):
        for result, state in (({"installed": True, "signed_in": False}, "succeeded"), ({"installed": True, "signed_in": None, "error": "Unsupported Proton keyring implementation"}, "failed")):
            with self.subTest(state=state), patch.object(proton_cli, "install_flatpak") as install, patch.object(main, "_get_status", return_value=result) as status:
                main.INSTALL_JOB.update(state="running")
                main.CLI_OPERATION_LOCK.acquire()
                main._run_installation()
                self.assertEqual(main._installation_status()["state"], state)
                self.assertFalse(main.CLI_OPERATION_LOCK.locked())
                install.assert_called_once()
                status.assert_called_once()

    def test_worker_failure_is_not_retried_or_followed_by_cli_read(self):
        with patch.object(proton_cli, "install_flatpak", side_effect=RuntimeError("Installation failed")) as install, patch.object(main, "_get_status") as status:
            main.CLI_OPERATION_LOCK.acquire()
            main._run_installation()
        self.assertEqual(main._installation_status()["error"], "Installation failed")
        self.assertFalse(main.CLI_OPERATION_LOCK.locked())
        install.assert_called_once()
        status.assert_not_called()

    def test_real_worker_keeps_one_job_and_publishes_completion_after_unlock(self):
        entered = main.threading.Event()
        release = main.threading.Event()
        real_thread = main.threading.Thread
        workers = []

        def create_thread(**arguments):
            worker = real_thread(**arguments)
            workers.append(worker)
            return worker

        def install(progress):
            progress("installing")
            entered.set()
            if not release.wait(2):
                raise RuntimeError("Test gate timed out")

        with patch.object(main.threading, "Thread", side_effect=create_thread), patch.object(proton_cli, "install_flatpak", side_effect=install) as installer, patch.object(main, "_get_status", return_value={"installed": True, "signed_in": False}):
            try:
                self.assertEqual(main._start_installation()["state"], "running")
                self.assertTrue(entered.wait(2))
                self.assertEqual(main._start_installation()["stage"], "installing")
                self.assertEqual(main._status_with_installation()["installation"]["state"], "running")
            finally:
                release.set()
                for worker in workers:
                    worker.join(3)
            self.assertEqual(len(workers), 1)
            self.assertFalse(workers[0].is_alive())
            self.assertEqual(main._installation_status()["state"], "succeeded")
            self.assertFalse(main.CLI_OPERATION_LOCK.locked())
            installer.assert_called_once()


class FlatpakInstallTests(unittest.TestCase):
    def test_existing_trusted_remote_is_reused_and_success_is_verified(self):
        remote = "flathub\thttps://dl.flathub.org/repo/\t\n"
        with patch.object(os, "getuid", return_value=1000), patch.object(proton_cli, "flatpak_installed", side_effect=[False, False]), patch.object(subprocess, "run", side_effect=[subprocess.CompletedProcess([], 0, output, "") for output in (remote, "")]) as run:
            with self.assertRaisesRegex(RuntimeError, "could not be verified"):
                proton_cli.install_flatpak(Mock())
        self.assertEqual([call.args[0][1] for call in run.call_args_list], ["remotes", "install"])

    def test_user_install_adds_only_official_remote_and_verifies_installation(self):
        remote = "flathub\thttps://dl.flathub.org/repo/\t\n"
        replies = ["", "", remote, ""]
        with patch.object(os, "getuid", return_value=1000), patch.object(proton_cli, "flatpak_installed", side_effect=[False, True]), patch.object(subprocess, "run", side_effect=[subprocess.CompletedProcess([], 0, output, "") for output in replies]) as run:
            progress = Mock()
            proton_cli.install_flatpak(progress)
        commands = [call.args[0] for call in run.call_args_list]
        self.assertEqual(commands[-1], [proton_cli.FLATPAK, "install", "--user", "--noninteractive", "--assumeyes", "flathub", "com.protonvpn.www//stable"])
        self.assertIn("https://dl.flathub.org/repo/flathub.flatpakrepo", commands[1])
        self.assertEqual(run.call_args_list[-1].kwargs["timeout"], 1800)
        for call in run.call_args_list:
            self.assertIn("--user", call.args[0])
            self.assertEqual(call.kwargs["stdin"], subprocess.DEVNULL)
        self.assertEqual([call.args[0] for call in progress.call_args_list], ["checking", "repository", "installing", "verifying"])

    def test_existing_installation_is_never_updated_or_duplicated(self):
        with patch.object(os, "getuid", return_value=1000), patch.object(proton_cli, "flatpak_installed", return_value=True), patch.object(subprocess, "run") as run:
            proton_cli.install_flatpak(Mock())
        run.assert_not_called()

    def test_root_is_rejected_before_any_flatpak_operation(self):
        with patch.object(os, "getuid", return_value=0), patch.object(proton_cli, "flatpak_installed") as installed:
            with self.assertRaisesRegex(RuntimeError, "not root"):
                proton_cli.install_flatpak(Mock())
        installed.assert_not_called()

    def test_untrusted_remote_is_not_replaced_or_used(self):
        for remote in ("flathub\thttps://example.com/repo/\t\n", "flathub\thttps://dl.flathub.org/repo/\tno-gpg-verify\n"):
            with self.subTest(remote=remote), patch.object(os, "getuid", return_value=1000), patch.object(proton_cli, "flatpak_installed", return_value=False), patch.object(subprocess, "run", return_value=subprocess.CompletedProcess([], 0, remote, "")) as run:
                with self.assertRaisesRegex(RuntimeError, "not trusted"):
                    proton_cli.install_flatpak(Mock())
            self.assertEqual(run.call_count, 1)

    def test_failure_and_timeout_are_sanitized_and_not_retried(self):
        for failure in (subprocess.CompletedProcess([], 1, "private-data", "private-data"), subprocess.TimeoutExpired("private-data", 60)):
            with self.subTest(failure=type(failure).__name__), patch.object(os, "getuid", return_value=1000), patch.object(proton_cli, "flatpak_installed", return_value=False), patch.object(subprocess, "run", side_effect=[failure]) as run:
                with self.assertRaises(RuntimeError) as raised:
                    proton_cli.install_flatpak(Mock())
            self.assertNotIn("private-data", str(raised.exception))
            self.assertEqual(run.call_count, 1)


class PanelSnapshotTests(unittest.IsolatedAsyncioTestCase):
    async def test_snapshot_reads_metadata_and_settings_without_server_lookup(self):
        controller = Mock(is_logged_in=True, user_on_free_tier=False, account_name="verified-user")

        async def setting(feature):
            return "standard"

        controller.get_feature_setting = setting
        feature = types.SimpleNamespace(command="kill-switch", available_on_free_tier=True, click_type=types.SimpleNamespace(to_str=str))
        result = await cli_compat.read_panel_snapshot(controller, [feature])
        self.assertEqual(result["settings"], {"kill-switch": "standard"})
        self.assertEqual(result["account_name"], "verified-user")
        self.assertNotIn("connected", result)
        controller.get_updated_server_list.assert_not_called()
        controller.get_vpn_connector.assert_not_called()

    async def test_snapshot_handles_free_tier_and_signed_out_without_connection_reads(self):
        controller = Mock(is_logged_in=True, user_on_free_tier=True)
        feature = types.SimpleNamespace(command="netshield", available_on_free_tier=False)
        result = await cli_compat.read_panel_snapshot(controller, [feature])
        self.assertTrue(result["signed_in"])
        self.assertNotIn("connected", result)
        self.assertNotIn("private-data", str(result))
        self.assertEqual(result["requires_upgrade"], ["netshield"])
        controller.get_feature_setting.assert_not_called()
        controller.is_logged_in = False
        signed_out = await cli_compat.read_panel_snapshot(controller, [feature])
        self.assertFalse(signed_out["signed_in"])
        self.assertIsNone(signed_out["account_name"])
        controller.get_vpn_connector.assert_not_called()

    async def test_unavailable_account_name_does_not_break_snapshot_or_expose_details(self):
        class Controller:
            is_logged_in = True

            @property
            def account_name(self):
                raise RuntimeError("private-data")

        result = await cli_compat.read_panel_snapshot(Controller(), [])
        self.assertTrue(result["signed_in"])
        self.assertIsNone(result["account_name"])
        self.assertEqual(result["settings"], {})
        self.assertNotIn("private-data", str(result))

    async def test_signed_out_snapshot_does_not_read_account_name(self):
        reads = []

        class Controller:
            is_logged_in = False

            @property
            def account_name(self):
                reads.append(True)
                return "previous-user"

        result = await cli_compat.read_panel_snapshot(Controller(), [])
        self.assertIsNone(result["account_name"])
        self.assertEqual(reads, [])

    async def test_settings_failure_preserves_auth_without_exposing_details(self):
        controller = Mock(is_logged_in=True, user_on_free_tier=False)

        async def setting(feature):
            raise RuntimeError("private-data")

        controller.get_feature_setting = setting
        feature = types.SimpleNamespace(command="netshield", available_on_free_tier=False)
        result = await cli_compat.read_panel_snapshot(controller, [feature])
        self.assertTrue(result["signed_in"])
        self.assertEqual(result["settings_error"], "Proton settings could not be read")
        self.assertNotIn("settings", result)
        self.assertNotIn("private-data", str(result))


class ConnectionSnapshotTests(unittest.TestCase):
    def test_snapshot_returns_only_valid_authenticated_account_name(self):
        for signed_in, name, expected in (
            (True, "verified-user@example.com", "verified-user@example.com"),
            (False, "previous-user", None),
            (True, None, None),
            (True, {"token": "private-data"}, None),
            (True, "bad\nname", None),
            (True, "a" * 255, None),
        ):
            payload = {"signed_in": signed_in, "account_name": name, "credentials": "private-data"}
            with self.subTest(signed_in=signed_in, expected=expected), patch.object(proton_cli, "run_cli", return_value=json.dumps(payload)):
                result = proton_cli.panel_snapshot()
            self.assertEqual(result["account_name"], expected)
            self.assertNotIn("private-data", str(result))

    def test_account_status_rpc_returns_busy_without_reading_or_throwing(self):
        with main.CLI_OPERATION_LOCK, patch.object(main, "_get_status") as status:
            result = asyncio.run(main.Plugin().get_status())
        self.assertTrue(result["busy"])
        self.assertIsNone(result["signed_in"])
        self.assertIn("in progress", result["error"])
        status.assert_not_called()
        with patch.object(main, "_get_status", return_value={"signed_in": False}) as status:
            self.assertFalse(asyncio.run(main.Plugin().get_status())["signed_in"])
        status.assert_called_once_with()

    def test_connection_rpc_works_during_cli_operation_without_proton_or_wallet(self):
        expected = {"connected": True, "tunnel_active": True}
        with main.CLI_OPERATION_LOCK, patch.object(proton_cli, "connection_status", return_value=expected), patch.object(proton_cli, "run_cli") as cli, patch.object(proton_cli, "flatpak_installed") as installed, patch.object(keyring, "ensure_service") as wallet:
            self.assertEqual(asyncio.run(main.Plugin().get_connection_status()), expected)
        cli.assert_not_called()
        installed.assert_not_called()
        wallet.assert_not_called()

    def test_invalid_snapshot_is_rejected_without_echoing_output(self):
        for output in ("private-data", "[]", '{"signed_in":"private-data"}', '{"signed_in":true,"settings":{"netshield":"private-data"}}'):
            with self.subTest(output=output), patch.object(proton_cli, "run_cli", return_value=output):
                with self.assertRaisesRegex(RuntimeError, "unsupported panel snapshot") as raised:
                    proton_cli.panel_snapshot()
                self.assertNotIn("private-data", str(raised.exception))

    def test_connection_metadata_uses_only_networkmanager(self):
        for output, connected, server in (
            ("wireguard:proton0:activated:ProtonVPN CA#12", True, "CA#12"),
            ("wireguard:proton0:activated:ProtonVPN", True, ""),
            ("wireguard:proton0:activating:ProtonVPN", None, ""),
            ("wifi:wlan0:activated:private-network", False, ""),
        ):
            with self.subTest(output=output), patch.object(subprocess, "run", return_value=subprocess.CompletedProcess([], 0, output, "")), patch.object(proton_cli, "run_cli") as cli:
                result = proton_cli.connection_status()
                self.assertIs(result["connected"], connected)
                self.assertEqual(result["server"], server)
                cli.assert_not_called()

    def test_connection_failure_stays_unknown(self):
        with patch.object(subprocess, "run", side_effect=OSError("private-data")):
            result = proton_cli.connection_status()
        self.assertIsNone(result["connected"])
        self.assertNotIn("private-data", str(result))


class PanelActionTests(unittest.TestCase):
    def setUp(self):
        guard = patch.object(main, "_require_account")
        self.account = guard.start()
        self.addCleanup(guard.stop)

    def test_quick_connect_uses_fastest_server_without_country(self):
        with patch.object(proton_cli, "run_cli") as cli, patch.object(main, "_get_status", return_value={"connected": True}):
            self.assertTrue(main._quick_connect()["connected"])
        cli.assert_called_once_with(["connect"])
        self.account.assert_called_once_with()

    def test_feature_actions_validate_allowlist_and_readback(self):
        for name in ("netshield", "vpn-accelerator", "moderate-nat"):
            for value in proton_cli.SETTING_VALUES[name]:
                expected = {"settings": {name: value}, "connected": True, "requires_reconnect": [name]}
                with self.subTest(name=name, value=value), patch.object(proton_cli, "run_cli") as cli, patch.object(main, "_get_status", return_value=expected):
                    result = main._set_feature(name, value)
                    self.assertNotIn("error", result)
                    self.assertIn("reconnect", result["notice"])
                    cli.assert_called_once_with(["config", "set", name, value])
        with patch.object(proton_cli, "run_cli"), patch.object(main, "_get_status", return_value={"settings": {"netshield": "off"}}):
            self.assertIn("error", main._set_feature("netshield", "malware-only"))
        for name, value in (("kill-switch", "off"), ("custom-dns", "on"), ([], "on"), ("netshield", "private-data"), ("moderate-nat", True)):
            with self.subTest(name=name, value=value), patch.object(proton_cli, "run_cli") as cli:
                with self.assertRaises(ValueError):
                    getattr(main, "_set_feature")(name, value)
                cli.assert_not_called()

    def test_feature_rpc_does_not_run_when_busy(self):
        with main.CLI_OPERATION_LOCK, patch.object(main, "_set_feature") as action:
            result = asyncio.run(main.Plugin().set_feature("netshield", "off"))
        self.assertIn("in progress", result["error"])
        action.assert_not_called()

    def test_kill_switch_reads_real_setting_and_rejects_unknown(self):
        for output, expected in (("kill-switch              off", False), ("kill-switch  standard", True), ("kill-switch permanent", None), ("", None)):
            with self.subTest(output=output), patch.object(proton_cli, "run_cli", return_value=output) as cli:
                self.assertIs(main._get_settings()["kill_switch"], expected)
                cli.assert_called_once_with(["config", "list"])

    @patch.object(proton_cli, "tunnel_active", return_value=False)
    def test_toggle_validates_input_and_checks_readback(self, tunnel):
        for enabled in (True, False):
            with self.subTest(enabled=enabled), patch.object(proton_cli, "run_cli") as cli, patch.object(main, "_get_settings", return_value={"kill_switch": enabled}), patch.object(main, "_get_status", return_value={}):
                self.assertIs(main._set_kill_switch(enabled)["kill_switch"], enabled)
                cli.assert_called_once_with(["config", "set", "kill-switch", "standard" if enabled else "off"])
        for invalid in ("false", 1, None):
            with self.subTest(invalid=invalid), patch.object(proton_cli, "run_cli") as cli:
                with self.assertRaises(ValueError):
                    main._set_kill_switch(invalid)
                cli.assert_not_called()
        with patch.object(proton_cli, "run_cli"), patch.object(main, "_get_settings", return_value={"kill_switch": False}), patch.object(main, "_get_status", return_value={}):
            self.assertIn("error", main._set_kill_switch(True))
        self.assertEqual(tunnel.call_count, 3)

    def test_kill_switch_refuses_active_or_unknown_tunnel_without_commands(self):
        for enabled in (True, False):
            for active, message in ((True, "Disconnect the VPN"), (None, "Cannot verify tunnel state")):
                with self.subTest(enabled=enabled, active=active), patch.object(proton_cli, "tunnel_active", return_value=active), patch.object(proton_cli, "run_cli") as cli, patch.object(main, "_disconnect") as disconnect:
                    with self.assertRaisesRegex(RuntimeError, message):
                        main._set_kill_switch(enabled)
                    cli.assert_not_called()
                    disconnect.assert_not_called()

    def test_kill_switch_cli_refusal_is_readable_without_raw_output(self):
        environment = {"XDG_RUNTIME_DIR": "/run/user/1000", "DBUS_SESSION_BUS_ADDRESS": "unix:path=/run/user/1000/bus"}
        failure = subprocess.CompletedProcess([], 2, "private-data", "Error: Disconnect before changing Kill Switch. Run 'protonvpn disconnect' first.")
        with patch.object(proton_cli.os, "getuid", return_value=1000), patch.object(proton_cli, "cli_environment", return_value=environment), patch.object(subprocess, "run", return_value=failure):
            with self.assertRaises(RuntimeError) as raised:
                proton_cli.run_cli(["config", "set", "kill-switch", "standard"])
        self.assertEqual(str(raised.exception), "Disconnect the VPN before changing the kill switch")

    def test_signout_disconnects_first_and_verifies_logout(self):
        calls = Mock()
        with patch.object(proton_cli, "tunnel_active", return_value=True), patch.object(main, "_disconnect", side_effect=lambda: calls.disconnect() or {}) as disconnect, patch.object(proton_cli, "run_cli", side_effect=calls.cli), patch.object(main, "_get_status", return_value={"signed_in": False, "tunnel_active": False}):
            calls.disconnect.return_value = {"tunnel_active": False}
            self.assertFalse(main._signout()["signed_in"])
            disconnect.assert_called_once_with()
        self.assertEqual(calls.mock_calls, [call.disconnect(), call.cli(["signout"])])

    def test_signout_refuses_unknown_or_failed_disconnect(self):
        for active, disconnected in ((None, {}), (True, {"tunnel_active": True}), (True, {"error": "failed", "tunnel_active": False})):
            with self.subTest(active=active, disconnected=disconnected), patch.object(proton_cli, "tunnel_active", return_value=active), patch.object(main, "_disconnect", return_value=disconnected), patch.object(proton_cli, "run_cli") as cli:
                with self.assertRaisesRegex(RuntimeError, "sign-out was not attempted"):
                    main._signout()
                cli.assert_not_called()


class RouteSnapshotTests(unittest.TestCase):
    def setUp(self):
        class Client:
            _assert_running_on_glib_loop_thread = Mock()

            @classmethod
            def _apply_connection_async(cls, active_connection, future):
                raise AssertionError("Unpatched implementation")

        self.client = Client
        self.original = Client._apply_connection_async
        self.source = inspect.getsource(self.original)
        self.nm = Mock()
        self.connection = Mock(routes=[])
        self.device = Mock()
        self.active = Mock()
        self.active.get_connection.return_value = self.connection
        self.active.get_devices.return_value = [self.device]
        self.nm.SimpleConnection.new_clone.side_effect = lambda connection: types.SimpleNamespace(routes=list(connection.routes))
        self.future = Future()

    def install(self):
        with patch.object(cli_compat, "UPSTREAM_ROUTE_APPLY_SHA256", hashlib.sha256(self.source.encode()).hexdigest()):
            self.assertTrue(cli_compat.install_route_snapshot_fix(self.client, self.nm))

    def commit(self):
        callback = self.connection.commit_changes_async.call_args.kwargs["callback"]
        callback(self.connection, object())

    def test_snapshot_survives_callback_configuration_replacement(self):
        self.install()
        for requested, stale in ((["endpoint"], []), ([], ["endpoint"])):
            with self.subTest(requested=requested):
                self.future = Future()
                self.connection.routes = list(requested)
                self.client._apply_connection_async(self.active, self.future)
                self.connection.routes[:] = stale
                self.commit()
                arguments = self.device.reapply_async.call_args
                self.assertEqual(arguments.args[0].routes, requested)
                self.assertEqual(arguments.kwargs["version_id"], 0)
                self.assertEqual(arguments.kwargs["flags"], 0)
                self.assertIsNone(arguments.kwargs["cancellable"])
                self.assertFalse(self.future.done())
                arguments.kwargs["callback"](self.device, object())
                self.assertIsNone(self.future.result(timeout=0))
        self.connection.commit_changes_async.assert_called_with(
            save_to_disk=False, cancellable=None,
            callback=self.connection.commit_changes_async.call_args.kwargs["callback"],
        )
        self.assertEqual(self.client._assert_running_on_glib_loop_thread.call_count, 2)

    def test_commit_failure_prevents_reapply(self):
        self.install()
        error = RuntimeError("commit failed")
        self.connection.commit_changes_finish.side_effect = error
        self.client._apply_connection_async(self.active, self.future)
        self.commit()
        self.assertIs(self.future.exception(timeout=0), error)
        self.device.reapply_async.assert_not_called()

    def test_reapply_failures_propagate(self):
        self.install()
        for method in ("reapply_async", "reapply_finish"):
            with self.subTest(method=method):
                self.future = Future()
                self.device.reset_mock(side_effect=True)
                error = RuntimeError("reapply failed")
                getattr(self.device, method).side_effect = error
                self.client._apply_connection_async(self.active, self.future)
                self.commit()
                if method == "reapply_finish":
                    self.device.reapply_async.call_args.kwargs["callback"](self.device, object())
                self.assertIs(self.future.exception(timeout=0), error)

    def test_unknown_or_unreadable_implementation_is_unchanged(self):
        self.assertFalse(cli_compat.install_route_snapshot_fix(self.client, self.nm))
        self.assertEqual(self.client._apply_connection_async, self.original)
        with patch.object(cli_compat.inspect, "getsource", side_effect=OSError):
            self.assertFalse(cli_compat.install_route_snapshot_fix(self.client, self.nm))
        self.assertEqual(self.client._apply_connection_async, self.original)
        self.nm.SimpleConnection.new_clone.assert_not_called()

    def test_all_commands_use_guard_and_only_network_uses_service(self):
        launcher = Path(cli_compat.__file__).read_text(encoding="utf-8")
        for arguments in (["connect"], ["connect", "--country", "US"], ["disconnect"], ["signout"], ["config", "set", "kill-switch", "standard"], ["config", "list"], ["status"], ["info"], ["countries", "list"]):
            with self.subTest(arguments=arguments), patch.object(subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "ok", "")) as run:
                self.assertEqual(proton_cli.run_cli(arguments), "ok")
                expected = (
                    [
                        "/usr/bin/systemd-run", "--user", "--wait", "--pipe", "--collect", "--quiet",
                        "--unit=decky-protonvpn-network", "--expand-environment=no",
                        "--property=Type=exec", "--property=Restart=no",
                        f"--property=RuntimeMaxSec={proton_cli.CLI_TIMEOUT_SECONDS - 5}s",
                        "--property=TimeoutStopSec=3s", "--property=KillMode=control-group",
                        "--property=UnsetEnvironment=LD_LIBRARY_PATH LD_PRELOAD",
                        "--setenv=LC_ALL=C", f"--setenv=XDG_RUNTIME_DIR=/run/user/{os.getuid()}",
                        f"--setenv=DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{os.getuid()}/bus",
                        "--", proton_cli.FLATPAK, "run", "--command=python3", proton_cli.PROTON_APP_ID, "-c", launcher, *arguments,
                    ]
                    if arguments[0] in ("connect", "disconnect", "signout") or arguments[:3] == ["config", "set", "kill-switch"]
                    else [proton_cli.FLATPAK, "run", "--command=python3", proton_cli.PROTON_APP_ID, "-c", launcher, *arguments]
                )
                self.assertEqual(run.call_args.args[0], expected)
                self.assertEqual(run.call_args.kwargs["stdin"], subprocess.DEVNULL)
                self.assertEqual(run.call_args.kwargs["timeout"], proton_cli.CLI_TIMEOUT_SECONDS)
                run.assert_called_once()

    def test_network_commands_refuse_root_or_nonstandard_user_bus(self):
        for arguments in (["connect"], ["disconnect"], ["signout"], ["config", "set", "kill-switch", "off"]):
            with self.subTest(arguments=arguments), patch.object(os, "getuid", return_value=0), patch.object(subprocess, "run") as run:
                with self.assertRaisesRegex(RuntimeError, "not root"):
                    proton_cli.run_cli(arguments)
                run.assert_not_called()
            for name in ("XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS"):
                environment = proton_cli.cli_environment()
                environment[name] = "nonstandard"
                with self.subTest(arguments=arguments, name=name), patch.object(proton_cli, "cli_environment", return_value=environment), patch.object(subprocess, "run") as run:
                    with self.assertRaisesRegex(RuntimeError, "standard user bus"):
                        proton_cli.run_cli(arguments)
                    run.assert_not_called()

    def test_launcher_failure_is_sanitized_without_retry(self):
        with patch.object(subprocess, "run", return_value=subprocess.CompletedProcess([], 1, "private-data", "NetworkManager private-data")) as run:
            with self.assertRaises(proton_cli.CLICommandError) as raised:
                proton_cli.run_cli(["connect"])
        self.assertNotIn("private-data", str(raised.exception))
        run.assert_called_once()


class DisconnectCleanupTests(unittest.TestCase):
    def setUp(self):
        async def original(timeout=10):
            raise AssertionError("Unpatched implementation")

        self.original = original
        self.server = types.SimpleNamespace(wait_for_current_tasks=original)

    def install(self):
        digest = hashlib.sha256(inspect.getsource(self.original).encode()).hexdigest()
        with patch.object(cli_compat, "UPSTREAM_TASK_WAIT_SHA256", digest):
            self.assertTrue(cli_compat.install_disconnect_cleanup_fix(self.server))

    def test_cancelled_background_task_does_not_fail_cleanup(self):
        self.install()

        async def scenario():
            background = asyncio.create_task(asyncio.Event().wait())
            background.cancel()
            await self.server.wait_for_current_tasks()
            self.assertTrue(background.cancelled())

        asyncio.run(scenario())

    def test_real_background_failure_is_not_suppressed(self):
        self.install()

        async def failure():
            raise RuntimeError("background failed")

        async def scenario():
            background = asyncio.create_task(failure())
            with self.assertRaisesRegex(RuntimeError, "background failed"):
                await self.server.wait_for_current_tasks()
            self.assertTrue(background.done())

        asyncio.run(scenario())

    def test_cleanup_timeout_is_not_suppressed(self):
        self.install()

        async def scenario():
            background = asyncio.create_task(asyncio.Event().wait())
            with self.assertRaises(asyncio.TimeoutError):
                await self.server.wait_for_current_tasks(timeout=0)
            self.assertTrue(background.cancelled())

        asyncio.run(scenario())

    def test_cancelling_the_command_still_propagates(self):
        self.install()

        async def scenario():
            background = asyncio.create_task(asyncio.Event().wait())
            asyncio.get_running_loop().call_soon(asyncio.current_task().cancel)
            with self.assertRaises(asyncio.CancelledError):
                await self.server.wait_for_current_tasks()
            self.assertTrue(background.cancelled())

        asyncio.run(scenario())

    def test_unknown_or_unreadable_wait_is_unchanged(self):
        self.assertFalse(cli_compat.install_disconnect_cleanup_fix(self.server))
        with patch.object(cli_compat.inspect, "getsource", side_effect=OSError):
            self.assertFalse(cli_compat.install_disconnect_cleanup_fix(self.server))
        self.assertIs(self.server.wait_for_current_tasks, self.original)


class BackendPackagingTests(unittest.TestCase):
    def test_backend_loads_with_only_decky_module_search_path(self):
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            staged = Path(directory)
            shutil.copy2(root / "main.py", staged / "main.py")
            shutil.copytree(root / "py_modules", staged / "py_modules", ignore=shutil.ignore_patterns("__pycache__"))
            subprocess.run(
                [sys.executable, "-I", "-c", """
import importlib.util
import sys
import types
from pathlib import Path

root = Path(sys.argv[1])
sys.path.append(str(root / "py_modules"))
from protonvpn import keyring, proton_cli
assert "decky" not in sys.modules
assert "main" not in sys.modules
assert Path(keyring.__file__).parent == root / "py_modules" / "protonvpn"
assert Path(proton_cli.__file__).parent == root / "py_modules" / "protonvpn"
sys.modules["decky"] = types.ModuleType("decky")
spec = importlib.util.spec_from_file_location("_", root / "main.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
assert callable(module.Plugin().get_status)
assert callable(module.Plugin().start_keyring)
assert module.keyring is keyring
assert module.proton_cli is proton_cli
""", directory],
                cwd=directory, check=True, capture_output=True, text=True, timeout=10,
            )


class SteamDisplayTests(unittest.TestCase):
    def test_discovery_fails_closed_when_scan_is_incomplete(self):
        with patch.object(os, "scandir") as scan, patch.object(keyring.time, "monotonic", return_value=0):
            scan.return_value.__enter__.return_value = iter([types.SimpleNamespace(name="self")] * 4097)
            with self.assertRaisesRegex(RuntimeError, "limit reached"):
                keyring.steam_display_environment()
        with patch.object(os, "scandir") as scan, patch.object(keyring.time, "monotonic", side_effect=[0, 3]):
            scan.return_value.__enter__.return_value = iter([types.SimpleNamespace(name="42")])
            with self.assertRaisesRegex(RuntimeError, "timed out"):
                keyring.steam_display_environment()
        with patch.object(os, "scandir", side_effect=PermissionError("private-data")):
            with self.assertRaisesRegex(RuntimeError, "discovery is unavailable") as raised:
                keyring.steam_display_environment()
            self.assertNotIn("private-data", str(raised.exception))

    def test_reads_only_display_settings_from_the_users_steam_process(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            process = root / "42"
            process.mkdir()
            (process / "comm").write_text("steam\n")
            authority = root / "authority"
            authority.touch()
            (process / "environ").write_bytes(
                f"DISPLAY=:2\0XAUTHORITY={authority}\0TOKEN=private-data\0QT_QPA_PLATFORM=offscreen\0".encode()
            )
            with patch.object(Path, "is_socket", return_value=True) as socket_check:
                self.assertEqual(keyring.steam_display_environment(root), {"DISPLAY": ":2", "XAUTHORITY": str(authority)})
                socket_check.assert_called_once_with()

    def test_refuses_missing_stale_remote_and_ambiguous_displays(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            process = root / "42"
            process.mkdir()
            (process / "comm").write_text("steam\n")
            for raw in (b"TOKEN=private-data\0", b"DISPLAY=host:0\0", b"DISPLAY=:0\0XAUTHORITY=relative\0", b"DISPLAY=:0\0" + b"x" * 131073):
                (process / "environ").write_bytes(raw)
                with self.subTest(raw=raw[:20]), patch.object(Path, "is_socket", return_value=True):
                    with self.assertRaisesRegex(RuntimeError, "No usable Steam display"):
                        keyring.steam_display_environment(root)
            (process / "environ").write_bytes(b"DISPLAY=:0\0")
            with patch.object(Path, "is_socket", return_value=False):
                with self.assertRaisesRegex(RuntimeError, "No usable Steam display"):
                    keyring.steam_display_environment(root)
            with patch.object(Path, "is_socket", return_value=True):
                self.assertEqual(keyring.steam_display_environment(root), {"DISPLAY": ":0"})
            other = root / "43"
            other.mkdir()
            (other / "comm").write_text("steam\n")
            (other / "environ").write_bytes(b"DISPLAY=:1\0")
            with patch.object(Path, "is_socket", return_value=True):
                with self.assertRaisesRegex(RuntimeError, "Multiple Steam displays"):
                    keyring.steam_display_environment(root)

    def test_ignores_other_users_and_other_processes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            process = root / "42"
            process.mkdir()
            (process / "comm").write_text("steam\n")
            (process / "environ").write_bytes(b"DISPLAY=:0\0")
            with patch.object(os, "getuid", return_value=os.getuid() + 1):
                with self.assertRaisesRegex(RuntimeError, "No usable Steam display"):
                    keyring.steam_display_environment(root)
            (process / "comm").write_text("other\n")
            with self.assertRaisesRegex(RuntimeError, "No usable Steam display"):
                keyring.steam_display_environment(root)


class KeyringServiceTests(unittest.TestCase):
    def setUp(self):
        logger = patch.object(main.decky, "logger", create=True)
        self.logger = logger.start()
        self.addCleanup(logger.stop)

    def test_kde_launch_uses_scoped_display_and_preserves_global_environment(self):
        environment = {"XDG_RUNTIME_DIR": "/run/user/1000", "DBUS_SESSION_BUS_ADDRESS": "unix:path=/run/user/1000/bus", "DISPLAY": ":99"}
        before = dict(environment)
        with (
            patch.object(os, "getuid", return_value=1000),
            patch.object(proton_cli, "cli_environment", return_value=environment),
            patch.object(subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "", "")) as run,
        ):
            keyring.start_kde_service({"DISPLAY": ":2", "XAUTHORITY": "/user/authority", "TOKEN": "private-data"})
        command = run.call_args.args[0]
        self.assertEqual(command[:4], [keyring.SYSTEMD_RUN, "--user", "--collect", "--quiet"])
        self.assertEqual(command[-1], keyring.KSECRET_SERVICE)
        for argument in ("--setenv=DISPLAY=:2", "--setenv=XAUTHORITY=/user/authority", "--setenv=QT_QPA_PLATFORM=xcb", "--property=Type=dbus", "--property=BusName=org.freedesktop.secrets", "--property=TimeoutStartSec=10s", "--property=Restart=no"):
            self.assertIn(argument, command)
        self.assertNotIn("private-data", str(run.call_args))
        self.assertNotIn("offscreen", str(run.call_args))
        self.assertEqual(run.call_args.kwargs["timeout"], 15)
        self.assertEqual(run.call_args.kwargs["stdin"], subprocess.DEVNULL)
        self.assertEqual(environment, before)

    def test_kde_launch_refuses_root_custom_bus_and_redacts_failures(self):
        with patch.object(os, "getuid", return_value=0), patch.object(subprocess, "run") as run:
            with self.assertRaisesRegex(RuntimeError, "not root"):
                keyring.start_kde_service({"DISPLAY": ":0"})
            run.assert_not_called()
        with patch.object(os, "getuid", return_value=1000), patch.object(proton_cli, "cli_environment", return_value={}), patch.object(subprocess, "run") as run:
            with self.assertRaisesRegex(RuntimeError, "standard user bus"):
                keyring.start_kde_service({"DISPLAY": ":0"})
            run.assert_not_called()
        environment = {"XDG_RUNTIME_DIR": "/run/user/1000", "DBUS_SESSION_BUS_ADDRESS": "unix:path=/run/user/1000/bus"}
        for failure in (OSError("private-data"), subprocess.TimeoutExpired([], 15, output="private-data"), None):
            with (
                self.subTest(failure=type(failure).__name__),
                patch.object(os, "getuid", return_value=1000),
                patch.object(proton_cli, "cli_environment", return_value=environment),
                patch.object(subprocess, "run", side_effect=failure, return_value=subprocess.CompletedProcess([], 1, "private-data", "private-data")) as run,
            ):
                with self.assertRaises(RuntimeError) as raised:
                    keyring.start_kde_service({"DISPLAY": ":0"})
                self.assertNotIn("private-data", str(raised.exception))
                self.assertIn("XAUTHORITY", next(argument for argument in run.call_args.args[0] if argument.startswith("--property=UnsetEnvironment=")))

    def test_kde_activation_uses_steam_display_instead_of_broken_dbus_startup(self):
        with (
            patch.object(os, "getuid", return_value=1000),
            patch.object(keyring, "user_bus_call", side_effect=[set(), {"org.kde.secretservicecompat"}]) as bus,
            patch.object(keyring, "steam_display_environment", return_value={"DISPLAY": ":2"}),
            patch.object(keyring, "start_kde_service") as start,
            patch.object(main, "_get_status", return_value={"signed_in": True, "connected": False}) as verify,
        ):
            result = main._start_keyring_service()
        start.assert_called_once_with({"DISPLAY": ":2"})
        verify.assert_called_once_with()
        self.assertEqual(bus.call_count, 2)
        self.assertNotIn("error", result)
        self.assertIn("startup completed", result["diagnostics"]["Keyring activation stage"])
        self.logger.info.assert_called_once()

    def test_missing_display_does_not_launch_kde_or_fall_back_to_crashing_activation(self):
        with (
            patch.object(os, "getuid", return_value=1000),
            patch.object(keyring, "user_bus_call", side_effect=[set(), {"org.kde.secretservicecompat"}]) as bus,
            patch.object(keyring, "steam_display_environment", side_effect=RuntimeError("No usable Steam display")),
            patch.object(keyring, "start_kde_service") as start,
        ):
            failure, report = keyring.start_service()
        self.assertEqual(failure, "No usable Steam display")
        self.assertEqual(report["Keyring activation stage"], "finding Steam display")
        self.assertIn("not attempted", report["KDE startup log"])
        start.assert_not_called()
        self.assertEqual(bus.call_count, 2)

    def test_failed_scoped_kde_launch_keeps_startup_evidence_and_does_not_retry(self):
        with (
            patch.object(os, "getuid", return_value=1000),
            patch.object(keyring, "user_bus_call", side_effect=[set(), {"org.kde.secretservicecompat"}]) as bus,
            patch.object(keyring, "steam_display_environment", return_value={"DISPLAY": ":2"}),
            patch.object(keyring, "start_kde_service", side_effect=RuntimeError("KDE startup failed")) as start,
            patch.object(keyring, "startup_diagnostics", return_value={"KDE startup log": "Qt could not connect to a display"}),
            patch.object(main, "_get_status", return_value={"signed_in": True, "connected": None, "error": "Secret Service unavailable"}),
        ):
            result = main._start_keyring_service()
        self.assertEqual(result["error"], "KDE startup failed")
        self.assertTrue(result["signed_in"])
        self.assertEqual(result["diagnostics"]["Keyring activation stage"], "starting KDE on Steam display")
        self.assertEqual(result["diagnostics"]["KDE startup log"], "Qt could not connect to a display")
        self.assertIn("Qt could not connect", str(self.logger.info.call_args))
        start.assert_called_once_with({"DISPLAY": ":2"})
        self.assertEqual(bus.call_count, 2)

    def test_startup_log_is_scoped_bounded_and_only_reports_fixed_findings(self):
        output = "\n".join(json.dumps({"MESSAGE": message, "_HOSTNAME": "private-data"}) for message in (
            "qt.qpa.xcb: could not connect to display private-data",
            "No Qt platform plugin could be initialized. private-data",
            "private-data",
        ))
        with (
            patch.object(os, "getuid", return_value=1000),
            patch.object(subprocess, "run", return_value=subprocess.CompletedProcess([], 0, output, "private-data")) as run,
        ):
            report = keyring.startup_diagnostics(1234.5)
        self.assertEqual(report, {"KDE startup log": "Qt could not connect to a display; Qt platform initialization failed"})
        command = run.call_args.args[0]
        self.assertEqual(command[0], keyring.JOURNALCTL)
        for argument in ("--boot", "--since=@1234.500000", "--lines=40", "--output=json", "--output-fields=MESSAGE", "_UID=1000", "_COMM=ksecretd"):
            self.assertIn(argument, command)
        self.assertNotIn("+", command)
        self.assertEqual(run.call_args.kwargs["timeout"], 6)
        self.assertEqual(run.call_args.kwargs["stdin"], subprocess.DEVNULL)
        self.assertTrue(run.call_args.kwargs["start_new_session"])
        self.assertNotIn("private-data", json.dumps(report))

    def test_startup_log_does_not_treat_missing_evidence_as_success(self):
        for output, expected in (
            ("", "no matching entries"),
            ("private-data", "unreadable entries"),
            ('{"MESSAGE":42}', "unreadable entries"),
            ('{"MESSAGE":"private-data"}', "no recognized failure in recent entries"),
            ('{"MESSAGE":"ksecretd is disabled! private-data"}', "KDE wallet disabled in configuration"),
        ):
            with self.subTest(output=output), patch.object(subprocess, "run", return_value=subprocess.CompletedProcess([], 0, output, "private-data")):
                self.assertEqual(keyring.startup_diagnostics(1234), {"KDE startup log": expected})
        for failure, expected in (
            (OSError("private-data"), "unavailable"),
            (subprocess.TimeoutExpired([], 6, output="private-data"), "check timed out"),
        ):
            with self.subTest(failure=type(failure).__name__), patch.object(subprocess, "run", side_effect=failure):
                self.assertEqual(keyring.startup_diagnostics(1234), {"KDE startup log": expected})
        with patch.object(subprocess, "run", return_value=subprocess.CompletedProcess([], 1, "private-data", "private-data")):
            self.assertEqual(keyring.startup_diagnostics(1234), {"KDE startup log": "unavailable"})

    def test_user_bus_errors_never_expose_raw_output(self):
        for stderr, message in (
            ("org.freedesktop.DBus.Error.ServiceUnknown: private-data", "service not registered"),
            ("org.freedesktop.DBus.Error.AccessDenied: private-data", "access denied"),
            ("org.freedesktop.DBus.Error.NoReply: private-data", "service did not respond"),
            ("org.freedesktop.DBus.Error.Spawn.ChildExited: private-data", "service exited during startup"),
            ("Call failed: Process org.kde.secretservicecompat received signal 6 private-data", "service terminated by a signal during startup; signal 6"),
            ("org.freedesktop.DBus.Error.Spawn.ChildSignaled: private-data", "service terminated by a signal during startup"),
            ("Call failed: Failed to execute program /private-data: No such file or directory", "service executable could not be started"),
            ("Process private-data exited abnormally", "service exited abnormally during startup"),
            ("private-data", "service operation failed"),
        ):
            with self.subTest(stderr=stderr), patch.object(subprocess, "run", return_value=subprocess.CompletedProcess([], 1, "private-data", stderr)):
                with self.assertRaisesRegex(RuntimeError, message) as raised:
                    keyring.user_bus_call("ListNames")
                self.assertNotIn("private-data", str(raised.exception))
        for failure in (OSError("private-data"), subprocess.TimeoutExpired([], 6, output="private-data")):
            with self.subTest(failure=type(failure).__name__), patch.object(subprocess, "run", side_effect=failure):
                with self.assertRaises(RuntimeError) as raised:
                    keyring.user_bus_call("ListNames")
                self.assertNotIn("private-data", str(raised.exception))

    def test_user_bus_rejects_malformed_replies_and_arbitrary_activation(self):
        for method, output in (
            ("ListNames", "private-data"),
            ("ListNames", "[]"),
            ("ListNames", '{"type":"as","data":[[42]]}'),
            ("ListNames", '{"type":"s","data":["private-data"]}'),
            ("StartServiceByName", '{"type":"u","data":[true]}'),
            ("StartServiceByName", '{"type":"u","data":[3]}'),
        ):
            with self.subTest(output=output), patch.object(subprocess, "run", return_value=subprocess.CompletedProcess([], 0, output, "")):
                with self.assertRaisesRegex(RuntimeError, "invalid response"):
                    keyring.user_bus_call(method, "org.kde.kwalletd6" if method == "StartServiceByName" else None)
        with patch.object(subprocess, "run") as run:
            with self.assertRaises(ValueError):
                keyring.user_bus_call("StartServiceByName", "org.example.unknown")
            with self.assertRaises(ValueError):
                keyring.user_bus_call("UpdateActivationEnvironment")
            run.assert_not_called()

    def test_failed_service_activation_is_preserved_after_status_refresh(self):
        with (
            patch.object(os, "getuid", return_value=1000),
            patch.object(keyring.time, "time", return_value=1234.5),
            patch.object(keyring, "startup_diagnostics", return_value={"KDE startup log": "Qt could not connect to a display"}) as startup,
            patch.object(keyring, "user_bus_call", side_effect=[set(), {"org.kde.kwalletd6"}, RuntimeError("service exited during startup")]),
            patch.object(main, "_get_status", return_value={"signed_in": True, "connected": None, "error": "Secret Service unavailable"}),
        ):
            report = main._start_keyring_service()
        self.assertTrue(report["signed_in"])
        self.assertEqual(report["error"], "service exited during startup")
        self.assertEqual(report["diagnostics"]["Service activation result"], "failed")
        self.assertEqual(report["diagnostics"]["KDE startup log"], "Qt could not connect to a display")
        startup.assert_called_once_with(1234.5)

    def test_start_keyring_rpc_serializes_operations_and_returns_expected_errors(self):
        with patch.object(main, "_cli_operation", return_value={"signed_in": True}) as operation:
            self.assertEqual(asyncio.run(main.Plugin().start_keyring()), {"signed_in": True})
            operation.assert_called_once_with(main._start_keyring_service)
        with patch.object(main, "_cli_operation", side_effect=RuntimeError("operation in progress")):
            report = asyncio.run(main.Plugin().start_keyring())
        self.assertEqual(report["error"], "operation in progress")
        self.assertIsNone(report["signed_in"])

    def test_host_bus_calls_are_structured_bounded_and_private(self):
        for method, response, expected in (
            ("ListNames", {"type": "as", "data": [["org.freedesktop.secrets"]]}, {"org.freedesktop.secrets"}),
            ("ListActivatableNames", {"type": "as", "data": [[]]}, set()),
            ("StartServiceByName", {"type": "u", "data": [1]}, set()),
            ("StartServiceByName", {"type": "u", "data": [2]}, set()),
        ):
            with self.subTest(method=method), patch.object(subprocess, "run", return_value=subprocess.CompletedProcess([], 0, json.dumps(response), "private-data")) as run:
                self.assertEqual(keyring.user_bus_call(method, "org.kde.kwalletd6" if method == "StartServiceByName" else None), expected)
                command = run.call_args.args[0]
                self.assertEqual(command[:4], [keyring.BUSCTL, "--user", "--timeout=5", "--json=short"])
                self.assertEqual(run.call_args.kwargs["timeout"], 6)
                self.assertEqual(run.call_args.kwargs["stdin"], subprocess.DEVNULL)
                self.assertTrue(run.call_args.kwargs["start_new_session"])
                if method == "StartServiceByName":
                    self.assertEqual(command[-3:], ["su", "org.kde.kwalletd6", "0"])

    def test_activation_uses_existing_provider_and_verifies_proton(self):
        for service in ("org.kde.kwalletd6", "org.kde.kwalletd5", "org.gnome.keyring", "org.freedesktop.secrets"):
            status = {"installed": True, "signed_in": True, "connected": False}
            with (
                self.subTest(service=service),
                patch.object(os, "getuid", return_value=1000),
                patch.object(keyring, "user_bus_call", side_effect=[set(), {service}, set()]) as bus,
                patch.object(main, "_get_status", return_value=status) as get_status,
            ):
                self.assertEqual(main._start_keyring_service(), status)
                self.assertEqual(bus.call_args_list, [call("ListNames"), call("ListActivatableNames"), call("StartServiceByName", service)])
                get_status.assert_called_once_with()

    def test_activation_never_replaces_running_service(self):
        with (
            patch.object(os, "getuid", return_value=1000),
            patch.object(keyring, "startup_diagnostics") as startup,
            patch.object(keyring, "user_bus_call", return_value={"org.freedesktop.secrets"}) as bus,
            patch.object(main, "_get_status", return_value={"signed_in": True}),
        ):
            main._start_keyring_service()
            bus.assert_called_once_with("ListNames")
            startup.assert_not_called()

    def test_activation_refuses_root_missing_or_ambiguous_providers(self):
        with patch.object(os, "getuid", return_value=0), patch.object(keyring, "user_bus_call") as bus:
            self.assertIn("not root", main._start_keyring_service()["error"])
            bus.assert_not_called()
        for names in (set(), {"org.kde.kwalletd6", "org.gnome.keyring"}):
            with (
                self.subTest(names=names),
                patch.object(os, "getuid", return_value=1000),
                patch.object(keyring, "user_bus_call", side_effect=[set(), names]) as bus,
                patch.object(main, "_get_status", return_value={"signed_in": True}),
            ):
                result = main._start_keyring_service()
                self.assertTrue(result["signed_in"])
                self.assertIn("error", result)
                self.assertEqual(bus.call_count, 2)

    def test_failed_proton_verification_is_not_reported_as_repaired(self):
        with (
            patch.object(os, "getuid", return_value=1000),
            patch.object(keyring, "user_bus_call", side_effect=[set(), {"org.kde.kwalletd6"}, set()]),
            patch.object(main, "_get_status", return_value={"signed_in": True, "connected": None, "error": "keyring locked"}),
        ):
            result = main._start_keyring_service()
        self.assertEqual(result["error"], "keyring locked")
        self.assertIn("verification failed", result["diagnostics"]["Service activation result"])

    def test_host_diagnostics_filter_names_and_only_offer_unambiguous_activation(self):
        for available, expected in (
            ({"org.example.private-data", "org.kde.secretservicecompat"}, "available"),
            ({"org.example.private-data"}, "unavailable"),
            ({"org.kde.kwalletd6", "org.gnome.keyring"}, "unavailable"),
        ):
            with (
                self.subTest(available=available),
                patch.object(os, "getuid", return_value=1000),
                patch.object(keyring, "user_bus_call", side_effect=[set(), available]),
            ):
                report = keyring.host_diagnostics()
                self.assertEqual(report["Keyring service activation"], expected)
                self.assertNotIn("private-data", json.dumps(report))

    def test_select_existing_keyring_service_without_guessing(self):
        for names, expected in (
            ({"org.freedesktop.secrets", "org.kde.kwalletd6", "org.gnome.keyring"}, "org.freedesktop.secrets"),
            ({"org.kde.secretservicecompat", "org.kde.kwalletd6"}, "org.kde.secretservicecompat"),
            ({"org.kde.kwalletd5", "org.kde.kwalletd6"}, "org.kde.kwalletd6"),
            ({"org.kde.kwalletd5"}, "org.kde.kwalletd5"),
            ({"org.gnome.keyring"}, "org.gnome.keyring"),
            ({"org.example.unknown"}, None),
        ):
            with self.subTest(names=names):
                self.assertEqual(keyring.select_service(names), expected)
        with self.assertRaisesRegex(RuntimeError, "Multiple keyring providers"):
            keyring.select_service({"org.kde.kwalletd6", "org.gnome.keyring"})


class KeyringDiagnosticTests(unittest.TestCase):
    def setUp(self):
        for mocked in (patch.object(keyring, "ensure_service"), patch.object(proton_cli, "tunnel_active", return_value=None)):
            mocked.start()
            self.addCleanup(mocked.stop)

    def run_probe(self, *, names=None, activatable=None, locked=False, collection_error=None, bus_error=None):
        storage = types.ModuleType("secretstorage")
        storage.ItemNotFoundException = type("ItemNotFoundException", (Exception,), {})
        storage.SecretServiceNotAvailableException = type("SecretServiceNotAvailableException", (Exception,), {})
        connection = Mock(spec=["close"])
        storage.dbus_init = Mock(return_value=connection, side_effect=bus_error)
        collection = Mock(spec=["is_locked"])
        collection.is_locked.return_value = locked
        errors = {
            "missing": storage.ItemNotFoundException,
            "unavailable": storage.SecretServiceNotAvailableException,
            "unexpected": RuntimeError,
        }
        storage.Collection = Mock(return_value=collection, side_effect=errors[collection_error]("private-data") if collection_error else None)
        bus = Mock(spec=["ListNames", "ListActivatableNames", "GetNameOwner"])
        bus.ListNames.return_value = (names or [],)
        bus.ListActivatableNames.return_value = (activatable or [],)
        bus.GetNameOwner.return_value = (":1.42",)
        bus_messages = types.ModuleType("jeepney.bus_messages")
        bus_messages.message_bus = object()
        blocking = types.ModuleType("jeepney.io.blocking")
        blocking.Proxy = Mock(return_value=bus)
        output = io.StringIO()
        with (
            patch.object(metadata, "entry_points", return_value=[types.SimpleNamespace(name="secret_service"), types.SimpleNamespace(name="private-driver")]),
            patch.object(metadata, "version", return_value="1.2.3"),
            patch.dict(sys.modules, {
                "secretstorage": storage,
                "jeepney": types.ModuleType("jeepney"),
                "jeepney.io": types.ModuleType("jeepney.io"),
                "jeepney.bus_messages": bus_messages,
                "jeepney.io.blocking": blocking,
            }),
            redirect_stdout(output),
        ):
            exec(compile(keyring.KEYRING_PROBE_CODE, "keyring-probe", "exec"), {})
        self.assertNotIn("private-data", output.getvalue())
        if bus_error:
            connection.close.assert_not_called()
        else:
            connection.close.assert_called_once_with()
        self.assertTrue(collection.method_calls in ([], [call.is_locked()]))
        report = json.loads(output.getvalue())
        self.assertEqual(report.pop("drivers"), ["other", "secret_service"])
        self.assertEqual(report.pop("cli_version"), "1.2.3")
        self.assertEqual(report.pop("keyring_version"), "1.2.3")
        return report, storage, bus

    def test_probe_running_provider_and_lock_state(self):
        for name, provider in (
            ("org.kde.kwalletd5", "KWallet"),
            ("org.kde.kwalletd6", "KWallet"),
            ("org.gnome.keyring", "GNOME Keyring"),
            ("org.example.other", "other"),
        ):
            for locked in (True, False):
                with self.subTest(provider=name, locked=locked):
                    report, storage, _ = self.run_probe(names=["org.freedesktop.secrets", name], locked=locked)
                    self.assertEqual(report, {"bus": "reachable", "service": "running", "provider": provider, "collection": "locked" if locked else "unlocked"})
                    storage.Collection.assert_called_once()

    def test_probe_does_not_start_inactive_or_absent_service(self):
        for activatable, expected in ((["org.freedesktop.secrets"], "inactive"), ([], "absent")):
            with self.subTest(expected=expected):
                report, storage, bus = self.run_probe(activatable=activatable)
                self.assertEqual(report, {"bus": "reachable", "service": expected})
                storage.Collection.assert_not_called()
                bus.GetNameOwner.assert_not_called()

    def test_probe_collection_and_bus_failures_are_private(self):
        for failure, expected in (("missing", "missing"), ("unavailable", "unavailable"), ("unexpected", "check failed")):
            with self.subTest(failure=failure):
                report, _, _ = self.run_probe(names=["org.freedesktop.secrets"], collection_error=failure)
                self.assertEqual(report["collection"], expected)
        report, storage, _ = self.run_probe(bus_error=RuntimeError("private-data"))
        self.assertEqual(report, {"bus": "unreachable"})
        storage.Collection.assert_not_called()

    def test_probe_missing_dependencies_are_reported(self):
        output = io.StringIO()
        with (
            patch.dict(sys.modules, {"secretstorage": None}),
            patch.object(metadata, "entry_points", side_effect=RuntimeError("private-data")),
            redirect_stdout(output),
        ):
            exec(keyring.KEYRING_PROBE_CODE, {})
        self.assertEqual(json.loads(output.getvalue()), {"probe": "dependencies missing"})

    def test_diagnostics_compare_user_bus_without_mutating_environment(self):
        for inherited_bus, expected_calls in (("unix:path=/run/user/1000/bus", 1), ("unix:path=/private/bus", 2)):
            inherited = {"XDG_RUNTIME_DIR": "/run/user/1000", "DBUS_SESSION_BUS_ADDRESS": inherited_bus, "HOME": "private-home", "DISPLAY": "private-display"}
            before = dict(inherited)
            with (
                self.subTest(inherited_bus=inherited_bus),
                patch.object(os, "getuid", return_value=1000),
                patch.object(proton_cli, "cli_environment", return_value=inherited),
                patch.object(keyring, "host_diagnostics", return_value={}),
                patch.object(keyring, "probe_keyring", return_value={"bus": "reachable", "collection": "locked"}) as probe,
            ):
                report = keyring.diagnostics()
                self.assertEqual(probe.call_count, expected_calls)
                self.assertEqual(probe.call_args.args[0]["DBUS_SESSION_BUS_ADDRESS"], "unix:path=/run/user/1000/bus")
                self.assertEqual(report["Default collection"], "locked")
                self.assertEqual(inherited, before)
                self.assertNotIn("private", json.dumps(report))

    def test_probe_timeout_and_launch_errors_are_private(self):
        for failure, expected in (
            (subprocess.TimeoutExpired([], 10, output="private-data"), "timed out"),
            (OSError("private-data"), "unavailable"),
        ):
            with self.subTest(expected=expected), patch.object(subprocess, "run", side_effect=failure):
                self.assertEqual(keyring.probe_keyring({}), {"probe": expected})

    def test_status_failure_attaches_diagnostics_without_signing_in_again(self):
        for category in ("keyring error", "keyring locked", "keyring unlock dismissed", "keyring backend unavailable", "Secret Service unavailable"):
            failure = proton_cli.CLICommandError("status failed", category)
            with (
                self.subTest(category=category),
                patch.object(proton_cli, "flatpak_installed", return_value=True),
                patch.object(proton_cli, "run_cli", side_effect=failure) as cli,
                patch.object(keyring, "diagnostics", return_value={"Default collection": "locked"}) as probe,
                patch.object(main.decky, "logger", create=True) as logger,
            ):
                report = main._get_status()
                self.assertIsNone(report["signed_in"])
                self.assertIsNone(report["connected"])
                self.assertEqual(report["diagnostics"], {"Default collection": "locked", "CLI exception types": "not reported"})
                self.assertEqual(cli.call_args_list, [call(["panel-snapshot"])])
                probe.assert_called_once_with()
                logger.warning.assert_called_once()
                self.assertNotIn("private", str(logger.warning.call_args))
                self.assertNotIn("private", json.dumps(report))

    def test_broken_diagnostics_do_not_hide_original_failure(self):
        with (
            patch.object(proton_cli, "flatpak_installed", return_value=True),
            patch.object(proton_cli, "signed_in", return_value=True),
            patch.object(proton_cli, "run_cli", side_effect=proton_cli.CLICommandError("status failed", "keyring error")),
            patch.object(keyring, "diagnostics", side_effect=RuntimeError("private-data")),
            patch.object(main.decky, "logger", create=True),
        ):
            report = main._get_status()
        self.assertEqual(report["error"], "status failed")
        self.assertEqual(report["diagnostics"], {"Probe": "unavailable", "CLI exception types": "not reported"})
        self.assertNotIn("private", json.dumps(report))


class ProtonCLITests(unittest.TestCase):
    def setUp(self):
        for mocked in (
            patch.object(keyring, "ensure_service", wraps=keyring.ensure_service),
            patch.object(keyring, "user_bus_call", return_value=["org.freedesktop.secrets"]),
            patch.object(proton_cli, "tunnel_active", return_value=None),
        ):
            mocked.start()
            self.addCleanup(mocked.stop)

    def test_keyring_metadata_and_exception_identifiers_are_allowlisted(self):
        output = json.dumps({"drivers": ["json", "secret_service"], "cli_version": "1.2.3", "keyring_version": "private-data"})
        with patch.object(subprocess, "run", return_value=subprocess.CompletedProcess([], 0, output, "")):
            self.assertEqual(keyring.probe_keyring({}), {"drivers": "json, secret_service", "cli_version": "1.2.3"})
        with patch.object(subprocess, "run", return_value=subprocess.CompletedProcess([], 1, "", "keyring.errors.InitError: private-data org.freedesktop.DBus.Error.NoReply")):
            with self.assertRaises(proton_cli.CLICommandError) as raised:
                proton_cli.run_cli(["status"])
        self.assertEqual(raised.exception.identifiers, "InitError, NoReply")
        self.assertNotIn("private", str(raised.exception))

    def test_keyring_probe_accepts_only_fixed_diagnostic_values(self):
        output = json.dumps({
            "bus": "reachable", "service": "running", "provider": "KWallet",
            "collection": "locked", "private-token": "private-data",
        })
        with patch.object(subprocess, "run", return_value=subprocess.CompletedProcess([], 0, output, "private-data")) as run:
            report = keyring.probe_keyring({"LC_ALL": "C"})
        self.assertEqual(report, {
            "bus": "reachable", "service": "running", "provider": "KWallet",
            "collection": "locked",
        })
        self.assertNotIn("private", json.dumps(report))
        self.assertEqual(run.call_args.kwargs["timeout"], 10)
        self.assertEqual(run.call_args.kwargs["env"], {"LC_ALL": "C"})
        self.assertEqual(run.call_args.kwargs["stdin"], subprocess.DEVNULL)

    def test_keyring_probe_failure_never_exposes_output(self):
        for result in (
            subprocess.CompletedProcess([], 1, "private-data", "private-data"),
            subprocess.CompletedProcess([], 0, "private-data", ""),
            subprocess.CompletedProcess([], 0, json.dumps({"bus": "private-data"}), ""),
            subprocess.CompletedProcess([], 0, "[]", ""),
        ):
            with self.subTest(result=result), patch.object(subprocess, "run", return_value=result):
                self.assertEqual(keyring.probe_keyring({}), {"probe": "unavailable"})

    def test_keyring_failure_categories_do_not_expose_secrets(self):
        for output, category in (
            ("keyring.errors.KeyringLocked: private-data", "keyring locked"),
            ("secretstorage.exceptions.LockedException: private-data", "keyring locked"),
            ("SecretService: The collection was dismissed. private-data", "keyring unlock dismissed"),
            ("keyring.errors.NoKeyringError: private-data", "keyring backend unavailable"),
            ("secretstorage.exceptions.SecretServiceNotAvailableException: private-data", "Secret Service unavailable"),
            ("org.freedesktop.secrets org.freedesktop.DBus.Error.ServiceUnknown private-data", "Secret Service unavailable"),
            ("keyring.errors.KeyringError: private-data", "keyring error"),
        ):
            with self.subTest(category=category):
                self.assertEqual(proton_cli.command_failure_category(output), category)

    def test_cli_errors_identify_stage_and_redact_raw_output(self):
        for arguments, stderr, stage, category in (
            (["info"], "secretservice private-data", "account check", "keyring error"),
            (["status"], "NetworkManager private-data", "connection status", "NetworkManager error"),
            (["countries", "list"], "no such command private-data", "country list", "unsupported command"),
        ):
            with (
                self.subTest(arguments=arguments),
                patch.object(subprocess, "run", return_value=subprocess.CompletedProcess([], 1, "", stderr)),
            ):
                with self.assertRaises(RuntimeError) as raised:
                    proton_cli.run_cli(arguments)
                message = str(raised.exception)
                self.assertIn(stage, message)
                self.assertIn(category, message)
                self.assertIn("exit 1", message)
                self.assertNotIn("private-data", message)

    def test_status_failure_preserves_confirmed_signin(self):
        with (
            patch.object(proton_cli, "flatpak_installed", return_value=True),
            patch.object(proton_cli, "run_cli", return_value=json.dumps({"signed_in": True})),
            patch.object(proton_cli, "connection_status", return_value={"connected": None, "tunnel_active": None, "error": "status failed"}),
        ):
            result = main._get_status()
        self.assertTrue(result["signed_in"])
        self.assertIsNone(result["connected"])
        self.assertEqual(result["error"], "status failed")

    def test_failed_account_check_is_not_signed_out(self):
        with (
            patch.object(proton_cli, "flatpak_installed", return_value=True),
            patch.object(proton_cli, "run_cli", side_effect=RuntimeError("account check failed")),
        ):
            result = main._get_status()
        self.assertIsNone(result["signed_in"])
        self.assertIsNone(result["connected"])

    def test_frozen_environment_restores_original_library_path(self):
        inherited = {
            "LD_LIBRARY_PATH": "/tmp/_MEIdecky:/system/libs",
            "LD_LIBRARY_PATH_ORIG": "/system/libs",
            "DBUS_SESSION_BUS_ADDRESS": "unix:path=/run/user/1000/bus",
            "XDG_RUNTIME_DIR": "/run/user/1000",
            "HOME": "/home/deck",
        }
        with (
            patch.dict(os.environ, inherited, clear=True),
            patch.object(sys, "frozen", True, create=True),
        ):
            environment = proton_cli.cli_environment()
            self.assertEqual(environment["LD_LIBRARY_PATH"], "/system/libs")
            self.assertNotIn("LD_LIBRARY_PATH_ORIG", environment)
            self.assertEqual(environment["DBUS_SESSION_BUS_ADDRESS"], inherited["DBUS_SESSION_BUS_ADDRESS"])
            self.assertEqual(environment["XDG_RUNTIME_DIR"], inherited["XDG_RUNTIME_DIR"])
            self.assertEqual(environment["HOME"], inherited["HOME"])
            self.assertEqual(dict(os.environ), inherited)

    def test_frozen_environment_removes_library_path_without_original(self):
        for original in ({}, {"LD_LIBRARY_PATH_ORIG": ""}):
            with (
                self.subTest(original=original),
                patch.dict(os.environ, {"LD_LIBRARY_PATH": "/tmp/_MEIdecky", **original}, clear=True),
                patch.object(sys, "frozen", True, create=True),
            ):
                self.assertNotIn("LD_LIBRARY_PATH", proton_cli.cli_environment())

    def test_unfrozen_environment_preserves_custom_library_path(self):
        with (
            patch.dict(os.environ, {"LD_LIBRARY_PATH": "/custom/libs"}, clear=True),
            patch.object(sys, "frozen", False, create=True),
        ):
            self.assertEqual(proton_cli.cli_environment()["LD_LIBRARY_PATH"], "/custom/libs")

    def test_flatpak_failure_identifies_category_without_echoing_output(self):
        for stderr, category in (
            ("symbol lookup error: private diagnostic", "shared-library error"),
            ("error while loading shared libraries: private diagnostic", "shared-library error"),
            ("Permission denied: private diagnostic", "permission denied"),
            ("Failed to connect to D-Bus: private diagnostic", "D-Bus error"),
            ("Unknown option --columns: private diagnostic", "unsupported option"),
            ("private diagnostic", "unclassified error"),
        ):
            with (
                self.subTest(category=category),
                patch.object(subprocess, "run", return_value=subprocess.CompletedProcess([], 1, "", stderr)),
            ):
                with self.assertRaises(RuntimeError) as raised:
                    proton_cli.flatpak_installed()
                self.assertIn(category, str(raised.exception))
                self.assertIn("exit 1", str(raised.exception))
                self.assertNotIn("private diagnostic", str(raised.exception))

    def test_detection_error_returns_unknown_installation_status(self):
        with (
            patch.object(proton_cli, "flatpak_installed", side_effect=RuntimeError("Flatpak check failed")),
            patch.object(proton_cli, "run_cli") as run_cli,
        ):
            result = main._get_status()
            countries = main._get_countries()
        self.assertIsNone(result["installed"])
        self.assertEqual(result["error"], "Flatpak check failed")
        self.assertNotIn("error", countries)
        self.assertTrue(countries["countries"])
        run_cli.assert_not_called()

    def test_flatpak_detection_checks_application_list(self):
        with patch.object(
            subprocess, "run",
            return_value=subprocess.CompletedProcess([], 0, "com.protonvpn.www\n", ""),
        ) as run:
            self.assertTrue(proton_cli.flatpak_installed())
        self.assertEqual(run.call_args.args[0], [proton_cli.FLATPAK, "list", "--app", "--columns=application"])

    def test_flatpak_detection_reports_absence_only_after_successful_query(self):
        with patch.object(
            subprocess, "run",
            return_value=subprocess.CompletedProcess([], 0, "org.example.Other\n", ""),
        ):
            self.assertFalse(proton_cli.flatpak_installed())

    def test_flatpak_detection_does_not_hide_failures_as_missing_app(self):
        failures = [
            FileNotFoundError(), PermissionError(),
            subprocess.TimeoutExpired([proton_cli.FLATPAK], 10),
        ]
        for failure in failures:
            with self.subTest(failure=type(failure).__name__), patch.object(subprocess, "run", side_effect=failure):
                with self.assertRaises(RuntimeError):
                    proton_cli.flatpak_installed()
        with patch.object(
            subprocess, "run",
            return_value=subprocess.CompletedProcess([], 1, "", "private diagnostic"),
        ):
            with self.assertRaisesRegex(RuntimeError, "Flatpak") as raised:
                proton_cli.flatpak_installed()
            self.assertNotIn("private diagnostic", str(raised.exception))

    def test_parse_status_extracts_connection_details(self):
        status = proton_cli.parse_status(
            "Status: Connected\nServer: US-CA#856 in San Jose, United States\n"
            "Load: 48%\nProtocol: wireguard"
        )
        self.assertEqual(
            status,
            {
                "connected": True,
                "server": "US-CA#856 in San Jose, United States",
                "protocol": "wireguard",
            },
        )

    def test_parse_countries_skips_heading_and_parses_names(self):
        countries = proton_cli.parse_countries(
            "Country                           Code\n"
            "--------------------------------  ------\n"
            "Canada                            CA\n"
            "United States                     US\n"
        )
        self.assertEqual(
            countries,
            [
                {"name": "Canada", "code": "CA"},
                {"name": "United States", "code": "US"},
            ],
        )

    def test_status_does_not_return_account_name(self):
        with (
            patch.object(proton_cli, "flatpak_installed", return_value=True),
            patch.object(
                proton_cli,
                "run_cli",
                return_value=json.dumps({"signed_in": True, "account": "user@example.com", "settings": {"kill-switch": "off"}}),
            ),
            patch.object(proton_cli, "connection_status", return_value={"connected": True, "tunnel_active": True}),
        ):
            status = main._get_status()

        self.assertTrue(status["signed_in"])
        self.assertTrue(status["connected"])
        self.assertNotIn("user@example.com", str(status))

    def test_status_detects_cli_signed_out(self):
        with (
            patch.object(proton_cli, "flatpak_installed", return_value=True),
            patch.object(
                proton_cli,
                "run_cli",
                return_value=json.dumps({"signed_in": False}),
            ),
        ):
            status = main._get_status()

        self.assertIs(status["signed_in"], False)
        self.assertIsNone(status["connected"])

    def test_missing_app_returns_install_guidance_state(self):
        with (
            patch.object(proton_cli, "flatpak_installed", return_value=False),
            patch.object(proton_cli, "run_cli") as run_cli,
        ):
            status = main._get_status()

        self.assertFalse(status["installed"])
        run_cli.assert_not_called()

    def test_get_countries_is_bundled_without_any_subprocess(self):
        with (
            patch.object(subprocess, "run") as run,
            patch.object(proton_cli, "run_cli") as run_cli,
        ):
            result = main._get_countries()

        run.assert_not_called()
        run_cli.assert_not_called()
        self.assertIn({"name": "Canada", "code": "CA"}, result["countries"])
        self.assertTrue(all(re.fullmatch(r"[A-Z]{2}", country["code"]) for country in result["countries"]))

    def test_connect_country_validates_then_calls_cli(self):
        with (
            patch.object(proton_cli, "flatpak_installed", return_value=True),
            patch.object(proton_cli, "signed_in", return_value=True),
            patch.object(
                main,
                "_get_countries",
                return_value={"signed_in": True, "countries": [{"name": "Canada", "code": "CA"}]},
            ),
            patch.object(keyring, "start_service", return_value=(None, {})) as start,
            patch.object(proton_cli, "run_cli", side_effect=lambda arguments: self.assertTrue(start.called)) as run_cli,
            patch.object(main, "_get_status", return_value={"connected": True}),
        ):
            result = main._connect_country("CA")

        start.assert_called_once_with()
        run_cli.assert_called_once_with(["connect", "--country", "CA"])
        self.assertTrue(result["connected"])

    def test_connect_country_failure_does_not_retry(self):
        failure = proton_cli.CLICommandError("Proton VPN connection failed: Secret Service unavailable (exit 1)", "Secret Service unavailable")
        with (
            patch.object(proton_cli, "flatpak_installed", return_value=True),
            patch.object(proton_cli, "signed_in", return_value=True),
            patch.object(main, "_get_countries", return_value={"signed_in": True, "countries": [{"name": "United States", "code": "US"}]}),
            patch.object(keyring, "start_service", return_value=(None, {})) as start,
            patch.object(proton_cli, "run_cli", side_effect=failure) as run_cli,
        ):
            result = asyncio.run(main.Plugin().connect_country("US"))
        self.assertEqual(result["error"], str(failure))
        self.assertIsNone(result["connected"])
        start.assert_called_once_with()
        run_cli.assert_called_once_with(["connect", "--country", "US"])

    def test_connect_country_keyring_failure_prevents_connection(self):
        with (
            patch.object(proton_cli, "flatpak_installed", return_value=True),
            patch.object(main, "_get_countries", return_value={"signed_in": True, "countries": [{"name": "United States", "code": "US"}]}),
            patch.object(keyring, "start_service", return_value=("No usable Steam display", {})) as start,
            patch.object(proton_cli, "run_cli") as run_cli,
        ):
            result = asyncio.run(main.Plugin().connect_country("US"))
        self.assertIn("keyring startup failed: No usable Steam display", result["error"])
        self.assertIsNone(result["connected"])
        start.assert_called_once_with()
        run_cli.assert_not_called()

    def test_connect_country_rejects_unknown_code(self):
        with (
            patch.object(
                main,
                "_get_countries",
                return_value={"signed_in": True, "countries": [{"name": "Canada", "code": "CA"}]},
            ),
            patch.object(keyring, "start_service") as start,
            patch.object(proton_cli, "run_cli") as run_cli,
        ):
            with self.assertRaisesRegex(ValueError, "available country list"):
                main._connect_country("US")

        run_cli.assert_not_called()
        start.assert_not_called()

    def test_disconnect_uses_proton_cli(self):
        with (
            patch.object(proton_cli, "flatpak_installed", return_value=True),
            patch.object(proton_cli, "signed_in", return_value=True),
            patch.object(proton_cli, "run_cli") as run_cli,
            patch.object(main, "_get_status", return_value={"connected": False}),
        ):
            result = main._disconnect()

        run_cli.assert_called_once_with(["disconnect"])
        self.assertFalse(result["connected"])

    def test_connection_rpcs_return_expected_errors_without_asserting_state(self):
        plugin = main.Plugin()
        for method, target, arguments in (
            (plugin.connect_country, "_connect_country", ("US",)),
            (plugin.disconnect, "_disconnect", ()),
            (plugin.quick_connect, "_quick_connect", ()),
            (plugin.set_kill_switch, "_set_kill_switch", (True,)),
            (plugin.signout, "_signout", ()),
        ):
            for failure in (
                ValueError("Choose a valid Proton VPN country"),
                proton_cli.CLICommandError("Proton VPN connection failed: Secret Service unavailable (exit 1)", "Secret Service unavailable"),
                RuntimeError("Proton VPN connection timed out; refresh status before retrying"),
            ):
                with self.subTest(target=target, error=str(failure)), patch.object(main, target, side_effect=failure) as action:
                    result = asyncio.run(method(*arguments))
                self.assertEqual(result, {"installed": None, "signed_in": None, "connected": None, "error": str(failure)})
                action.assert_called_once_with(*arguments)
                self.assertFalse(main.CLI_OPERATION_LOCK.locked())

    def test_connection_rpcs_do_not_retry_when_an_operation_is_busy(self):
        plugin = main.Plugin()
        with patch.object(main, "_connect_country") as connect, patch.object(main, "_disconnect") as disconnect:
            with main.CLI_OPERATION_LOCK:
                results = (asyncio.run(plugin.connect_country("US")), asyncio.run(plugin.disconnect()))
        for result in results:
            self.assertIn("in progress", result["error"])
            self.assertIsNone(result["connected"])
        connect.assert_not_called()
        disconnect.assert_not_called()

    def test_connection_rpcs_preserve_successful_results(self):
        plugin = main.Plugin()
        for method, target, arguments, connected in (
            (plugin.connect_country, "_connect_country", ("US",), True),
            (plugin.disconnect, "_disconnect", (), False),
            (plugin.quick_connect, "_quick_connect", (), True),
            (plugin.set_kill_switch, "_set_kill_switch", (True,), True),
            (plugin.signout, "_signout", (), False),
        ):
            expected = {"installed": True, "signed_in": True, "connected": connected}
            with self.subTest(target=target), patch.object(main, target, return_value=expected):
                self.assertEqual(asyncio.run(method(*arguments)), expected)


class SignInTests(unittest.TestCase):
    def test_signin_prepares_keyring_before_submitting_credentials(self):
        def run_cli(*arguments, **options):
            self.keyring_start.assert_called_once_with()
            return subprocess.CompletedProcess([], 0, "", "")

        with (
            patch.object(subprocess, "run", side_effect=run_cli),
            patch.object(main, "_get_status", return_value={"signed_in": True}),
        ):
            self.assertTrue(main._run_cli_signin({"username": "user", "password": "private-password", "totp": ""})["signed_in"])
        self.assertNotIn("private-password", str(self.logger.info.call_args_list))
        self.logger.info.assert_any_call("Proton VPN sign-in: CLI returned; exit=%d", 0)

    def test_signin_keyring_failure_prevents_credential_submission(self):
        self.keyring_start.return_value = ("No usable Steam display", {})
        with patch.object(subprocess, "run") as run_cli:
            with self.assertRaisesRegex(RuntimeError, "keyring startup failed: No usable Steam display"):
                main._run_cli_signin({"username": "user", "password": "private-password", "totp": ""})
        run_cli.assert_not_called()
        self.assertNotIn("private-password", str(self.logger.info.call_args_list))

    def test_signin_reports_sanitized_cli_category(self):
        with patch.object(subprocess, "run", return_value=subprocess.CompletedProcess([], 1, "", "KeyringLocked private-password")):
            with self.assertRaisesRegex(RuntimeError, r"sign-in failed: keyring locked \(exit 1\)"):
                main._run_cli_signin({"username": "user", "password": "private-password", "totp": ""})
        self.assertNotIn("private-password", str(self.logger.info.call_args_list))

    def test_signin_zero_exit_without_verified_account_is_not_silent(self):
        for signed_in in (False, None):
            with (
                self.subTest(signed_in=signed_in),
                patch.object(subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "", "")),
                patch.object(main, "_get_status", return_value={"installed": True, "signed_in": signed_in, "connected": False}),
            ):
                result = main._run_cli_signin({"username": "user", "password": "secret", "totp": ""})
            self.assertIn("without completing sign-in", result["error"])
            self.assertIs(result["signed_in"], signed_in)

    def test_signin_success_is_not_reported_as_failed_authentication(self):
        with (
            patch.object(subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "", "")),
            patch.object(main, "_get_status", return_value={"installed": True, "signed_in": True, "connected": None, "error": "status failed"}),
        ):
            result = main._run_cli_signin({"username": "user", "password": "secret", "totp": ""})
        self.assertTrue(result["signed_in"])
        self.assertIn("completed sign-in", result["error"])
        self.assertIn("status failed", result["error"])

    def test_signin_rpc_returns_expected_errors_without_python_exception(self):
        plugin = main.Plugin()
        with patch.object(main, "_begin_signin", side_effect=RuntimeError("session unavailable")):
            self.assertEqual(asyncio.run(plugin.begin_signin()), {"error": "session unavailable"})
        with patch.object(main, "_complete_signin", side_effect=RuntimeError("already signed in")):
            self.assertEqual(asyncio.run(plugin.complete_signin("session", "ciphertext")), {"error": "already signed in"})
        with patch.object(main, "_complete_signin", side_effect=ValueError("expired")):
            self.assertEqual(asyncio.run(plugin.complete_signin("session", "ciphertext")), {"error": "expired"})
        self.assertIn("failed", str(self.logger.info.call_args_list))
        self.assertNotIn("session unavailable", str(self.logger.info.call_args_list))
        self.assertNotIn("expired", str(self.logger.info.call_args_list))

    def test_signin_stage_logging_excludes_payloads_and_session_material(self):
        plugin = main.Plugin()
        session = {"session_id": "private-session", "public_key": "private-public-key"}
        with (
            patch.object(main, "_begin_signin", return_value=session),
            patch.object(main, "_complete_signin", return_value={"signed_in": True}),
            patch.object(main, "_cancel_signin"),
        ):
            self.assertEqual(asyncio.run(plugin.begin_signin()), session)
            self.assertTrue(asyncio.run(plugin.complete_signin("private-session", "private-ciphertext"))["signed_in"])
            asyncio.run(plugin.cancel_signin("private-session"))
        self.assertEqual(self.logger.info.call_args_list, [
            call("Proton VPN sign-in: secure session requested"),
            call("Proton VPN sign-in: secure session %s", "ready"),
            call("Proton VPN sign-in: encrypted submission received"),
            call("Proton VPN sign-in: completion returned; outcome=%s", "signed in"),
            call("Proton VPN sign-in: unused session cleanup requested"),
        ])
        self.assertNotIn("private", str(self.logger.info.call_args_list))

    def setUp(self):
        logger = patch.object(main.decky, "logger", create=True)
        self.logger = logger.start()
        self.addCleanup(logger.stop)
        keyring_start = patch.object(keyring, "start_service", return_value=(None, {}))
        self.keyring_start = keyring_start.start()
        self.addCleanup(keyring_start.stop)
        self.sessions = patch.dict(main.SIGNIN_SESSIONS, {}, clear=True)
        self.sessions.start()
        self.addCleanup(self.sessions.stop)

    def test_complete_wipes_key_and_consumes_session(self):
        private_key = bytearray(b"private-key")
        credentials = {"username": "user", "password": "secret", "totp": ""}
        main.SIGNIN_SESSIONS["session"] = (private_key, float("inf"))
        with (
            patch.object(main, "_decrypt_signin_payload", return_value=credentials),
            patch.object(main, "_run_cli_signin", return_value={"signed_in": True}),
        ):
            self.assertTrue(main._complete_signin("session", "ciphertext")["signed_in"])
        self.assertEqual(private_key, bytearray(len(private_key)))
        self.assertEqual(credentials, {})
        with self.assertRaisesRegex(ValueError, "expired"):
            main._complete_signin("session", "ciphertext")

    def test_expired_submission_wipes_key(self):
        private_key = bytearray(b"private-key")
        main.SIGNIN_SESSIONS["session"] = (private_key, 0)
        with self.assertRaisesRegex(ValueError, "expired"):
            main._complete_signin("session", "ciphertext")
        self.assertEqual(private_key, bytearray(len(private_key)))

    def test_decryption_failure_wipes_key(self):
        private_key = bytearray(b"private-key")
        main.SIGNIN_SESSIONS["session"] = (private_key, float("inf"))
        with patch.object(main, "_decrypt_signin_payload", side_effect=ValueError("invalid")):
            with self.assertRaises(ValueError):
                main._complete_signin("session", "ciphertext")
        self.assertEqual(private_key, bytearray(len(private_key)))

    def test_begin_checks_capacity_before_generating_keys(self):
        for index in range(4):
            main.SIGNIN_SESSIONS[str(index)] = (bytearray(b"key"), float("inf"))
        with (
            patch.object(proton_cli, "flatpak_installed", return_value=True),
            patch.object(main, "_generate_signin_keypair") as generate,
        ):
            with self.assertRaisesRegex(RuntimeError, "in progress"):
                main._begin_signin()
        generate.assert_not_called()

    def test_begin_expires_old_keys_and_returns_only_public_material(self):
        old_key = bytearray(b"old")
        new_key = bytearray(b"new")
        main.SIGNIN_SESSIONS["expired"] = (old_key, 0)
        with (
            patch.object(proton_cli, "flatpak_installed", return_value=True),
            patch.object(main, "_generate_signin_keypair", return_value=(new_key, "public")),
        ):
            result = main._begin_signin()
        self.assertEqual(set(result), {"session_id", "public_key"})
        self.assertEqual(result["public_key"], "public")
        self.assertEqual(old_key, bytearray(3))
        self.assertIs(main.SIGNIN_SESSIONS[result["session_id"]][0], new_key)

    def test_generation_is_bounded_and_lock_is_released_on_error(self):
        with (
            patch.object(proton_cli, "flatpak_installed", return_value=True),
            patch.object(main, "_generate_signin_keypair", side_effect=OSError("failure")) as generate,
        ):
            with main.SIGNIN_SESSIONS_LOCK:
                with self.assertRaisesRegex(RuntimeError, "in progress"):
                    main._begin_signin()
            generate.assert_not_called()
            with self.assertRaisesRegex(RuntimeError, "secure sign-in session"):
                main._begin_signin()
        self.assertFalse(main.SIGNIN_SESSIONS_LOCK.locked())

    def test_cancel_is_idempotent_and_wipes_key(self):
        private_key = bytearray(b"key")
        main.SIGNIN_SESSIONS["session"] = (private_key, float("inf"))
        main._cancel_signin("session")
        main._cancel_signin("session")
        self.assertEqual(private_key, bytearray(3))
        self.assertFalse(main.SIGNIN_SESSIONS)

    def test_cleanup_expires_only_old_sessions(self):
        old_key, live_key = bytearray(b"old"), bytearray(b"live")
        main.SIGNIN_SESSIONS.update(old=(old_key, 0), live=(live_key, float("inf")))
        main._clear_signin_sessions(expired_only=True)
        self.assertEqual(old_key, bytearray(3))
        self.assertEqual(live_key, bytearray(b"live"))
        main._clear_signin_sessions()
        self.assertEqual(live_key, bytearray(4))
        self.assertFalse(main.SIGNIN_SESSIONS)

    def test_plugin_unload_clears_sessions_and_stops_cleanup(self):
        private_key = bytearray(b"key")
        main.SIGNIN_SESSIONS["session"] = (private_key, float("inf"))

        async def lifecycle():
            plugin = main.Plugin()
            await plugin._main()
            task = plugin._cleanup_task
            await plugin._unload()
            self.assertTrue(task.done())

        with patch.object(main.decky, "logger", logging.getLogger("test"), create=True):
            asyncio.run(lifecycle())
        self.assertEqual(private_key, bytearray(3))
        self.assertFalse(main.SIGNIN_SESSIONS)

    def test_cli_operation_rejects_overlap_and_releases_lock(self):
        with main.CLI_OPERATION_LOCK:
            with self.assertRaisesRegex(RuntimeError, "in progress"):
                main._cli_operation(lambda: None)
        with self.assertRaises(ValueError):
            main._cli_operation(lambda: int("invalid"))
        self.assertFalse(main.CLI_OPERATION_LOCK.locked())

    def test_signin_keeps_password_and_code_out_of_arguments_and_environment(self):
        for code in ("", "123456", "recovery-code"):
            with (
                self.subTest(code=code),
                patch.object(main, "_get_status", return_value={"signed_in": True}),
                patch.object(proton_cli, "cli_environment", return_value={"LC_ALL": "C"}),
                patch.object(subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "", "")) as run,
            ):
                main._run_cli_signin({"username": "-username", "password": "unique-secret", "totp": code})
                arguments = run.call_args.args[0]
                options = run.call_args.kwargs
                self.assertEqual(arguments[-4:], ["signin", "--totp", "--", "-username"])
                self.assertEqual(options["input"], f"unique-secret\n{code}\n")
                self.assertNotIn("unique-secret", str(arguments) + str(options["env"]))
                self.assertTrue(options["start_new_session"])
                self.assertEqual(options["timeout"], main.SIGNIN_TIMEOUT_SECONDS)

    def test_signin_rejects_invalid_fields_without_running_cli(self):
        invalid_fields = [
            ("username", "bad user"), ("username", []), ("password", ""),
            ("password", "secret\nextra"), ("password", "secret\r"),
            ("password", "secret\0"), ("password", 123), ("totp", "code\nextra"),
            ("totp", "code\0"), ("totp", None),
        ]
        with patch.object(subprocess, "run") as run:
            for field, value in invalid_fields:
                with self.subTest(field=field, value=value):
                    credentials = {"username": "user", "password": "secret", "totp": ""}
                    credentials[field] = value
                    with self.assertRaises(ValueError):
                        main._run_cli_signin(credentials)
        run.assert_not_called()

    def test_signin_errors_never_echo_cli_output_or_timeout_details(self):
        secret = "SECRET-MUST-NOT-APPEAR"
        failures = [
            subprocess.CompletedProcess([], 1, secret, secret),
            subprocess.CompletedProcess([], 1, "", "Invalid two-factor " + secret),
            subprocess.TimeoutExpired(["signin", secret], 180, output=secret, stderr=secret),
            OSError(secret),
        ]
        for failure in failures:
            with self.subTest(failure=type(failure).__name__), patch.object(subprocess, "run") as run:
                if isinstance(failure, Exception):
                    run.side_effect = failure
                else:
                    run.return_value = failure
                try:
                    main._run_cli_signin({"username": "user", "password": "secret", "totp": ""})
                except RuntimeError:
                    self.assertNotIn(secret, traceback.format_exc())
                else:
                    self.fail("Expected a sanitized error")

    def test_status_redacts_cli_error_output(self):
        with (
            patch.object(proton_cli, "flatpak_installed", return_value=True),
            patch.object(subprocess, "run", return_value=subprocess.CompletedProcess([], 1, "private-account", "private-token")),
        ):
            result = main._get_status()
        self.assertIn("error", result)
        self.assertNotIn("private", str(result))

    def test_ciphertext_validation_precedes_openssl(self):
        with patch.object(subprocess, "run") as run:
            for ciphertext in (None, "", "!" * 684, base64.b64encode(b"short").decode()):
                with self.subTest(ciphertext=ciphertext), self.assertRaises(ValueError):
                    main._decrypt_signin_payload(bytearray(b"key"), ciphertext)
        run.assert_not_called()

    def test_decrypted_payload_requires_exact_schema(self):
        ciphertext = base64.b64encode(bytes(512)).decode()
        for payload in ([], {}, {"username": "user", "password": "secret", "totp": "", "extra": True}):
            with (
                self.subTest(payload=payload),
                patch.object(main.tempfile, "TemporaryFile", return_value=tempfile.TemporaryFile()),
                patch.object(subprocess, "run", return_value=subprocess.CompletedProcess([], 0, json.dumps(payload).encode(), b"")),
            ):
                with self.assertRaisesRegex(ValueError, "Invalid sign-in request"):
                    main._decrypt_signin_payload(bytearray(b"key"), ciphertext)


if __name__ == "__main__":
    unittest.main()
