import asyncio
import base64
import io
import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
import traceback
import types
import unittest
from contextlib import redirect_stdout
from importlib import metadata
from pathlib import Path
from unittest.mock import Mock, call, patch

sys.modules.setdefault("decky", types.ModuleType("decky"))

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "py_modules"))

import main
from protonvpn import keyring, proton_cli


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


class KeyringServiceTests(unittest.TestCase):
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
        for service in ("org.kde.secretservicecompat", "org.kde.kwalletd6", "org.kde.kwalletd5", "org.gnome.keyring", "org.freedesktop.secrets"):
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
                patch.object(proton_cli, "run_cli", side_effect=["Account: 'private-user'", failure]) as cli,
                patch.object(keyring, "diagnostics", return_value={"Default collection": "locked"}) as probe,
                patch.object(main.decky, "logger", create=True) as logger,
            ):
                report = main._get_status()
                self.assertTrue(report["signed_in"])
                self.assertIsNone(report["connected"])
                self.assertEqual(report["diagnostics"], {"Default collection": "locked", "CLI exception types": "not reported"})
                self.assertEqual(cli.call_args_list, [call(["info"]), call(["status"])])
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
            patch.object(proton_cli, "run_cli", side_effect=["Account: 'dummy-user'", RuntimeError("status failed")]),
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
        self.assertEqual(countries["error"], "Flatpak check failed")
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
                side_effect=[
                    "Account: 'user@example.com'",
                    "Status: Connected\nServer: US-CA#856\nProtocol: wireguard",
                ],
            ),
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
                side_effect=["Account: 'None'", "Status: Disconnected"],
            ),
        ):
            status = main._get_status()

        self.assertFalse(status["signed_in"])
        self.assertFalse(status["connected"])

    def test_missing_app_returns_install_guidance_state(self):
        with (
            patch.object(proton_cli, "flatpak_installed", return_value=False),
            patch.object(proton_cli, "run_cli") as run_cli,
        ):
            status = main._get_status()

        self.assertFalse(status["installed"])
        run_cli.assert_not_called()

    def test_get_countries_uses_proton_cli(self):
        with (
            patch.object(proton_cli, "flatpak_installed", return_value=True),
            patch.object(proton_cli, "signed_in", return_value=True),
            patch.object(
                proton_cli,
                "run_cli",
                return_value="Country  Code\nCanada   CA\nUnited States US",
            ) as run_cli,
        ):
            result = main._get_countries()

        run_cli.assert_called_once_with(["countries", "list"])
        self.assertEqual(result["countries"][0], {"name": "Canada", "code": "CA"})

    def test_connect_country_validates_then_calls_cli(self):
        with (
            patch.object(
                main,
                "_get_countries",
                return_value={"signed_in": True, "countries": [{"name": "Canada", "code": "CA"}]},
            ),
            patch.object(proton_cli, "run_cli") as run_cli,
            patch.object(main, "_get_status", return_value={"connected": True}),
        ):
            result = main._connect_country("CA")

        run_cli.assert_called_once_with(["connect", "--country", "CA"])
        self.assertTrue(result["connected"])

    def test_connect_country_rejects_unknown_code(self):
        with (
            patch.object(
                main,
                "_get_countries",
                return_value={"signed_in": True, "countries": [{"name": "Canada", "code": "CA"}]},
            ),
            patch.object(proton_cli, "run_cli") as run_cli,
        ):
            with self.assertRaisesRegex(ValueError, "available country list"):
                main._connect_country("US")

        run_cli.assert_not_called()

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


class SignInTests(unittest.TestCase):
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

    def setUp(self):
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
