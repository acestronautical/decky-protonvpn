import sys
import types
import unittest
from unittest.mock import patch

sys.modules.setdefault("decky", types.ModuleType("decky"))

import main


class ProtonCLITests(unittest.TestCase):
    def test_parse_status_extracts_connection_details(self):
        status = main._parse_status(
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
        countries = main._parse_countries(
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
            patch.object(main, "_flatpak_installed", return_value=True),
            patch.object(
                main,
                "_run_cli",
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
            patch.object(main, "_flatpak_installed", return_value=True),
            patch.object(
                main,
                "_run_cli",
                side_effect=["Account: 'None'", "Status: Disconnected"],
            ),
        ):
            status = main._get_status()

        self.assertFalse(status["signed_in"])
        self.assertFalse(status["connected"])

    def test_missing_app_returns_install_guidance_state(self):
        with (
            patch.object(main, "_flatpak_installed", return_value=False),
            patch.object(main, "_run_cli") as run_cli,
        ):
            status = main._get_status()

        self.assertFalse(status["installed"])
        run_cli.assert_not_called()

    def test_get_countries_uses_proton_cli(self):
        with (
            patch.object(main, "_flatpak_installed", return_value=True),
            patch.object(main, "_signed_in", return_value=True),
            patch.object(
                main,
                "_run_cli",
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
            patch.object(main, "_run_cli") as run_cli,
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
            patch.object(main, "_run_cli") as run_cli,
        ):
            with self.assertRaisesRegex(ValueError, "available country list"):
                main._connect_country("US")

        run_cli.assert_not_called()

    def test_disconnect_uses_proton_cli(self):
        with (
            patch.object(main, "_flatpak_installed", return_value=True),
            patch.object(main, "_signed_in", return_value=True),
            patch.object(main, "_run_cli") as run_cli,
            patch.object(main, "_get_status", return_value={"connected": False}),
        ):
            result = main._disconnect()

        run_cli.assert_called_once_with(["disconnect"])
        self.assertFalse(result["connected"])


if __name__ == "__main__":
    unittest.main()
