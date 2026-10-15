import sys
import types
import unittest
from unittest.mock import patch

sys.modules.setdefault("decky", types.ModuleType("decky"))

import main


PROFILE = {
    "uuid": "proton-uuid",
    "name": "ProtonVPN US-CA#879",
    "type": "wireguard",
}


class ProtonBackendTests(unittest.TestCase):
    def test_split_nmcli_fields_handles_escaped_colons(self):
        fields = main._split_nmcli_fields(r"proton-uuid:ProtonVPN US\:CA#879:wireguard")
        self.assertEqual(fields, ["proton-uuid", "ProtonVPN US:CA#879", "wireguard"])

    def test_get_connections_reports_active_proton_profile(self):
        with (
            patch.object(main, "_flatpak_installed", return_value=True),
            patch.object(
                main,
                "_run_nmcli",
                side_effect=[
                    "proton-uuid:ProtonVPN US-CA#879:wireguard\n",
                    "proton-uuid\n",
                ],
            ),
        ):
            status = main._get_connections()

        self.assertTrue(status["installed"])
        self.assertTrue(status["connected"])
        self.assertEqual(status["connections"], [{**PROFILE, "active": True}])

    def test_missing_app_returns_install_guidance_state(self):
        with (
            patch.object(main, "_flatpak_installed", return_value=False),
            patch.object(main, "_run_nmcli") as run_nmcli,
        ):
            status = main._get_connections()

        self.assertFalse(status["installed"])
        self.assertEqual(status["connections"], [])
        run_nmcli.assert_not_called()

    def test_toggle_disconnects_active_profile_by_uuid(self):
        with (
            patch.object(main, "_flatpak_installed", return_value=True),
            patch.object(main, "_proton_profiles", return_value=[PROFILE]),
            patch.object(main, "_active_uuids", return_value={"proton-uuid"}),
            patch.object(main, "_run_nmcli") as run_nmcli,
            patch.object(main, "_get_connections", return_value={"connected": False}),
        ):
            main._toggle_connection("proton-uuid")

        run_nmcli.assert_called_once_with(
            ["connection", "down", "uuid", "proton-uuid"]
        )

    def test_toggle_connects_inactive_profile_by_uuid(self):
        with (
            patch.object(main, "_flatpak_installed", return_value=True),
            patch.object(main, "_proton_profiles", return_value=[PROFILE]),
            patch.object(main, "_active_uuids", return_value=set()),
            patch.object(main, "_run_nmcli") as run_nmcli,
            patch.object(main, "_get_connections", return_value={"connected": True}),
        ):
            main._toggle_connection("proton-uuid")

        run_nmcli.assert_called_once_with(
            ["connection", "up", "uuid", "proton-uuid"]
        )

    def test_toggle_refuses_to_switch_while_another_profile_is_active(self):
        other_profile = {**PROFILE, "uuid": "other-proton-uuid"}
        with (
            patch.object(main, "_flatpak_installed", return_value=True),
            patch.object(main, "_proton_profiles", return_value=[PROFILE, other_profile]),
            patch.object(main, "_active_uuids", return_value={"other-proton-uuid"}),
            patch.object(main, "_run_nmcli") as run_nmcli,
        ):
            with self.assertRaisesRegex(RuntimeError, "Disconnect the active Proton VPN"):
                main._toggle_connection("proton-uuid")

        run_nmcli.assert_not_called()

    def test_toggle_rejects_unknown_profile(self):
        with (
            patch.object(main, "_flatpak_installed", return_value=True),
            patch.object(main, "_proton_profiles", return_value=[PROFILE]),
            patch.object(main, "_run_nmcli") as run_nmcli,
        ):
            with self.assertRaisesRegex(ValueError, "not available"):
                main._toggle_connection("unknown-uuid")

        run_nmcli.assert_not_called()


if __name__ == "__main__":
    unittest.main()
