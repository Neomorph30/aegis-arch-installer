"""All network-related tests are simulated: never connect to a real network."""

import io
import tempfile
from pathlib import Path
import unittest
from unittest.mock import Mock, patch
from urllib.error import URLError, HTTPError

from aegis import network


class NetworkTests(unittest.TestCase):
    def test_https_success_and_early_exit(self):
        response = Mock(status=200)
        context = Mock()
        context.__enter__ = Mock(return_value=response)
        context.__exit__ = Mock(return_value=False)
        with patch("aegis.network.urllib.request.urlopen", return_value=context) as open_url:
            result = network.check_internet()
        self.assertEqual(result["status"], "verified-online")
        self.assertEqual(open_url.call_count, 1)
        self.assertEqual(open_url.call_args.kwargs["timeout"], 3)
        self.assertEqual(open_url.call_args.args[0].get_method(), "HEAD")

    def test_two_endpoint_failures_never_claim_offline(self):
        with patch("aegis.network.urllib.request.urlopen", side_effect=URLError("DNS failure")) as url:
            result = network.check_internet()
        self.assertEqual(url.call_count, 2)
        self.assertEqual(result["status"], "unverified")
        self.assertNotIn("DNS failure", result["note"])

    def test_https_403_still_proves_tls_reachability(self):
        with patch("aegis.network.urllib.request.urlopen", side_effect=HTTPError("https://archlinux.org", 403, "forbidden", {}, None)):
            self.assertEqual(network.check_internet()["status"], "verified-online")

    def test_first_host_down_second_host_up(self):
        response = Mock(status=200)
        cm = Mock()
        cm.__enter__ = Mock(return_value=response)
        cm.__exit__ = Mock(return_value=False)
        with patch("aegis.network.urllib.request.urlopen", side_effect=[URLError("down"), cm]) as url:
            self.assertEqual(network.check_internet()["status"], "verified-online")
            self.assertEqual(url.call_count, 2)

    def test_wifi_detection_uses_sysfs_not_device_name(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "lo").mkdir()
            (root / "wlan0").mkdir()
            (root / "wlan0" / "wireless").mkdir()
            (root / "wlp3s0").mkdir()
            (root / "wlp3s0" / "phy80211").mkdir()
            (root / "enp0s31f6").mkdir()
            self.assertEqual(network.wifi_interfaces(root), ["wlan0", "wlp3s0"])
            self.assertEqual(network.wifi_interfaces(root / "missing"), [])

    @patch("aegis.network._network_manager_active", return_value=True)
    @patch("aegis.network.shutil.which", side_effect=lambda name: "/usr/bin/nmtui" if name == "nmtui" else "/usr/bin/iwctl")
    def test_nm_preferred_when_active(self, _which, _nm):
        self.assertEqual(network.setup_tool(), ("NetworkManager (nmtui)", ["/usr/bin/nmtui", "connect"]))

    @patch("aegis.network._network_manager_active", return_value=False)
    @patch("aegis.network.shutil.which", side_effect=lambda name: "/usr/bin/iwctl" if name == "iwctl" else None)
    def test_iwd_fallback_on_archiso(self, _which, _nm):
        self.assertEqual(network.setup_tool(), ("iwd (iwctl)", ["/usr/bin/iwctl"]))

    @patch("aegis.network.sys.stdin.isatty", return_value=True)
    @patch("aegis.network.sys.stdout.isatty", return_value=True)
    @patch("aegis.network.setup_tool", return_value=("iwd", ["/usr/bin/iwctl"]))
    def test_wifi_start_error_does_not_chain_os_details(self, _tool, _out, _in):
        with patch(
            "aegis.network.subprocess.run",
            side_effect=OSError("private-path-or-environment-detail"),
        ):
            with self.assertRaises(network.NetworkSetupError) as caught:
                network.launch_wifi_setup()
        self.assertIsNone(caught.exception.__cause__)
        self.assertNotIn("private-path-or-environment-detail", str(caught.exception))

    @patch("aegis.network.sys.stdout.isatty", return_value=False)
    def test_never_launch_wifi_noninteractive(self, _tty):
        with patch("aegis.network.subprocess.run") as run:
            with self.assertRaises(network.NetworkSetupError):
                network.launch_wifi_setup()
            run.assert_not_called()

    @patch("aegis.network.sys.stdin.isatty", return_value=True)
    @patch("aegis.network.sys.stdout.isatty", return_value=True)
    @patch("aegis.network.setup_tool", return_value=("iwd", ["/usr/bin/iwctl"]))
    def test_launch_no_shell_secrets_or_capture(self, _tool, _out, _in):
        with patch("aegis.network.subprocess.run", return_value=Mock(returncode=0)) as run:
            self.assertEqual(network.launch_wifi_setup(), 0)
            self.assertEqual(run.call_args.args[0], ["/usr/bin/iwctl"])
            self.assertEqual(run.call_args.kwargs, {"check": False})

    @patch("aegis.network.setup_tool", return_value=("iwd", ["/usr/bin/iwctl"]))
    @patch("aegis.network.launch_wifi_setup")
    @patch("aegis.network.network_preflight")
    def test_declining_offer_never_connects(self, preflight, launch, _tool):
        preflight.return_value = {"status": "unverified", "check": "HTTPS", "note": "Check failed", "wifi_interfaces": ["wlan0"]}
        with patch("builtins.input", return_value="n"), patch("sys.stdout", new_callable=io.StringIO):
            result = network.interactive_preflight()
        launch.assert_not_called()
        self.assertEqual(preflight.call_count, 1)
        self.assertEqual(result["status"], "unverified")

    @patch("aegis.network.setup_tool", return_value=("iwd", ["/usr/bin/iwctl"]))
    @patch("aegis.network.launch_wifi_setup", return_value=0)
    @patch("aegis.network.network_preflight")
    def test_eof_or_ctrl_c_declines_optional_wifi_setup(self, preflight, launch, _tool):
        for interruption in (EOFError, KeyboardInterrupt):
            preflight.return_value = {"status": "unverified", "check": "HTTPS", "note": "Unverified", "wifi_interfaces": ["wlan0"]}
            with patch("builtins.input", side_effect=interruption), patch("sys.stdout", new_callable=io.StringIO):
                result = network.interactive_preflight()
            self.assertEqual(result["status"], "unverified")
        launch.assert_not_called()

    @patch("aegis.network.setup_tool", return_value=("iwd", ["/usr/bin/iwctl"]))
    @patch("aegis.network.launch_wifi_setup", return_value=0)
    @patch("aegis.network.network_preflight")
    def test_opt_in_rechecks_network(self, preflight, launch, _tool):
        preflight.side_effect = [
            {"status": "unverified", "check": "HTTPS", "note": "Unverified", "wifi_interfaces": ["wlan0"]},
            {"status": "verified-online", "check": "HTTPS", "note": "Online", "wifi_interfaces": ["wlan0"]},
        ]
        with patch("builtins.input", return_value="yes"), patch("sys.stdout", new_callable=io.StringIO):
            result = network.interactive_preflight()
        self.assertEqual(result["status"], "verified-online")
        launch.assert_called_once()
        self.assertEqual(preflight.call_count, 2)

    @patch("aegis.network.launch_wifi_setup")
    @patch("aegis.network.network_preflight")
    def test_no_wifi_device_never_triggers_setup(self, preflight, launch):
        preflight.return_value = {"status": "unverified", "check": "HTTPS", "note": "Check failed", "wifi_interfaces": []}
        with patch("builtins.input") as request, patch("sys.stdout", new_callable=io.StringIO):
            network.interactive_preflight()
        request.assert_not_called()
        launch.assert_not_called()

    @patch("aegis.cli.network_preflight")
    def test_readonly_check_does_not_prompt(self, preflight):
        from aegis.cli import main
        preflight.return_value = {"status": "unverified", "check": "HTTPS", "note": "Check failed", "wifi_interfaces": ["wlan0"]}
        with patch("builtins.input") as request, patch("sys.stdout", new_callable=io.StringIO) as stdout:
            self.assertEqual(main(["network"]), 0)
        request.assert_not_called()
        self.assertIn("unverified", stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
