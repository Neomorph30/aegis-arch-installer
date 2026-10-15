"""Conservative network preflight and explicitly authorized interactive Wi-Fi setup.

No password collection, network credential storage, service toggles, or shell commands.
A failed HTTPS check is *not* proof the machine lacks internet access.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
import sys
import urllib.error
import urllib.request

# Independently hosted HTTPS endpoints; TLS is verified by the system trust store.
# A check verifies general connectivity, NOT mirror or pacman readiness.
CHECK_URLS = ("https://archlinux.org/", "https://www.kernel.org/")


class NetworkSetupError(RuntimeError):
    """A requested interactive setup cannot be safely started."""


def wifi_interfaces(sys_net: Path = Path("/sys/class/net")) -> list[str]:
    """Read kernel-exported wireless interface hints, without changing state."""
    try:
        interfaces = list(sys_net.iterdir())
    except OSError:
        return []
    found = []
    for path in interfaces:
        # Avoid trusting naming conventions like wlan0; predictable names vary.
        if (path / "wireless").exists() or (path / "phy80211").exists():
            found.append(path.name)
    return sorted(found)


def check_internet(timeout: float = 3.0) -> dict[str, object]:
    """Return a conservative HTTPS connectivity result, never a reachability guarantee.

    DNS, routing, proxy policy, captive portals, incorrect system time and TLS
    trust all affect the outcome. An HTTPS response proves only connectivity to
    that specific site at that moment.
    """
    for url in CHECK_URLS:
        try:
            req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": "AEGIS-network-preflight/0.2"})
            with urllib.request.urlopen(req, timeout=timeout) as response:
                if 200 <= response.status < 400:
                    return {"status": "verified-online", "check": "HTTPS", "note": "Verified access to a public HTTPS endpoint; Arch mirrors not yet checked."}
        except urllib.error.HTTPError as exc:
            # Valid TLS + a server response (e.g. HEAD forbidden) still confirms
            # the remote server was reached. Do not expose response bodies.
            if 400 <= exc.code < 500:
                return {"status": "verified-online", "check": "HTTPS", "note": "Verified HTTPS response; package mirrors not yet checked."}
        except (urllib.error.URLError, TimeoutError, OSError, ValueError):
            continue
    return {"status": "unverified", "check": "HTTPS", "note": "No verified HTTPS response. Internet may be disconnected, restricted, or DNS/TLS may be failing."}


def network_preflight() -> dict[str, object]:
    return {**check_internet(), "wifi_interfaces": wifi_interfaces(), "setup_requires_consent": True}


def _network_manager_active() -> bool:
    nmcli = shutil.which("nmcli")
    if not nmcli:
        return False
    try:
        result = subprocess.run([nmcli, "-t", "-f", "RUNNING", "general"], capture_output=True,
                                text=True, timeout=3, check=False)
        return result.returncode == 0 and result.stdout.strip().lower() == "running"
    except (OSError, subprocess.SubprocessError):
        return False


def setup_tool() -> tuple[str, list[str]] | None:
    """Choose the existing interactive manager; never supply secrets as args."""
    if _network_manager_active() and (nmtui := shutil.which("nmtui")):
        return ("NetworkManager (nmtui)", [nmtui, "connect"])
    if iwctl := shutil.which("iwctl"):
        return ("iwd (iwctl)", [iwctl])
    return None


def launch_wifi_setup() -> int:
    """Launch a system-provided interactive tool after explicit user consent.

    Network profiles may be changed by the tool, but AEGIS never handles Wi-Fi
    secrets itself. Intentionally forbidden in noninteractive environments.
    """
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        raise NetworkSetupError("Wi-Fi setup requires a local interactive terminal")
    tool = setup_tool()
    if tool is None:
        raise NetworkSetupError("Neither active NetworkManager/nmtui nor iwctl is available")
    name, command = tool
    print(f"Launching {name}. Connect within the system tool, then exit to return to AEGIS.")
    try:
        # Inherit terminal streams so the system tool prompts for any secrets.
        # Never capture or log password input or include it on command line.
        return subprocess.run(command, check=False).returncode
    except OSError as exc:
        raise NetworkSetupError("Unable to start the system Wi-Fi configuration tool") from exc


def print_network_status(status: dict[str, object]) -> None:
    print(f"Internet: {status['status']} ({status['check']})")
    print(status["note"])
    interfaces = status.get("wifi_interfaces", [])
    print("Wi-Fi devices: " + (", ".join(interfaces) if interfaces else "none detected"))
    if status["status"] != "verified-online":
        print("Check Ethernet, Wi-Fi, DNS, captive portals or system clock before downloading packages.")


def interactive_preflight(*, offer_setup: bool = True) -> dict[str, object]:
    """Check network; offer (never silently activate) system Wi-Fi setup."""
    result = network_preflight()
    print_network_status(result)
    if result["status"] == "verified-online" or not offer_setup:
        return result
    if not result["wifi_interfaces"]:
        print("No Wi-Fi interface detected. Try Ethernet, tethering, or load the correct firmware.")
        return result
    if setup_tool() is None:
        print("No supported Wi-Fi manager found. The Arch ISO normally includes iwctl.")
        return result
    try:
        consent = input("Open interactive Wi-Fi setup now? [y/N]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print("\\nInput closed or interrupted. Network settings unchanged.")
        return result
    if consent not in ("y", "yes"):
        print("Network settings unchanged.")
        return result
    launch_wifi_setup()
    print("Checking network again after Wi-Fi setup...")
    result = network_preflight()
    print_network_status(result)
    return result
