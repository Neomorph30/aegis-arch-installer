"""Tests for read-only guest probing with temporary fake sysfs/procfs."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from types import SimpleNamespace

from lab.guest_probe import GuestProbeError, observe_guest


def lsblk_data():
    return {"blockdevices": [
        {"name": "vda", "path": "/dev/vda", "type": "disk", "size": 25769803776,
         "serial": "AEGIS-LAB-PRIMARY", "ro": 0, "mountpoints": [None],
         "children": [{"name": "vda1", "path": "/dev/vda1", "type": "part",
                       "size": 4294967296, "serial": None, "ro": 0, "mountpoints": [None]}]},
        {"name": "vdb", "path": "/dev/vdb", "type": "disk", "size": 8589934592,
         "serial": "AEGIS-LAB-SECONDARY", "ro": 1, "mountpoints": [None]},
        {"name": "sr0", "path": "/dev/sr0", "type": "rom", "size": 0,
         "serial": "ARCH-ISO", "ro": 1, "mountpoints": ["/run/archiso/bootmnt"]},
        {"name": "loop0", "path": "/dev/loop0", "type": "loop", "size": 1000},
    ]}


class GuestProbeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name)
        self.sys = base / "sys"
        self.proc = base / "proc"
        (self.sys / "class/dmi/id").mkdir(parents=True)
        (self.sys / "class/net/lo").mkdir(parents=True)
        for name in ("vda", "vda1", "vdb", "sr0"):
            (self.sys / f"class/block/{name}/holders").mkdir(parents=True)
        (self.sys / "class/dmi/id/sys_vendor").write_text("QEMU")
        (self.sys / "class/dmi/id/product_name").write_text("Standard PC Q35")
        self.proc.mkdir()
        (self.proc / "swaps").write_text("Filename Type Size Used Priority\n")
        self.commands = []

    def runner(self, command, **kwargs):
        self.commands.append((command, kwargs))
        return SimpleNamespace(stdout=json.dumps(lsblk_data()))

    def observe(self):
        return observe_guest(sys_root=self.sys, proc_root=self.proc, run=self.runner)

    def test_normalizes_fixed_lab_disks_and_ignores_loops(self):
        result = self.observe()
        self.assertEqual(result["environment"]["sys_vendor"], "QEMU")
        self.assertEqual(result["network_mode"], "disabled")
        self.assertEqual([d["path"] for d in result["devices"]], ["/dev/vda", "/dev/vdb", "/dev/sr0"])
        self.assertEqual(result["devices"][0]["serial"], "AEGIS-LAB-PRIMARY")
        self.assertEqual(result["devices"][0]["children"][0]["path"], "/dev/vda1")
        self.assertEqual(len(self.commands), 1)
        command, kwargs = self.commands[0]
        self.assertEqual(command[0], "lsblk")
        self.assertFalse(kwargs.get("shell", False))
        self.assertEqual(kwargs["timeout"], 8)

    def test_active_swap_is_detected(self):
        (self.proc / "swaps").write_text("Filename Type Size Used Priority\n/dev/vda2 partition 1024 0 -2\n")
        result = self.observe()
        self.assertEqual(result["active_swaps"], ["/dev/vda2"])

    def test_non_loopback_network_is_unverified(self):
        (self.sys / "class/net/enp0s3").mkdir()
        self.assertEqual(self.observe()["network_mode"], "unverified")

    def test_malformed_json_fails_closed(self):
        with self.assertRaisesRegex(GuestProbeError, "invalid JSON"):
            observe_guest(sys_root=self.sys, proc_root=self.proc,
                          run=lambda *args, **kwargs: SimpleNamespace(stdout="{"))

    def test_probe_timeout_fails_closed_after_one_retry(self):
        calls = []
        def timeout(*args, **kwargs):
            calls.append(1)
            raise subprocess.TimeoutExpired("lsblk", 8)
        with self.assertRaisesRegex(GuestProbeError, "timed out twice"):
            observe_guest(sys_root=self.sys, proc_root=self.proc, run=timeout)
        self.assertEqual(len(calls), 2)

    def test_transient_probe_timeout_recovers_on_single_retry(self):
        calls = []
        valid_output = json.dumps(lsblk_data())
        def transient(*args, **kwargs):
            calls.append(1)
            if len(calls) == 1:
                raise subprocess.TimeoutExpired("lsblk", 8)
            return SimpleNamespace(stdout=valid_output)
        result = observe_guest(sys_root=self.sys, proc_root=self.proc, run=transient)
        self.assertEqual(len(calls), 2)
        self.assertEqual(result["environment"]["sys_vendor"], "QEMU")


    def test_unreadable_holder_state_is_not_reported_as_empty(self):
        import shutil
        shutil.rmtree(self.sys / "class/block/vda/holders")
        result = self.observe()
        self.assertEqual(result["devices"][0]["holders"], ["UNVERIFIED"])

    def test_unreadable_swap_state_fails_closed(self):
        (self.proc / "swaps").unlink()
        with self.assertRaisesRegex(GuestProbeError, "active swap state"):
            self.observe()

    def test_unexpected_schema_fails_closed(self):
        with self.assertRaisesRegex(GuestProbeError, "unexpected schema"):
            observe_guest(sys_root=self.sys, proc_root=self.proc,
                          run=lambda *args, **kwargs: SimpleNamespace(stdout='{"unexpected": []}'))


if __name__ == "__main__":
    unittest.main()
