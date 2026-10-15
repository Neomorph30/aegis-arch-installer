import json
import os
import stat
import unittest
from unittest.mock import patch
from subprocess import CompletedProcess

from aegis.hardware import HardwareInspectionError, _sysfs_block_node, read_disks


class HardwareTests(unittest.TestCase):
    @patch("aegis.hardware.shutil.which", return_value="/usr/bin/lsblk")
    @patch("aegis.hardware.subprocess.run")
    def test_read_disks_filters_partitions(self, run, _which):
        run.return_value = CompletedProcess([], 0, json.dumps({"blockdevices": [
            {"path": "/dev/sda", "type": "disk"},
            {"path": "/dev/sda1", "type": "part"},
        ]}), "")
        self.assertEqual(len(read_disks()), 1)
        self.assertEqual(read_disks()[0]["path"], "/dev/sda")
        self.assertNotIn("shell", run.call_args.kwargs)

    @patch("aegis.hardware.os.stat")
    def test_sysfs_holder_lookup_uses_kernel_major_minor_not_device_basename(self, stat_call):
        stat_call.return_value = type("BlockStat", (), {
            "st_mode": stat.S_IFBLK | 0o600,
            "st_rdev": os.makedev(259, 7),
        })()
        self.assertEqual(str(_sysfs_block_node("/dev/renamed-alias")),
                         "/sys/dev/block/259:7")
        stat_call.assert_called_once_with("/dev/renamed-alias")

    @patch("aegis.hardware.os.stat")
    def test_sysfs_holder_lookup_rejects_non_block_device(self, stat_call):
        stat_call.return_value = type("RegularStat", (), {
            "st_mode": stat.S_IFREG | 0o600,
            "st_rdev": 0,
        })()
        with self.assertRaises(OSError):
            _sysfs_block_node("/tmp/not-a-device")

    @patch("aegis.hardware.shutil.which", return_value=None)
    def test_lsblk_required(self, _which):
        with self.assertRaises(HardwareInspectionError):
            read_disks()


if __name__ == "__main__":
    unittest.main()
