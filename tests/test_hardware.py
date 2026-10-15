import json
import unittest
from unittest.mock import patch
from subprocess import CompletedProcess

from aegis.hardware import HardwareInspectionError, read_disks


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

    @patch("aegis.hardware.shutil.which", return_value=None)
    def test_lsblk_required(self, _which):
        with self.assertRaises(HardwareInspectionError):
            read_disks()


if __name__ == "__main__":
    unittest.main()
