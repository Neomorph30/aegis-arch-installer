"""Hermetic unit tests for aegis.hardware detection and edge cases."""
from __future__ import annotations

import json
import os
from pathlib import Path
import stat
from subprocess import CompletedProcess, SubprocessError
import tempfile
import unittest
from unittest.mock import patch

from aegis.hardware import (
    HardwareInspectionError,
    _active_swap_devices,
    _sysfs_block_node,
    read_assessment_observation,
    _cpu_label,
    _gpu_summary,
    _memory_mib,
    _read_text,
    _run_readonly,
    _secure_boot_state,
    _tpm_version,
    inspect,
    read_disks,
)


class CPUInspectionTests(unittest.TestCase):
    """Test CPU label parsing, case sensitivity, and fallback behavior."""

    @patch("aegis.hardware._read_text", return_value="""processor\t: 0
vendor_id\t: GenuineIntel
cpu family\t: 6
model\t\t: 140
model name\t: 11th Gen Intel(R) Core(TM) i7-1185G7 @ 3.00GHz
stepping\t: 1
""")
    def test_cpu_label_intel(self, _mock_read):
        self.assertEqual(_cpu_label(), "11th Gen Intel(R) Core(TM) i7-1185G7 @ 3.00GHz")

    @patch("aegis.hardware._read_text", return_value="""processor\t: 0
vendor_id\t: AuthenticAMD
cpu family\t: 25
model\t\t: 33
model name\t: AMD Ryzen 9 5900X 12-Core Processor
stepping\t: 0
""")
    def test_cpu_label_amd(self, _mock_read):
        self.assertEqual(_cpu_label(), "AMD Ryzen 9 5900X 12-Core Processor")

    @patch("aegis.hardware._read_text", return_value="""processor\t: 0
MODEL NAME\t: Custom Enterprise Processor
""")
    def test_cpu_label_case_insensitive(self, _mock_read):
        self.assertEqual(_cpu_label(), "Custom Enterprise Processor")

    @patch("aegis.hardware._read_text", return_value="""processor\t: 0
model name\t: First Processor Label
processor\t: 1
model name\t: Second Processor Label
""")
    def test_cpu_label_multicore_takes_first_entry(self, _mock_read):
        self.assertEqual(_cpu_label(), "First Processor Label")

    @patch("aegis.hardware._read_text", return_value="""processor\t: 0
vendor_id\t: GenuineIntel
""")
    @patch("aegis.hardware.platform.processor", return_value="x86_64")
    def test_cpu_label_missing_model_name_fallback_to_processor(self, _proc, _mock_read):
        self.assertEqual(_cpu_label(), "x86_64")

    @patch("aegis.hardware._read_text", return_value="")
    @patch("aegis.hardware.platform.processor", return_value="Intel64 Family 6 Model 140")
    def test_cpu_label_missing_file_fallback_to_processor(self, _proc, _mock_read):
        self.assertEqual(_cpu_label(), "Intel64 Family 6 Model 140")

    @patch("aegis.hardware._read_text", return_value="")
    @patch("aegis.hardware.platform.processor", return_value="")
    def test_cpu_label_empty_fallback_unknown(self, _proc, _mock_read):
        self.assertEqual(_cpu_label(), "unknown")


class MemoryInspectionTests(unittest.TestCase):
    """Test memory extraction in MiB, boundary values, and error handling."""

    @patch("aegis.hardware._read_text", return_value="""MemTotal:       32840000 kB
MemFree:         4123000 kB
MemAvailable:   18230000 kB
""")
    def test_memory_mib_valid(self, _mock_read):
        self.assertEqual(_memory_mib(), 32070)

    @patch("aegis.hardware._read_text", return_value="""MemTotal:       16777216 kB
""")
    def test_memory_mib_parses_kilobytes(self, _mock_read):
        self.assertEqual(_memory_mib(), 16384)


    @patch("aegis.hardware._read_text", return_value="""MemTotal:       0 kB
""")
    def test_memory_mib_zero(self, _mock_read):
        self.assertEqual(_memory_mib(), 0)

    @patch("aegis.hardware._read_text", return_value="""MemFree:         4123000 kB
MemAvailable:   18230000 kB
""")
    def test_memory_mib_missing_memtotal_line(self, _mock_read):
        self.assertIsNone(_memory_mib())

    @patch("aegis.hardware._read_text", return_value="""MemTotal:       invalid_size kB
""")
    def test_memory_mib_non_numeric(self, _mock_read):
        self.assertIsNone(_memory_mib())

    @patch("aegis.hardware._read_text", return_value="""MemTotal:
""")
    def test_memory_mib_missing_value_column(self, _mock_read):
        self.assertIsNone(_memory_mib())

    @patch("aegis.hardware._read_text", return_value="")
    def test_memory_mib_missing_or_unreadable_file(self, _mock_read):
        self.assertIsNone(_memory_mib())


class TPMInspectionTests(unittest.TestCase):
    """Test TPM 2.0, 1.2, absent, and error states using synthetic sysfs."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.tpm_base = self.root / "sys" / "class" / "tpm"
        self.tpm_base.mkdir(parents=True)

    def _patch_base(self, target_dir: Path):
        orig_path = Path
        def router(arg, *args, **kwargs):
            if str(arg) == "/sys/class/tpm":
                return target_dir
            return orig_path(arg, *args, **kwargs)
        return patch("aegis.hardware.Path", side_effect=router)

    def test_tpm_2_0_detected(self):
        tpm0 = self.tpm_base / "tpm0"
        tpm0.mkdir()
        (tpm0 / "tpm_version_major").write_text("2\n")
        with self._patch_base(self.tpm_base):
            self.assertEqual(_tpm_version(), "2.0-detected-unverified")

    def test_tpm_1_2_detected(self):
        tpm0 = self.tpm_base / "tpm0"
        tpm0.mkdir()
        (tpm0 / "tpm_version_major").write_text("1\n")
        with self._patch_base(self.tpm_base):
            self.assertEqual(_tpm_version(), "1.2-detected")

    def test_tpm_multi_chip_prioritizes_2_0(self):
        tpm0 = self.tpm_base / "tpm0"
        tpm0.mkdir()
        (tpm0 / "tpm_version_major").write_text("1\n")
        tpm1 = self.tpm_base / "tpm1"
        tpm1.mkdir()
        (tpm1 / "tpm_version_major").write_text("2\n")
        with self._patch_base(self.tpm_base):
            self.assertEqual(_tpm_version(), "2.0-detected-unverified")

    def test_tpm_not_detected_when_no_devices(self):
        with self._patch_base(self.tpm_base):
            self.assertEqual(_tpm_version(), "not-detected")

    def test_tpm_not_detected_when_sys_class_tpm_missing(self):
        missing_dir = self.root / "nonexistent" / "tpm"
        with self._patch_base(missing_dir):
            self.assertEqual(_tpm_version(), "not-detected")

    def test_tpm_unknown_version_value(self):
        tpm0 = self.tpm_base / "tpm0"
        tpm0.mkdir()
        (tpm0 / "tpm_version_major").write_text("99\n")
        with self._patch_base(self.tpm_base):
            self.assertEqual(_tpm_version(), "unknown")

    def test_tpm_missing_version_file_returns_unknown(self):
        tpm0 = self.tpm_base / "tpm0"
        tpm0.mkdir()
        # Missing tpm_version_major -> _read_text returns "" -> unknown
        with self._patch_base(self.tpm_base):
            self.assertEqual(_tpm_version(), "unknown")

    def test_tpm_unreadable_version_file_returns_unknown(self):
        tpm0 = self.tpm_base / "tpm0"
        tpm0.mkdir()
        (tpm0 / "tpm_version_major").write_text("2\n")
        # Simulates an unreadable file where Path.read_text raises OSError
        with self._patch_base(self.tpm_base), \
             patch.object(Path, "read_text", side_effect=OSError("Simulated read error")):
            self.assertEqual(_tpm_version(), "unknown")


    def test_tpm_glob_os_error_returns_unknown(self):
        mock_path = patch("aegis.hardware.Path")
        with mock_path as mocked:
            mocked.return_value.glob.side_effect = OSError("Simulated permission error")
            self.assertEqual(_tpm_version(), "unknown")


class SecureBootInspectionTests(unittest.TestCase):
    """Test EFI variable parsing for SecureBoot state."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.efivars_dir = self.root / "sys" / "firmware" / "efi" / "efivars"
        self.efivars_dir.mkdir(parents=True)

    def _patch_efivars(self, target_dir: Path):
        orig_path = Path
        def router(arg, *args, **kwargs):
            if str(arg) == "/sys/firmware/efi/efivars":
                return target_dir
            return orig_path(arg, *args, **kwargs)
        return patch("aegis.hardware.Path", side_effect=router)

    def test_secure_boot_unavailable_when_dir_missing(self):
        missing_dir = self.root / "nonexistent" / "efivars"
        with self._patch_efivars(missing_dir):
            self.assertEqual(_secure_boot_state(), "unavailable")

    def test_secure_boot_enabled_reported(self):
        # 4 attribute bytes + 1 byte state (0x01 = enabled)
        var_file = self.efivars_dir / "SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"
        var_file.write_bytes(b"\x07\x00\x00\x00\x01")
        with self._patch_efivars(self.efivars_dir):
            self.assertEqual(_secure_boot_state(), "enabled-reported")

    def test_secure_boot_disabled_reported(self):
        # 4 attribute bytes + 1 byte state (0x00 = disabled)
        var_file = self.efivars_dir / "SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"
        var_file.write_bytes(b"\x07\x00\x00\x00\x00")
        with self._patch_efivars(self.efivars_dir):
            self.assertEqual(_secure_boot_state(), "disabled-reported")

    def test_secure_boot_unverified_on_other_byte_value(self):
        var_file = self.efivars_dir / "SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"
        var_file.write_bytes(b"\x07\x00\x00\x00\x02")
        with self._patch_efivars(self.efivars_dir):
            self.assertEqual(_secure_boot_state(), "unverified")

    def test_secure_boot_unverified_on_short_payload(self):
        var_file = self.efivars_dir / "SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"
        var_file.write_bytes(b"\x07\x00\x00\x00")
        with self._patch_efivars(self.efivars_dir):
            self.assertEqual(_secure_boot_state(), "unverified")

    def test_secure_boot_unverified_on_long_payload(self):
        var_file = self.efivars_dir / "SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"
        var_file.write_bytes(b"\x07\x00\x00\x00\x01\x00")
        with self._patch_efivars(self.efivars_dir):
            self.assertEqual(_secure_boot_state(), "unverified")

    def test_secure_boot_unverified_when_multiple_entries(self):
        (self.efivars_dir / "SecureBoot-uuid1").write_bytes(b"\x07\x00\x00\x00\x01")
        (self.efivars_dir / "SecureBoot-uuid2").write_bytes(b"\x07\x00\x00\x00\x01")
        with self._patch_efivars(self.efivars_dir):
            self.assertEqual(_secure_boot_state(), "unverified")

    def test_secure_boot_unverified_when_zero_entries(self):
        with self._patch_efivars(self.efivars_dir):
            self.assertEqual(_secure_boot_state(), "unverified")

    def test_secure_boot_unverified_on_read_os_error(self):
        var_file = self.efivars_dir / "SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"
        var_file.write_bytes(b"\x07\x00\x00\x00\x01")
        with patch.object(Path, "read_bytes", side_effect=OSError("Read error")), \
             self._patch_efivars(self.efivars_dir):
            self.assertEqual(_secure_boot_state(), "unverified")


class GPUInspectionTests(unittest.TestCase):
    """Test lspci output parsing and display controller filtering."""

    @patch("aegis.hardware.shutil.which", return_value=None)
    def test_gpu_lspci_missing(self, _which):
        self.assertEqual(_gpu_summary(), [])

    @patch("aegis.hardware.shutil.which", return_value="/usr/bin/lspci")
    @patch("aegis.hardware._run_readonly", side_effect=HardwareInspectionError("lspci failed"))
    def test_gpu_lspci_error(self, _run, _which):
        self.assertEqual(_gpu_summary(), [])

    @patch("aegis.hardware.shutil.which", return_value="/usr/bin/lspci")
    @patch("aegis.hardware._run_readonly", return_value="""00:00.0 Host bridge [0600]: Intel Corporation Device [8086:4660] (rev 02)
01:00.0 VGA compatible controller [0300]: NVIDIA Corporation AD104 [GeForce RTX 4070] [10de:2786] (rev a1)
01:00.1 Audio device [0403]: NVIDIA Corporation Device [10de:22bc] (rev a1)
02:00.0 3D controller [0302]: Advanced Micro Devices, Inc. [AMD/ATI] Device [1002:73bf] (rev c1)
03:00.0 Display controller [0380]: Intel Corporation Arc A770 [8086:5690] (rev 08)
""")
    def test_gpu_filtering_vga_3d_display(self, _run, _which):
        gpus = _gpu_summary()
        self.assertEqual(len(gpus), 3)
        self.assertTrue(any("VGA compatible controller" in g and "NVIDIA" in g for g in gpus))
        self.assertTrue(any("3D controller" in g and "AMD/ATI" in g for g in gpus))
        self.assertTrue(any("Display controller" in g and "Intel Corporation" in g for g in gpus))
        self.assertFalse(any("Audio device" in g for g in gpus))

    @patch("aegis.hardware.shutil.which", return_value="/usr/bin/lspci")
    @patch("aegis.hardware._run_readonly", return_value="""00:1f.3 Audio device [0403]: Intel Corporation Device [8086:7aa0]
00:1f.6 Ethernet controller [0200]: Intel Corporation Ethernet Connection [8086:1a1e]
""")
    def test_gpu_ignores_unrelated_devices(self, _run, _which):
        self.assertEqual(_gpu_summary(), [])

    @patch("aegis.hardware.shutil.which", return_value="/usr/bin/lspci")
    @patch("aegis.hardware._run_readonly", return_value="")
    def test_gpu_empty_output(self, _run, _which):
        self.assertEqual(_gpu_summary(), [])


class StorageAndProbeTests(unittest.TestCase):
    """Test allowlisted command runner and disk discovery edge cases."""

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

    @patch("aegis.hardware.shutil.which", return_value="/usr/bin/lsblk")
    @patch("aegis.hardware.subprocess.run")
    def test_read_disks_normalizes_real_leaf_nodes_for_planning(self, run, _which):
        run.return_value = CompletedProcess([], 0, json.dumps({"blockdevices": [
            {"path": "/dev/sda", "type": "disk", "children": [
                {"path": "/dev/sda1", "type": "part"}
            ]},
            {"path": "/dev/sdb", "type": "disk"},
        ]}), "")
        disks = read_disks()
        self.assertEqual(disks[0]["children"][0]["children"], [])
        self.assertEqual(disks[1]["children"], [])

    @patch("aegis.hardware.shutil.which", return_value="/usr/bin/lsblk")
    @patch("aegis.hardware.subprocess.run")
    def test_read_disks_preserves_malformed_children_for_fail_closed_validation(self, run, _which):
        malformed = {"unexpected": "mapping"}
        run.return_value = CompletedProcess([], 0, json.dumps({"blockdevices": [
            {"path": "/dev/sda", "type": "disk", "children": malformed},
        ]}), "")
        self.assertEqual(read_disks()[0]["children"], malformed)

    def test_unresolvable_active_swap_entry_is_unknown_not_safe(self):
        with patch("aegis.hardware.Path.read_text",
                   return_value="Filename Type Size Used Priority\\n/dev/missing-swap partition 1024 0 -2\\n"), \\
             patch("aegis.hardware.os.stat", side_effect=OSError("device disappeared")):
            self.assertIsNone(_active_swap_devices())

    def test_read_disks_rejects_excessive_topology_instead_of_truncating(self):
        root = {"path": "/dev/vda", "type": "disk", "children": []}
        cursor = root
        for index in range(18):
            child = {"path": f"/dev/vda{index + 1}", "type": "part", "children": []}
            cursor["children"].append(child)
            cursor = child
        with patch("aegis.hardware.shutil.which", return_value="/usr/bin/lsblk"), \\
             patch("aegis.hardware.subprocess.run",
                   return_value=CompletedProcess([], 0, json.dumps({"blockdevices": [root]}), "")):
            with self.assertRaisesRegex(HardwareInspectionError, "topology exceeds safety limits"):
                read_disks()

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

    def test_live_assessment_normalizes_real_lsblk_leaf_nodes(self):
        from aegis.inventory import assess_inventory

        root = {
            "path": "/dev/vda", "type": "disk", "serial": "SERIAL-A", "wwn": "WWN-A",
            "mountpoints": [None],
            # lsblk omits children on a real leaf disk.
        }

        def enrich(node, _swap):
            node["holders"] = []
            node["active_swap"] = False
            node["ambiguous"] = False

        with patch("aegis.hardware.read_disks", return_value=[root]), \
             patch("aegis.hardware._active_swap_devices", return_value=set()), \
             patch("aegis.hardware._enrich_block_node", side_effect=enrich):
            observation = read_assessment_observation()

        self.assertEqual(observation["devices"][0]["children"], [])
        result = assess_inventory(observation)
        self.assertEqual(result["status"], "review_required")
        self.assertFalse(result["write_authorized"])

    def test_live_assessment_preserves_explicitly_malformed_children(self):
        root = {
            "path": "/dev/vda", "type": "disk", "serial": "SERIAL-A", "wwn": "WWN-A",
            "mountpoints": [None], "children": {"unexpected": "mapping"},
        }

        with patch("aegis.hardware.read_disks", return_value=[root]), \
             patch("aegis.hardware._active_swap_devices", return_value=set()), \
             patch("aegis.hardware._enrich_block_node") as enrich:
            observation = read_assessment_observation()

        self.assertEqual(observation["devices"][0]["children"], {"unexpected": "mapping"})
        enrich.assert_called_once()
        from aegis.inventory import assess_inventory
        self.assertEqual(assess_inventory(observation)["status"], "blocked")

    def test_live_assessment_fails_closed_on_excessive_topology(self):
        root = {"path": "/dev/vda", "type": "disk", "children": []}
        cursor = root
        for index in range(18):
            child = {"path": f"/dev/vda{index + 1}", "type": "part", "children": []}
            cursor["children"].append(child)
            cursor = child
        with patch("aegis.hardware.read_disks", return_value=[root]), \
             patch("aegis.hardware._active_swap_devices") as swap, \
             patch("aegis.hardware._enrich_block_node") as enrich:
            result = read_assessment_observation()
        self.assertTrue(result["devices"][0]["ambiguous"])
        self.assertIsNone(result["devices"][0]["holders"])
        self.assertIsNone(result["devices"][0]["active_swap"])
        swap.assert_not_called()
        enrich.assert_not_called()

    def test_live_assessment_fails_closed_on_excessive_node_count(self):
        root = {"path": "/dev/vda", "type": "disk",
                "children": [{"path": f"/dev/vda{i}", "type": "part", "children": []}
                             for i in range(4097)]}
        with patch("aegis.hardware.read_disks", return_value=[root]), \
             patch("aegis.hardware._active_swap_devices") as swap, \
             patch("aegis.hardware._enrich_block_node") as enrich:
            result = read_assessment_observation()
        self.assertTrue(result["devices"][0]["ambiguous"])
        swap.assert_not_called()
        enrich.assert_not_called()

    @patch("aegis.hardware.shutil.which", return_value=None)
    def test_lsblk_required(self, _which):
        with self.assertRaises(HardwareInspectionError):
            read_disks()

    @patch("aegis.hardware.subprocess.run")
    def test_run_readonly_rejected_command(self, mock_run):
        with self.assertRaises(HardwareInspectionError) as ctx:
            _run_readonly(["fdisk", "-l"])
        self.assertIn("not on the read-only allowlist", str(ctx.exception))
        mock_run.assert_not_called()

    @patch("aegis.hardware.subprocess.run")
    def test_run_readonly_lspci_without_flags_rejected(self, mock_run):
        # Allowlist strictly requires ("lspci", "-nn"); unflagged lspci must fail closed
        with self.assertRaises(HardwareInspectionError) as ctx:
            _run_readonly(["lspci"])
        self.assertIn("not on the read-only allowlist", str(ctx.exception))
        mock_run.assert_not_called()

    @patch("aegis.hardware.subprocess.run")
    def test_run_readonly_command_tampering(self, mock_run):
        # Even variations of lsblk arguments must be rejected
        with self.assertRaises(HardwareInspectionError) as ctx:
            _run_readonly(["lsblk", "--all"])
        self.assertIn("not on the read-only allowlist", str(ctx.exception))
        mock_run.assert_not_called()


    @patch("aegis.hardware.subprocess.run", side_effect=SubprocessError("Command timeout"))
    def test_run_readonly_subprocess_error(self, _run):
        with self.assertRaises(HardwareInspectionError) as ctx:
            _run_readonly(["lspci", "-nn"])
        self.assertIn("Read-only probe failed", str(ctx.exception))

    @patch("aegis.hardware.shutil.which", return_value="/usr/bin/lsblk")
    @patch("aegis.hardware._run_readonly", return_value="not valid json")
    def test_read_disks_invalid_json(self, _run, _which):
        with self.assertRaises(HardwareInspectionError) as ctx:
            read_disks()
        self.assertIn("invalid JSON", str(ctx.exception))

    @patch("aegis.hardware.shutil.which", return_value="/usr/bin/lsblk")
    @patch("aegis.hardware._run_readonly", return_value="[1, 2, 3]")
    def test_read_disks_unexpected_json_root(self, _run, _which):
        with self.assertRaises(HardwareInspectionError) as ctx:
            read_disks()
        self.assertIn("unexpected device structure", str(ctx.exception))

    @patch("aegis.hardware.shutil.which", return_value="/usr/bin/lsblk")
    @patch("aegis.hardware._run_readonly", return_value='{"blockdevices": "not_a_list"}')
    def test_read_disks_blockdevices_not_list(self, _run, _which):
        with self.assertRaises(HardwareInspectionError) as ctx:
            read_disks()
        self.assertIn("unexpected device structure", str(ctx.exception))

    @patch("aegis.hardware.shutil.which", return_value="/usr/bin/lsblk")
    @patch("aegis.hardware._run_readonly", return_value='{"blockdevices": []}')
    def test_read_disks_empty(self, _run, _which):
        self.assertEqual(read_disks(), [])

    @patch("aegis.hardware.Path.read_text", side_effect=OSError("Simulated read error"))
    def test_read_text_catches_oserror(self, _mock_read):
        self.assertEqual(_read_text("/proc/simulated"), "")



class InspectIntegrationTests(unittest.TestCase):
    """Test full inspect() integration, schema compliance, and platform gating."""

    def test_inspect_requires_linux(self):
        with patch("aegis.hardware.platform.system", return_value="Windows"):
            with self.assertRaises(HardwareInspectionError) as ctx:
                inspect()
            self.assertIn("Hardware inspection requires Linux", str(ctx.exception))

    def test_inspect_schema_and_keys(self):
        with patch("aegis.hardware.platform.system", return_value="Linux"), \
             patch("aegis.hardware.platform.machine", return_value="x86_64"), \
             patch("aegis.hardware._cpu_label", return_value="Test CPU 8-Core"), \
             patch("aegis.hardware._memory_mib", return_value=16384), \
             patch("aegis.hardware._tpm_version", return_value="2.0-detected-unverified"), \
             patch("aegis.hardware._secure_boot_state", return_value="enabled-reported"), \
             patch("aegis.hardware._gpu_summary", return_value=["VGA compatible controller: Test GPU"]), \
             patch("aegis.hardware.read_disks", return_value=[{"path": "/dev/nvme0n1", "type": "disk"}]), \
             patch("aegis.hardware.Path.exists", return_value=True):

            data = inspect()

        self.assertEqual(data["schema_version"], "0.2")
        self.assertEqual(data["architecture"], "x86_64")
        self.assertEqual(data["cpu"], "Test CPU 8-Core")
        self.assertEqual(data["ram_mib"], 16384)
        self.assertTrue(data["uefi_detected"])
        self.assertTrue(data["tpm_device_detected"])
        self.assertEqual(data["tpm_version"], "2.0-detected-unverified")
        self.assertEqual(data["secure_boot_state"], "enabled-reported")
        self.assertEqual(len(data["gpu_devices"]), 1)
        self.assertEqual(len(data["disks"]), 1)
        self.assertIsInstance(data["notes"], list)
        self.assertGreaterEqual(len(data["notes"]), 3)

    def test_inspect_tpm_device_detected_logic(self):
        for version, expected in [
            ("2.0-detected-unverified", True),
            ("1.2-detected", True),
            ("not-detected", False),
            ("unknown", False),
        ]:
            with self.subTest(tpm_version=version), \
                 patch("aegis.hardware.platform.system", return_value="Linux"), \
                 patch("aegis.hardware._tpm_version", return_value=version), \
                 patch("aegis.hardware._cpu_label", return_value="CPU"), \
                 patch("aegis.hardware._memory_mib", return_value=1024), \
                 patch("aegis.hardware._secure_boot_state", return_value="unverified"), \
                 patch("aegis.hardware._gpu_summary", return_value=[]), \
                 patch("aegis.hardware.read_disks", return_value=[]), \
                 patch("aegis.hardware.Path.exists", return_value=False):

                data = inspect()
                self.assertEqual(data["tpm_device_detected"], expected)


if __name__ == "__main__":
    unittest.main()
