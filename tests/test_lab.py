"""Layer 02: tests only use synthetic images in private temporary directories."""
from __future__ import annotations

from pathlib import Path
import os
import stat
import tempfile
import unittest
from unittest.mock import patch

from lab.runtime import (
    LabConfig, LabError, _copy_regular_file, _exclusive_sparse_file,
    command_lines, dependencies, find_firmware, prepare_workspace,
    main,
)

GIB = 1024**3


class ConfigTests(unittest.TestCase):
    def test_valid_defaults(self):
        LabConfig().validate()

    def test_invalid_hardware_limits(self):
        for kw in ({'ram_mib': 0}, {'ram_mib': 9000}, {'cpus': 0}, {'cpus': 5},
                   {'primary_bytes': 100}, {'secondary_bytes': 0},
                   {'primary_bytes': 129 * GIB}, {'seconds': 0}, {'seconds': 31}):
            with self.subTest(kw=kw), self.assertRaises(LabError):
                LabConfig(**kw).validate()

    def test_dependency_inspection_cannot_start_vm(self):
        with patch('lab.runtime.shutil.which', return_value=None):
            result = dependencies()
        self.assertFalse(result['qemu_present'])
        self.assertFalse(result['arch_installer_enabled'])
        self.assertFalse(result['host_passthrough_enabled'])

    def test_pair_selection_never_mixes_firmware(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            code = p / 'CODE.fd'
            vars = p / 'VARS.fd'
            code.write_bytes(b'CODE')
            vars.write_bytes(b'VARS')
            self.assertEqual(find_firmware([(str(code), str(vars))]), (code, vars))
            vars.unlink()
            self.assertIsNone(find_firmware([(str(code), str(vars))]))

    def test_firmware_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)
            c = p / 'real-code'
            c.write_bytes(b'CODE')
            symlink = p / 'CODE.fd'
            symlink.symlink_to(c)
            v = p / 'VARS.fd'
            v.write_bytes(b'VARS')
            self.assertIsNone(find_firmware([(str(symlink), str(v))]))


class WorkspaceTests(unittest.TestCase):
    def _firmware(self, root):
        c = root / 'OVMF_CODE.src'
        v = root / 'OVMF_VARS.src'
        c.write_bytes(b'CODE')
        v.write_bytes(b'VARS')
        return c, v

    def test_preparation_sparse_private_files_and_tpm_dir(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            # TemporaryDirectory generally mode 0700; explicitly reinforce it.
            work = root / 'private'
            work.mkdir(mode=0o700)
            fw = self._firmware(root)
            config = LabConfig(primary_bytes=GIB, secondary_bytes=GIB)
            output = prepare_workspace(work, config, fw, iso=None)
            self.assertEqual(output['primary'].stat().st_size, GIB)
            self.assertEqual(output['secondary'].stat().st_size, GIB)
            self.assertEqual(output['vars'].read_bytes(), b'VARS')
            self.assertEqual(output['primary'].stat().st_mode & 0o777, 0o600)
            self.assertEqual(output['tpm_dir'].stat().st_mode & 0o777, 0o700)
            self.assertNotIn('iso', output)
            tpm, vm = command_lines(config, fw, output)
            joined = ' '.join(vm)
            self.assertIn('-nic none', joined)
            self.assertIn('q35,accel=tcg', joined)
            self.assertEqual(joined.count('virtio-blk-pci,drive='), 2)
            self.assertIn('serial=AEGIS-LAB-PRIMARY', joined)
            self.assertIn('serial=AEGIS-LAB-SECONDARY', joined)
            self.assertIn('node-name=secondary_file,filename=', joined)
            self.assertIn('read-only=on', joined)
            self.assertNotIn('/dev/sd', joined)
            self.assertNotIn('if=virtio,file=/dev/', joined)
            self.assertIn('startup-clear', tpm)
            self.assertIn('readonly=on', joined)
            self.assertIn('-display none', joined)
            self.assertIn('-nic none', joined)
            self.assertIn('-display gtk', ' '.join(command_lines(config, fw, output, interactive=True)[1]))
            _, observed_vm = command_lines(config, fw, output, observe_boot=True)
            observed = ' '.join(observed_vm)
            self.assertIn('-display vnc=127.0.0.1:0', observed)
            self.assertNotIn('-display gtk', observed)
            self.assertIn('-nic none', observed)
            self.assertNotIn('hostfwd=', observed)

    def test_explicit_user_nat_is_opt_in_and_has_no_port_forwarding(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            work = root / 'private'
            work.mkdir(mode=0o700)
            fw = self._firmware(root)
            output = prepare_workspace(work, LabConfig(primary_bytes=GIB, secondary_bytes=GIB), fw, None)
            _, vm = command_lines(LabConfig(primary_bytes=GIB, secondary_bytes=GIB), fw, output,
                                  network_mode='user-nat-explicit')
            joined = ' '.join(vm)
            self.assertIn('-nic user,model=virtio-net-pci', joined)
            self.assertNotIn('hostfwd=', joined)
            self.assertNotIn('-nic none', joined)

    def test_unknown_network_mode_fails_closed(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            work = root / 'private'
            work.mkdir(mode=0o700)
            fw = self._firmware(root)
            output = prepare_workspace(work, LabConfig(primary_bytes=GIB, secondary_bytes=GIB), fw, None)
            with self.assertRaisesRegex(LabError, 'Unsupported network mode'):
                command_lines(LabConfig(primary_bytes=GIB, secondary_bytes=GIB), fw, output,
                              network_mode='bridged')

    def test_private_workspace_required(self):
        with tempfile.TemporaryDirectory() as d:
            folder = Path(d) / 'world-readable'
            folder.mkdir(mode=0o755)
            fw = self._firmware(Path(d))
            with self.assertRaisesRegex(LabError, 'non-private'):
                prepare_workspace(folder, LabConfig(), fw, None)

    def test_symlink_workspace_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            good = Path(d) / 'good'
            good.mkdir(mode=0o700)
            link = Path(d) / 'link'
            link.symlink_to(good, target_is_directory=True)
            fw = self._firmware(Path(d))
            with self.assertRaises(LabError):
                prepare_workspace(link, LabConfig(), fw, None)

    def test_existing_disk_never_overwritten(self):
        with tempfile.TemporaryDirectory() as d:
            dest = Path(d) / 'primary.raw'
            dest.write_text('no overwrite')
            with self.assertRaises(FileExistsError):
                _exclusive_sparse_file(dest, GIB)
            self.assertEqual(dest.read_text(), 'no overwrite')

    def test_block_device_and_symlink_input_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            dst = Path(d) / 'out'
            with self.assertRaises(LabError):
                _copy_regular_file(Path('/dev/null'), dst, max_bytes=100)
            real = Path(d) / 'small.iso'
            real.write_bytes(b'fake image')
            link = Path(d) / 'symlink.iso'
            link.symlink_to(real)
            with self.assertRaises(OSError):
                _copy_regular_file(link, dst, max_bytes=100)
            self.assertFalse(dst.exists())

    def test_iso_copy_and_size_limit(self):
        with tempfile.TemporaryDirectory() as d:
            source = Path(d) / 'example.iso'
            source.write_bytes(b'fake data')
            with self.assertRaises(LabError):
                _copy_regular_file(source, Path(d) / 'too-small', max_bytes=4)
            dst = Path(d) / 'copy'
            self.assertEqual(_copy_regular_file(source, dst, max_bytes=128), 9)
            self.assertEqual(dst.read_bytes(), b'fake data')
            self.assertEqual(dst.stat().st_mode & 0o777, 0o600)

    def test_preexisting_symlink_cannot_be_replaced(self):
        with tempfile.TemporaryDirectory() as d:
            protected = Path(d) / 'target'
            protected.write_bytes(b'preserve')
            alias = Path(d) / 'disk.raw'
            alias.symlink_to(protected)
            with self.assertRaises(OSError):
                _exclusive_sparse_file(alias, GIB)
            self.assertEqual(protected.read_bytes(), b'preserve')

    def test_manually_edited_disk_path_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            work = root / 'private'
            work.mkdir(mode=0o700)
            fw = self._firmware(root)
            output = prepare_workspace(work, LabConfig(primary_bytes=GIB, secondary_bytes=GIB), fw, None)
            output['primary'] = Path('/dev/sda')
            with self.assertRaisesRegex(LabError, 'Unexpected primary path'):
                command_lines(LabConfig(), fw, output)

    def test_unsafe_comma_in_directory_rejected(self):
        with tempfile.TemporaryDirectory(prefix='unsafe,') as d:
            root = Path(d)
            work = root / 'private'
            work.mkdir(mode=0o700)
            fw = self._firmware(root)
            output = prepare_workspace(work, LabConfig(primary_bytes=GIB, secondary_bytes=GIB), fw, None)
            with self.assertRaisesRegex(LabError, 'Unsupported character'):
                command_lines(LabConfig(), fw, output)


class CLITests(unittest.TestCase):
    def test_check_requires_no_vm_runtime(self):
        with patch('lab.runtime.dependencies', return_value={'qemu_present': False}):
            self.assertEqual(main(['--check']), 0)

    def test_no_arguments_refuses_launch(self):
        with self.assertRaises(SystemExit) as cm:
            main([])
        self.assertEqual(cm.exception.code, 2)

    def test_root_refused_without_starting_vm(self):
        with patch('lab.runtime.os.geteuid', return_value=0), patch('lab.runtime.subprocess.Popen', side_effect=AssertionError('started!')):
            self.assertEqual(main(['--smoke']), 2)

    def test_missing_dependencies_refuse(self):
        with patch('lab.runtime.os.geteuid', return_value=1000), patch('lab.runtime.dependencies', return_value={k: False for k in ('qemu_present', 'swtpm_present','ovmf_pair_present')}):
            self.assertEqual(main(['--smoke']), 2)

    def test_boot_observation_requires_smoke_mode(self):
        self.assertEqual(main(['--run', '--observe-boot', '--iso', '/missing.iso', '--iso-sha256', '0' * 64]), 2)

if __name__ == '__main__':
    unittest.main()

class QMPTests(unittest.TestCase):
    def test_status_and_tpm_queries_with_local_mock(self):
        import json
        import socket
        import threading
        from lab.runtime import query_qmp
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'qmp.sock'
            server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            server.bind(str(path))
            server.listen(1)
            commands = []
            def answer():
                with server:
                    client, _ = server.accept()
                    with client, client.makefile('rwb') as stream:
                        stream.write(b'{"QMP":{"version":{"qemu":{}},"capabilities":[]}}\n')
                        stream.flush()
                        for reply in (b'{"return":{}}\n', b'{"return":{"status":"running"}}\n',
                                      b'{"return":[{"id":"tpm0","model":"tpm-tis"}]}\n'):
                            request = json.loads(stream.readline())
                            commands.append(request['execute'])
                            stream.write(reply)
                            stream.flush()
            thread = threading.Thread(target=answer, daemon=True)
            thread.start()
            self.assertEqual(query_qmp(path), {'qmp_running': True, 'qmp_tpm_detected': True})
            thread.join(timeout=2)
            self.assertEqual(commands, ['qmp_capabilities', 'query-status', 'query-tpm'])

    def test_missing_tpm_fails_closed(self):
        import json
        import socket
        import threading
        from lab.runtime import query_qmp
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'qmp.sock'
            server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            server.bind(str(path))
            server.listen(1)
            def answer():
                with server:
                    client, _ = server.accept()
                    with client, client.makefile('rwb') as stream:
                        stream.write(b'{"QMP":{}}\n')
                        stream.flush()
                        for reply in (b'{"return":{}}\n', b'{"return":{"status":"running"}}\n', b'{"return":[]}\n'):
                            stream.readline()
                            stream.write(reply)
                            stream.flush()
            thread = threading.Thread(target=answer, daemon=True)
            thread.start()
            with self.assertRaisesRegex(LabError, 'virtual TPM'):
                query_qmp(path)
            thread.join(timeout=2)
