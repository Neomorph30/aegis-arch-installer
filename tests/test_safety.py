import copy
from pathlib import Path
import json
import unittest

from aegis.planner import (PlanError, ALIGNMENT, EFI_SIZE_BYTES,
                           GPT_HEADROOM_BYTES, build_storage_plan)
from aegis.reporting import html_report, public_view
from aegis.profiles import recommend

FIXTURE = json.loads((Path(__file__).resolve().parent.parent / "fixtures" / "desktop-example.json").read_text())


def plan(**kwargs):
    return build_storage_plan(copy.deepcopy(FIXTURE), "/dev/nvme0n1", **kwargs)


class StorageSafetyTests(unittest.TestCase):
    def test_primary_layout_end_exclusive_ranges_aligned(self):
        p = plan()
        partitions = p["actions"][0]["partitions"]
        self.assertEqual(partitions[0]["offset_bytes"], ALIGNMENT)
        self.assertEqual(partitions[0]["size_bytes"], EFI_SIZE_BYTES)
        self.assertEqual(partitions[0]["end_exclusive_bytes"], partitions[1]["offset_bytes"])
        self.assertLess(partitions[1]["end_exclusive_bytes"], FIXTURE["disks"][0]["size"] - GPT_HEADROOM_BYTES + ALIGNMENT)
        for partition in partitions:
            self.assertEqual(partition["offset_bytes"] % ALIGNMENT, 0)
            self.assertEqual(partition["size_bytes"] % ALIGNMENT, 0)
        self.assertEqual(p["review_state"], "REQUIRES_EXPLICIT_APPROVAL")
        self.assertFalse(p["execution_enabled"])

    def test_ext4_proposes_no_btrfs_subvolumes(self):
        p = plan(filesystem="ext4")
        self.assertEqual(p["actions"][0]["partitions"][1]["filesystem"], "ext4")
        self.assertEqual(p["btrfs_subvolumes"], [])

    def test_rejects_invalid_filesystem(self):
        with self.assertRaises(PlanError):
            plan(filesystem="zfs")

    def test_secondary_preserves_existing_by_default(self):
        p = plan(secondary="/dev/sda")
        self.assertEqual(p["actions"][1]["action"], "preserve")
        self.assertEqual(p["actions"][1]["partitions"], [])

    def test_secondary_erase_layout(self):
        p = plan(secondary="/dev/sda", secondary_action="erase")
        self.assertTrue(p["actions"][1]["destructive"])
        self.assertEqual(p["actions"][1]["partitions"][0]["mount"], "/data")
        self.assertEqual(p["review_state"], "REQUIRES_EXPLICIT_APPROVAL")

    def test_archiso_usb_blocks_primary(self):
        # The USB is smaller than min; make it large enough to exercise exclusion.
        inv = copy.deepcopy(FIXTURE)
        inv["disks"][2]["size"] = 128 * 1024**3
        p = build_storage_plan(inv, "/dev/sdb")
        self.assertEqual(p["review_state"], "BLOCKED")
        self.assertTrue(any("installation-media" in s or "installer" in s for s in p["blockers"]))

    def test_mounted_root_is_blocked(self):
        inv = copy.deepcopy(FIXTURE)
        inv["disks"][0]["children"][0]["mountpoints"] = ["/"]
        p = build_storage_plan(inv, "/dev/nvme0n1")
        self.assertEqual(p["review_state"], "BLOCKED")
        self.assertTrue(any("mounted device" in s for s in p["blockers"]))

    def test_blank_serial_and_wwn_block(self):
        inv = copy.deepcopy(FIXTURE)
        inv["disks"][0]["serial"] = None
        inv["disks"][0]["wwn"] = None
        self.assertEqual(build_storage_plan(inv, "/dev/nvme0n1")["review_state"], "BLOCKED")

    def test_readonly_disk_blocks(self):
        inv = copy.deepcopy(FIXTURE)
        inv["disks"][0]["ro"] = True
        self.assertEqual(build_storage_plan(inv, "/dev/nvme0n1")["review_state"], "BLOCKED")

    def test_secondary_erase_mounted_is_blocked(self):
        inv = copy.deepcopy(FIXTURE)
        inv["disks"][1]["children"][0]["mountpoints"] = ["/mnt/games"]
        p = build_storage_plan(inv, "/dev/nvme0n1", "/dev/sda", "erase")
        self.assertTrue(any("secondary: mounted" in s for s in p["blockers"]))

    def test_secondary_preserve_mount_warn_not_block(self):
        inv = copy.deepcopy(FIXTURE)
        inv["disks"][1]["children"][0]["mountpoints"] = ["/mnt/games"]
        p = build_storage_plan(inv, "/dev/nvme0n1", "/dev/sda")
        self.assertEqual(p["review_state"], "REQUIRES_EXPLICIT_APPROVAL")
        self.assertTrue(any("mounted volumes" in s for s in p["warnings"]))

    def test_colliding_serial_blocks(self):
        inv = copy.deepcopy(FIXTURE)
        inv["disks"][1]["serial"] = inv["disks"][0]["serial"]
        with self.assertRaises(PlanError):
            build_storage_plan(inv, "/dev/nvme0n1", "/dev/sda")

    def test_invalid_secondary_size_rejected(self):
        inv = copy.deepcopy(FIXTURE)
        inv["disks"][1]["size"] = -1
        with self.assertRaises(PlanError):
            build_storage_plan(inv, "/dev/nvme0n1", "/dev/sda", "erase")

    def test_duplicate_paths_rejected(self):
        inv = copy.deepcopy(FIXTURE)
        inv["disks"].append(copy.deepcopy(inv["disks"][0]))
        with self.assertRaises(PlanError):
            build_storage_plan(inv, "/dev/nvme0n1")

    def test_uefi_required_profile_block(self):
        inv = copy.deepcopy(FIXTURE)
        inv["uefi_detected"] = False
        p = build_storage_plan(inv, "/dev/nvme0n1")
        self.assertEqual(p["review_state"], "BLOCKED")

    def test_unsupported_architecture_block(self):
        inv = copy.deepcopy(FIXTURE)
        inv["architecture"] = "aarch64"
        self.assertEqual(build_storage_plan(inv, "/dev/nvme0n1")["review_state"], "BLOCKED")

    def test_secondary_action_requires_disk(self):
        with self.assertRaises(PlanError):
            plan(secondary_action="erase")

    def test_unexecuted_statuses_only(self):
        p = plan()
        self.assertFalse(p["execution_enabled"])
        self.assertTrue(all(t["result"] != "PASSED" for t in p["tests"]))


class ReportSafetyTests(unittest.TestCase):
    def test_html_denies_installed_claim(self):
        p = plan()
        p["status"] = "SUCCESS"
        with self.assertRaises(ValueError):
            html_report(p)

    def test_html_denies_executable_plan(self):
        p = plan()
        p["execution_enabled"] = True
        with self.assertRaises(ValueError):
            html_report(p)

    def test_shareable_redacts_serial_and_wwn(self):
        html = html_report(plan())
        self.assertNotIn("EXAMPLE-NVME-0001", html)
        self.assertNotIn("example-wwn-nvme", html)
        self.assertIn("[REDACTED]", html)

    def test_private_html_includes_hardware_identifiers(self):
        self.assertIn("EXAMPLE-NVME-0001", html_report(plan(), shareable=False))

    def test_escapes_html_and_credentials(self):
        p = plan()
        p["warnings"].append(
            "<script>alert('no')</script> password=hunter2 "
            "private_key=PRIVATE-MATERIAL api_key=API-MATERIAL credential=LOGIN-MATERIAL"
        )
        rendered = html_report(p)
        self.assertNotIn("<script>", rendered)
        for secret in ("hunter2", "PRIVATE-MATERIAL", "API-MATERIAL", "LOGIN-MATERIAL"):
            with self.subTest(secret=secret):
                self.assertNotIn(secret, rendered)
        self.assertIn("&lt;script&gt;", rendered)

    def test_sensitive_keys_redacted(self):
        values = {
            "password": "not-safe",
            "tpm_pin": "123456",
            "nested": {"secret": "abc"},
            "TPM-PIN": "pin-here",
            "private-key": "private-here",
            "api key": "api-here",
            "luks_recovery_key": "recovery-here",
        }
        redacted = public_view(values)
        self.assertEqual(redacted["password"], "[REDACTED]")
        self.assertEqual(redacted["nested"]["secret"], "[REDACTED]")
        for key, secret in (
            ("TPM-PIN", "pin-here"),
            ("private-key", "private-here"),
            ("api key", "api-here"),
            ("luks_recovery_key", "recovery-here"),
        ):
            with self.subTest(key=key):
                self.assertEqual(redacted[key], "[REDACTED]")


    def test_compound_luks_recovery_key_assignment_is_redacted(self):
        p = plan()
        p["warnings"].append("luks_recovery_key=RECOVERY-MATERIAL")
        rendered = html_report(p)
        self.assertNotIn("RECOVERY-MATERIAL", rendered)
        self.assertIn("luks_recovery_key=[REDACTED]", rendered)

    def test_html_rejects_forged_passed_or_unknown_verification_status(self):
        for result in ("PASSED", "PASS", "SUCCESS", "verified"):
            with self.subTest(result=result):
                p = plan()
                p["tests"][0]["result"] = result
                with self.assertRaisesRegex(ValueError, "verification status"):
                    html_report(p)

    def test_html_rejects_missing_verification_evidence(self):
        p = plan()
        del p["tests"]
        with self.assertRaisesRegex(ValueError, "verification test evidence is missing"):
            html_report(p)

    def test_html_rejects_non_list_verification_evidence(self):
        p = plan()
        p["tests"] = {"name": "not a list", "result": "SKIPPED"}
        with self.assertRaisesRegex(ValueError, "verification tests must be a list"):
            html_report(p)

    def test_html_rejects_malformed_verification_entries(self):
        for entry in ("SKIPPED", None, [], {"name": " ", "result": "SKIPPED"}):
            with self.subTest(entry=entry):
                p = plan()
                p["tests"] = [entry]
                with self.assertRaises(ValueError):
                    html_report(p)

    def test_html_accepts_not_applicable_status(self):
        p = plan()
        p["tests"] = [{"name": "unsupported optional control", "result": "NOT_APPLICABLE"}]
        self.assertIn("NOT_APPLICABLE", html_report(p))

    def test_html_accepts_explicit_non_pass_proposal_statuses(self):
        p = plan()
        p["tests"] = [
            {"name": "future control", "result": "SKIPPED"},
            {"name": "unrun control", "result": "UNVERIFIED"},
            {"name": "blocked control", "result": "BLOCKED"},
            {"name": "failed preflight", "result": "FAILED"},
        ]
        rendered = html_report(p)
        for status in ("SKIPPED", "UNVERIFIED", "BLOCKED", "FAILED"):
            self.assertIn(status, rendered)

    def test_seeded_secret_variants_never_appear_in_shareable_html_or_json_view(self):
        p = plan()
        p["diagnostic_metadata"] = {
            "tpm-pin": "SEED_TPM_PIN_7f31",
            "luks_recovery_key": "SEED_LUKS_RECOVERY_2a9c",
            "signing_private_key": "SEED_SIGNING_PRIVATE_6b14",
            "api_key": "SEED_API_TOKEN_4d82",
            "nested": [
                {"password": "SEED_PASSWORD_8c23"},
                {"notes": "credential=SEED_CREDENTIAL_5e17"},
                {"detail": "token:SEED_TOKEN_1a90"},
            ],
        }
        json_view = json.dumps(public_view(p), sort_keys=True)
        html = html_report(p, shareable=True)
        for secret in (
            "SEED_TPM_PIN_7f31", "SEED_LUKS_RECOVERY_2a9c",
            "SEED_SIGNING_PRIVATE_6b14", "SEED_API_TOKEN_4d82",
            "SEED_PASSWORD_8c23", "SEED_CREDENTIAL_5e17", "SEED_TOKEN_1a90",
        ):
            with self.subTest(secret=secret):
                self.assertNotIn(secret, json_view)
                self.assertNotIn(secret, html)

    def test_report_never_invents_passed_test_evidence(self):
        p = plan()
        self.assertTrue(all(item.get("result") != "PASSED" for item in p["tests"]))
        rendered = html_report(p)
        self.assertNotIn(">PASSED</td>", rendered)
        self.assertIn("NOT EXECUTED OR VERIFIED", rendered)

    def test_shareable_json_view_redacts_hardware_identifiers_recursively(self):
        value = {
            "device": {"serial": "SEED_SERIAL_1", "wwn": "SEED_WWN_2"},
            "nested": [{"mac_address": "SEED_MAC_3", "part_uuid": "SEED_PARTUUID_4"}],
        }
        encoded = json.dumps(public_view(value, shareable=True), sort_keys=True)
        for secret in ("SEED_SERIAL_1", "SEED_WWN_2", "SEED_MAC_3", "SEED_PARTUUID_4"):
            with self.subTest(secret=secret):
                self.assertNotIn(secret, encoded)


class ProfileTests(unittest.TestCase):
    def test_nvidia_not_assumed_compatible(self):
        p = recommend(FIXTURE)
        self.assertIn("nvidia", p["detected_gpu_vendors"])
        self.assertNotIn("nvidia-open-dkms", p["package_candidates"])
        self.assertIn("linux-zen", p["package_candidates"])
        self.assertIn("steam", p["package_candidates"])
        self.assertEqual(p["optimization"]["status"], "NOT_RUN")

    def test_workstation_excludes_gaming(self):
        p = recommend(FIXTURE, "secure-workstation")
        self.assertNotIn("steam", p["package_candidates"])
        self.assertNotIn("linux-zen", p["package_candidates"])

    def test_hybrid_gpu_requires_review(self):
        inv = copy.deepcopy(FIXTURE)
        inv["gpu_devices"].append("Intel Corporation VGA compatible controller")
        self.assertTrue(any("Hybrid" in s for s in recommend(inv)["notes"]))

    def test_unknown_gpu_requires_review(self):
        inv = copy.deepcopy(FIXTURE)
        inv["gpu_devices"] = []
        self.assertTrue(any("unknown" in s for s in recommend(inv)["notes"]))

    def test_unknown_profile_rejected(self):
        with self.assertRaises(ValueError):
            recommend(FIXTURE, "turbo-no-mitigations")


if __name__ == "__main__":
    unittest.main()
