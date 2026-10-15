"""Tests for evidence-gated, non-executing optimization review."""
from __future__ import annotations

import copy
import unittest

from aegis.optimization import OptimizationReviewError, build_optimization_review


def measure(**overrides):
    result = {
        "hardware_fingerprint": "lab-cpu-gpu-001",
        "benchmark": "fixed-scene-1080p",
        "samples": 5,
        "median_fps": 100,
        "p95_frame_ms": 12,
        "max_temp_c": 70,
        "stability_passed": True,
    }
    result.update(overrides)
    return result


class OptimizationReviewTests(unittest.TestCase):
    def setUp(self):
        self.inventory = {"architecture": "x86_64", "cpu": "Example CPU"}

    def test_missing_evidence_requests_baseline(self):
        result = build_optimization_review(self.inventory, "gaming")
        self.assertEqual(result["status"], "MEASURE_FIRST")
        self.assertIn("BASELINE_AND_CANDIDATE_EVIDENCE_REQUIRED", result["reason_codes"])
        self.assertFalse(result["execution_enabled"])
        self.assertFalse(result["system_changes_performed"])

    def test_clear_improvement_is_only_eligible_for_human_review(self):
        result = build_optimization_review(
            self.inventory, "gaming", measure(),
            measure(median_fps=105, p95_frame_ms=11.5, max_temp_c=73),
        )
        self.assertEqual(result["status"], "ELIGIBLE_FOR_HUMAN_REVIEW")
        self.assertTrue(result["recommended_changes"][0]["requires_human_approval"])
        self.assertTrue(result["recommended_changes"][0]["requires_rollback_plan"])
        self.assertFalse(result["execution_enabled"])

    def test_fingerprint_mismatch_blocks_comparison(self):
        result = build_optimization_review(
            self.inventory, "vr", measure(),
            measure(hardware_fingerprint="different-system", median_fps=150),
        )
        self.assertEqual(result["status"], "BLOCKED")
        self.assertIn("HARDWARE_FINGERPRINT_MISMATCH", result["reason_codes"])

    def test_different_benchmarks_block_comparison(self):
        result = build_optimization_review(
            self.inventory, "gaming", measure(),
            measure(benchmark="different-scene", median_fps=150),
        )
        self.assertEqual(result["status"], "BLOCKED")
        self.assertIn("BENCHMARK_MISMATCH", result["reason_codes"])

    def test_failed_stability_gate_blocks_candidate(self):
        result = build_optimization_review(
            self.inventory, "gaming", measure(),
            measure(median_fps=150, stability_passed=False),
        )
        self.assertEqual(result["status"], "BLOCKED")
        self.assertIn("STABILITY_GATE_FAILED", result["reason_codes"])

    def test_thermal_regression_blocks_candidate(self):
        result = build_optimization_review(
            self.inventory, "gaming", measure(),
            measure(median_fps=110, p95_frame_ms=11, max_temp_c=76),
        )
        self.assertEqual(result["status"], "BLOCKED")
        self.assertIn("THERMAL_REGRESSION_GATE_FAILED", result["reason_codes"])

    def test_small_gain_or_frame_time_regression_is_not_recommended(self):
        cases = [
            measure(median_fps=102, p95_frame_ms=11),
            measure(median_fps=110, p95_frame_ms=12.5),
        ]
        for candidate in cases:
            with self.subTest(candidate=candidate):
                result = build_optimization_review(self.inventory, "gaming", measure(), candidate)
                self.assertEqual(result["status"], "NO_CLEAR_IMPROVEMENT")
                self.assertEqual(result["recommended_changes"], [])

    def test_invalid_and_nonfinite_metrics_fail_closed(self):
        for candidate in (measure(samples=2), measure(median_fps=float("nan")),
                          measure(stability_passed="yes")):
            with self.subTest(candidate=candidate), self.assertRaises(OptimizationReviewError):
                build_optimization_review(self.inventory, "gaming", measure(), candidate)

    def test_unknown_workload_rejected(self):
        with self.assertRaises(OptimizationReviewError):
            build_optimization_review(self.inventory, "turbo", measure(), measure())

    def test_input_is_not_mutated(self):
        before, after = measure(), measure(median_fps=105, p95_frame_ms=11)
        snapshot = copy.deepcopy((before, after, self.inventory))
        build_optimization_review(self.inventory, "gaming", before, after)
        self.assertEqual((before, after, self.inventory), snapshot)


if __name__ == "__main__":
    unittest.main()
