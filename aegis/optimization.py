"""Evidence-gated adaptive optimization review.

This module only evaluates supplied benchmark evidence. It never changes the host,
executes commands, selects kernel parameters, or claims universal best settings.
"""
from __future__ import annotations

import math
from typing import Any

SCHEMA_VERSION = 1
WORKLOADS = frozenset({"gaming", "vr", "workstation", "balanced", "battery"})
MIN_SAMPLES = 3
MIN_IMPROVEMENT_PERCENT = 3.0
MAX_ALLOWED_TEMP_DELTA_C = 5.0


class OptimizationReviewError(ValueError):
    """Optimization input is malformed or outside the reviewed policy."""


def _finite_number(value: Any, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise OptimizationReviewError(f"{field} must be a number")
    number = float(value)
    if not math.isfinite(number):
        raise OptimizationReviewError(f"{field} must be finite")
    return number


def _validate_measurement(record: Any, label: str) -> dict[str, Any]:
    if not isinstance(record, dict):
        raise OptimizationReviewError(f"{label} measurement must be an object")
    fingerprint = record.get("hardware_fingerprint")
    benchmark = record.get("benchmark")
    samples = record.get("samples")
    if not isinstance(fingerprint, str) or not fingerprint.strip():
        raise OptimizationReviewError(f"{label} hardware fingerprint is required")
    if not isinstance(benchmark, str) or not benchmark.strip():
        raise OptimizationReviewError(f"{label} benchmark name is required")
    if isinstance(samples, bool) or not isinstance(samples, int) or samples < MIN_SAMPLES:
        raise OptimizationReviewError(f"{label} needs at least {MIN_SAMPLES} samples")
    fps = _finite_number(record.get("median_fps"), f"{label}.median_fps")
    frame_time = _finite_number(record.get("p95_frame_ms"), f"{label}.p95_frame_ms")
    temperature = _finite_number(record.get("max_temp_c"), f"{label}.max_temp_c")
    if fps <= 0 or frame_time <= 0 or temperature < -20 or temperature > 150:
        raise OptimizationReviewError(f"{label} metrics are outside plausible input bounds")
    stable = record.get("stability_passed")
    if not isinstance(stable, bool):
        raise OptimizationReviewError(f"{label}.stability_passed must be boolean")
    return {
        "hardware_fingerprint": fingerprint,
        "benchmark": benchmark,
        "samples": samples,
        "median_fps": fps,
        "p95_frame_ms": frame_time,
        "max_temp_c": temperature,
        "stability_passed": stable,
    }


def build_optimization_review(
    inventory: dict[str, Any],
    workload: str,
    baseline: dict[str, Any] | None = None,
    candidate: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Return a conservative review record; no optimization is ever applied."""
    if not isinstance(inventory, dict):
        raise OptimizationReviewError("Hardware inventory must be an object")
    if workload not in WORKLOADS:
        raise OptimizationReviewError("Unknown workload profile")
    architecture = inventory.get("architecture", "unknown")
    cpu = inventory.get("cpu")
    if not isinstance(architecture, str) or not architecture:
        architecture = "unknown"
    if not isinstance(cpu, str) or not cpu.strip():
        cpu = "unknown"

    result: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "status": "MEASURE_FIRST",
        "workload": workload,
        "hardware": {"architecture": architecture, "cpu": cpu},
        "execution_enabled": False,
        "system_changes_performed": False,
        "recommended_changes": [],
        "reason_codes": [],
        "rollback_required": True,
        "limitations": [
            "Evidence evaluator only; it does not run benchmarks or change system settings.",
            "A hardware fingerprint is caller-supplied evidence, not cryptographic device attestation.",
            "A passing benchmark does not establish security, long-term stability, or universal compatibility.",
            "Thermal limits and vendor-specific power controls require hardware-specific qualification.",
        ],
    }

    if baseline is None or candidate is None:
        result["reason_codes"].append("BASELINE_AND_CANDIDATE_EVIDENCE_REQUIRED")
        return result

    before = _validate_measurement(baseline, "baseline")
    after = _validate_measurement(candidate, "candidate")
    if before["hardware_fingerprint"] != after["hardware_fingerprint"]:
        result["status"] = "BLOCKED"
        result["reason_codes"].append("HARDWARE_FINGERPRINT_MISMATCH")
        return result
    if before["benchmark"] != after["benchmark"]:
        result["status"] = "BLOCKED"
        result["reason_codes"].append("BENCHMARK_MISMATCH")
        return result
    if not before["stability_passed"] or not after["stability_passed"]:
        result["status"] = "BLOCKED"
        result["reason_codes"].append("STABILITY_GATE_FAILED")
        return result

    fps_gain = (after["median_fps"] - before["median_fps"]) / before["median_fps"] * 100
    frame_time_change = (after["p95_frame_ms"] - before["p95_frame_ms"]) / before["p95_frame_ms"] * 100
    temp_delta = after["max_temp_c"] - before["max_temp_c"]
    result["evidence"] = {
        "samples_per_run": min(before["samples"], after["samples"]),
        "median_fps_change_percent": round(fps_gain, 2),
        "p95_frame_time_change_percent": round(frame_time_change, 2),
        "maximum_temperature_delta_c": round(temp_delta, 2),
    }

    if temp_delta > MAX_ALLOWED_TEMP_DELTA_C:
        result["status"] = "BLOCKED"
        result["reason_codes"].append("THERMAL_REGRESSION_GATE_FAILED")
        return result
    if fps_gain < MIN_IMPROVEMENT_PERCENT or frame_time_change > 0:
        result["status"] = "NO_CLEAR_IMPROVEMENT"
        result["reason_codes"].append("PERFORMANCE_GAIN_NOT_CLEAR")
        return result

    result["status"] = "ELIGIBLE_FOR_HUMAN_REVIEW"
    result["reason_codes"].append("MEASURED_GAIN_WITHIN_INITIAL_POLICY")
    result["recommended_changes"].append({
        "change_id": "review_candidate_configuration",
        "action": "REVIEW_ONLY",
        "reason": "Candidate improved median FPS and did not regress p95 frame time beyond this initial policy.",
        "requires_human_approval": True,
        "requires_retest_after_apply": True,
        "requires_rollback_plan": True,
    })
    return result
