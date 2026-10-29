#!/usr/bin/env python3
"""
Reproducible Benchmark Suite for Sandbox Comparator.
Benchmarks both the Python reconciliation engine and the compiled native Rust binary
across N iterations against the reference report fixtures.
Outputs execution latencies, percentile breakdowns, and environment metadata.
"""

import json
import os
import platform
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from engine.timing_benchmark import ExecutionBenchmark


def get_percentile(sorted_list: List[float], p: float) -> float:
    if not sorted_list:
        return 0.0
    k = (len(sorted_list) - 1) * (p / 100.0)
    f = int(k)
    c = min(f + 1, len(sorted_list) - 1)
    d0 = sorted_list[f] * (c - k)
    d1 = sorted_list[c] * (k - f)
    return d0 + d1


def benchmark_rust_cli(iterations: int = 50, warmup_runs: int = 5) -> Dict[str, Any]:
    rust_dir = BASE_DIR / "rust"
    rust_bin = rust_dir / "target/release/sandbox-comparator"
    if not rust_bin.exists():
        print("Compiling Rust release binary for benchmarking...")
        subprocess.run(["cargo", "build", "--release"], cwd=rust_dir, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    report_a = BASE_DIR / "data/report_format_a_cape.json"
    report_b = BASE_DIR / "data/report_format_b_falcon.json"

    cmd = [
        str(rust_bin),
        "--report-a", str(report_a),
        "--report-b", str(report_b),
        "--format", "json"
    ]

    for _ in range(warmup_runs):
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)

    latencies_ms: List[float] = []
    for _ in range(iterations):
        t0 = time.perf_counter()
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        t1 = time.perf_counter()
        latencies_ms.append((t1 - t0) * 1000.0)

    latencies_ms.sort()
    return {
        "iterations": iterations,
        "mean_ms": round(sum(latencies_ms) / len(latencies_ms), 3),
        "median_ms": round(get_percentile(latencies_ms, 50), 3),
        "p95_ms": round(get_percentile(latencies_ms, 95), 3),
        "min_ms": round(latencies_ms[0], 3),
        "max_ms": round(latencies_ms[-1], 3),
    }


def main():
    iterations = 50
    print(f"Running Sandbox Comparator benchmarks (N={iterations} iterations)...")
    print(f"Platform: {platform.system()} {platform.machine()} | Python {platform.python_version()}")

    path_a = BASE_DIR / "data/report_format_a_cape.json"
    path_b = BASE_DIR / "data/report_format_b_falcon.json"
    size_a_kb = round(path_a.stat().st_size / 1024, 2)
    size_b_kb = round(path_b.stat().st_size / 1024, 2)

    py_results = ExecutionBenchmark.run_benchmark(iterations=iterations, warmup_runs=10)
    rust_results = benchmark_rust_cli(iterations=iterations, warmup_runs=5)

    phases = py_results["disaggregated_phases_ms"]
    e2e = py_results["end_to_end_runtime_ms"]

    print("\n" + "=" * 76)
    print("                      BENCHMARK RESULTS")
    print("=" * 76)
    print(f"Test Fixtures: CAPE ({size_a_kb} KB), Falcon ({size_b_kb} KB)")
    print(f"Iterations:    {iterations} (excluding warmup runs)\n")

    print(f"{'Engine':<20} | {'Phase':<32} | {'Mean (ms)':<10} | {'Median (ms)':<10}")
    print("-" * 76)
    print(f"{'Python':<20} | {'Schema Parsing & Normalization':<32} | {phases['schema_parsing_and_normalization']['mean']:<10.3f} | {phases['schema_parsing_and_normalization']['median']:<10.3f}")
    print(f"{'Python':<20} | {'Entity Matching & Reconcile':<32} | {phases['entity_matching_and_reconciliation']['mean']:<10.3f} | {phases['entity_matching_and_reconciliation']['median']:<10.3f}")
    print(f"{'Python':<20} | {'RFC 6901 Pointer Verification':<32} | {phases['rfc6901_pointer_verification']['mean']:<10.3f} | {phases['rfc6901_pointer_verification']['median']:<10.3f}")
    print(f"{'Python':<20} | {'File I/O':<32} | {phases['file_io']['mean']:<10.3f} | {phases['file_io']['median']:<10.3f}")
    print(f"{'Python (In-Memory)':<20} | {'End-to-End Execution':<32} | {e2e['mean']:<10.3f} | {e2e['median']:<10.3f}")
    print(f"{'Python (p95)':<20} | {'End-to-End 95th Percentile':<32} | {e2e['p95']:<10.3f} | {'-':<10}")
    print("-" * 76)
    print(f"{'Rust Core CLI':<20} | {'Full CLI Process (Spawn+I/O)':<32} | {rust_results['mean_ms']:<10.3f} | {rust_results['median_ms']:<10.3f}")
    print(f"{'Rust Core CLI (p95)':<20} | {'CLI Process 95th Percentile':<32} | {rust_results['p95_ms']:<10.3f} | {'-':<10}")
    print("=" * 76)
    print("Note: In-memory Python includes JSON parse + reconciliation; Rust CLI includes OS process spawn, disk I/O, parse, reconciliation, and stdout JSON serialization.\n")


if __name__ == "__main__":
    main()
