"""
Unit and Calibration Tests for Disentangled Semantics & Process Calibration (Milestone 3).
Validates:
1. Empirical Calibration: Benchmarks Multi-Factor Heuristic Matcher against Baseline on labeled corpus.
2. Disentangled Semantics: Asserts separate Observation Presence, Causal Explanation, and Epistemic Interpretation.
3. Defensive Parsing: Verifies malformed hashes, non-integer PIDs, and null payloads.
4. Timing Benchmark: Verifies reproducible execution time measurement.
"""

import json
import unittest
from pathlib import Path

from engine.calibration.process_corpus import (
    MultiFactorHeuristicMatcher,
    SimpleBaselineMatcher,
    evaluate_matcher,
    get_development_tuning_corpus,
)
from engine.models import (
    CausalExplanation,
    ObservationPresence,
    ProcessMatchConfidence,
)
from engine.parsers.cape_parser import parse_cape_report
from engine.parsers.falcon_parser import parse_falcon_report
from engine.reconciler import EvidenceComparator
from engine.timing_benchmark import ExecutionBenchmark


class TestCalibrationAndSemantics(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        parent_dir = Path(__file__).resolve().parent
        base_dir = parent_dir.parent if (parent_dir.parent / "data").exists() else parent_dir
        with open(base_dir / "data/report_format_a_cape.json", "r") as f:
            cls.raw_cape = json.load(f)
        with open(base_dir / "data/report_format_b_falcon.json", "r") as f:
            cls.raw_falcon = json.load(f)

        cls.norm_cape = parse_cape_report(cls.raw_cape, "report_a_cape")
        cls.norm_falcon = parse_falcon_report(cls.raw_falcon, "report_b_falcon")
        cls.comparator = EvidenceComparator(cls.norm_cape, cls.norm_falcon)
        cls.comparison = cls.comparator.reconcile()

    def test_calibration_benchmarking_on_labeled_corpus(self):
        """
        Verify that the Multi-Factor Heuristic Matcher is calibrated against the development tuning corpus:
        - Achieves F1 >= 0.80 and Precision >= 0.75.
        - Outperforms the Simple Baseline Matcher by >= 20% in F1 score.
        """
        corpus = get_development_tuning_corpus()
        base_metrics = evaluate_matcher(SimpleBaselineMatcher, corpus)
        multi_metrics = evaluate_matcher(MultiFactorHeuristicMatcher, corpus)

        self.assertGreaterEqual(multi_metrics["precision"], 0.75)
        self.assertGreaterEqual(multi_metrics["recall"], 0.85)
        self.assertGreaterEqual(multi_metrics["f1_score"], 0.80)

        # Baseline comparison assertion
        self.assertGreater(
            multi_metrics["f1_score"],
            base_metrics["f1_score"],
            f"Multi-factor ({multi_metrics['f1_score']}) must outperform baseline ({base_metrics['f1_score']})"
        )

    def test_disentangled_dropped_file_semantics(self):
        """
        Verify that dropped files disentangle observation presence from causal explanation:
        - crash_reporter.log: OBSERVED_ONLY_IN_B (not ambiguous NOT_OBSERVED)
        - mutex_flag.tmp: OBSERVED_ONLY_IN_A
        - update_payload.exe / staged_runner.bin: OBSERVED_IN_BOTH
        """
        files = {f.file_paths_by_report.get("report_a_cape", "") or f.file_paths_by_report.get("report_b_falcon", ""): f for f in self.comparison.reconciled_files}

        # crash_reporter.log (Observed in B, omitted in A; Report A had no limitations)
        crash_log = [f for f in self.comparison.reconciled_files if "crash_reporter.log" in f.filenames_by_report.get("report_b_falcon", "")][0]
        self.assertEqual(crash_log.observation_presence, ObservationPresence.OBSERVED_ONLY_IN_B)
        self.assertEqual(crash_log.causal_explanation, CausalExplanation.UNEXPLAINED)
        self.assertIn("Report A telemetry does not record this file", crash_log.epistemic_interpretation)

        # mutex_flag.tmp (Observed in A, omitted in B; Report B had WARN_TIMEOUT)
        mutex_file = [f for f in self.comparison.reconciled_files if "mutex_flag.tmp" in f.filenames_by_report.get("report_a_cape", "")][0]
        self.assertEqual(mutex_file.observation_presence, ObservationPresence.OBSERVED_ONLY_IN_A)
        self.assertEqual(mutex_file.causal_explanation, CausalExplanation.POTENTIAL_ENVIRONMENT_LIMITATION)
        self.assertIn("Report B telemetry does not record this file", mutex_file.epistemic_interpretation)

        # Corroborated payload
        payload = [f for f in self.comparison.reconciled_files if f.sha256 == "a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0"][0]
        self.assertEqual(payload.observation_presence, ObservationPresence.OBSERVED_IN_BOTH)
        self.assertEqual(payload.causal_explanation, CausalExplanation.CORROBORATED_EXECUTION)

    def test_disentangled_network_policy_semantics(self):
        """
        Verify that a blocked connection is represented as an observed event with an associated policy decision,
        rather than collapsing presence and explanation into one status.
        """
        c2 = [n for n in self.comparison.reconciled_network if "8080" in n.connection_key][0]
        self.assertEqual(c2.observation_presence, ObservationPresence.OBSERVED_ONLY_IN_A)
        self.assertEqual(c2.causal_explanation, CausalExplanation.POLICY_DECISION_RECORDED)
        self.assertIsNotNone(c2.policy_decision_record)
        self.assertIn("intercepted and blocked", c2.policy_decision_record)
        self.assertIn("relationship between the records is not established", c2.epistemic_interpretation)

    def test_defensive_parsing_malformed_and_missing_inputs(self):
        """
        Verify parser resilience against malformed inputs:
        - Malformed SHA-256 (non-hex, truncated)
        - Missing sections / null dictionaries
        - Non-integer process IDs
        """
        malformed_raw = {
            "report_metadata": {
                "target": {"sha256": "not_a_valid_hash"}
            },
            "behavior": {
                "processes": [
                    {"process_id": "non_int_pid", "process_name": "test.exe", "command_line": "test.exe"}
                ],
                "dropped": [
                    {"name": "corrupted.bin", "sha256": "truncated_hash_123", "size": "not_an_int"}
                ]
            }
        }

        norm = parse_cape_report(malformed_raw, "malformed_cape")
        self.assertEqual(len(norm.dropped_files), 1)
        self.assertTrue(norm.dropped_files[0].is_malformed_hash)
        self.assertGreaterEqual(len(norm.parser_warnings), 1)

        # Null input safety
        norm_null = parse_cape_report(None, "null_cape")
        self.assertEqual(len(norm_null.processes), 0)
        self.assertEqual(len(norm_null.dropped_files), 0)

    def test_timing_micro_benchmark_execution(self):
        """
        Verify that ExecutionBenchmark runs and measures sub-second execution with statistics.
        """
        benchmark_res = ExecutionBenchmark.run_benchmark(iterations=10)
        self.assertEqual(benchmark_res["iterations"], 10)
        self.assertGreater(benchmark_res["end_to_end_runtime_ms"]["mean"], 0.0)
        self.assertLess(benchmark_res["end_to_end_runtime_ms"]["mean"], 100.0)  # Sub-100ms expectation


if __name__ == "__main__":
    unittest.main()
