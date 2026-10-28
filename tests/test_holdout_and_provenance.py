"""
Unit, Holdout Calibration, and Provenance Verification Tests (Milestone 4).
Validates:
1. Holdout Evaluation Set Accuracy: Tests Multi-Factor Heuristic Matcher on 16 unseen pairs.
2. Port 8080 Provenance Integrity: Asserts observation pointer in Report A and policy warning pointer in Report B.
3. Neutral Telemetry Semantics: Asserts absence of premature C2 conclusions.
4. Disaggregated Timing Metrics: Measures discrete pipeline phase latencies and p95.
"""

import json
import unittest
from pathlib import Path

from engine.calibration.process_corpus import (
    MultiFactorHeuristicMatcher,
    SimpleBaselineMatcher,
    evaluate_matcher,
    get_holdout_evaluation_corpus,
)
from engine.models import (
    CausalExplanation,
    ObservationPresence,
)
from engine.parsers.cape_parser import parse_cape_report
from engine.parsers.falcon_parser import parse_falcon_report
from engine.provenance import resolve_json_pointer
from engine.reconciler import EvidenceComparator
from engine.timing_benchmark import ExecutionBenchmark


class TestHoldoutAndProvenance(unittest.TestCase):
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

    def test_holdout_evaluation_corpus_accuracy(self):
        """
        Verify that the Multi-Factor Heuristic Matcher generalizes to the 16-pair Holdout Evaluation Set:
        - Achieves F1 >= 0.80 and Precision >= 0.75.
        - Reduces the false-match rate compared to the Simple Baseline (0.25 vs 0.875).
        """
        holdout_corpus = get_holdout_evaluation_corpus()
        base_res = evaluate_matcher(SimpleBaselineMatcher, holdout_corpus)
        multi_res = evaluate_matcher(MultiFactorHeuristicMatcher, holdout_corpus)

        self.assertGreaterEqual(multi_res["precision"], 0.75)
        self.assertGreaterEqual(multi_res["recall"], 0.85)
        self.assertGreaterEqual(multi_res["f1_score"], 0.80)

        # Baseline comparison
        self.assertLess(
            multi_res["false_match_rate"],
            base_res["false_match_rate"],
            "Multi-factor matcher must achieve lower false match rate than baseline on holdout set"
        )
        self.assertGreater(
            multi_res["f1_score"],
            base_res["f1_score"],
            "Multi-factor matcher must achieve higher F1 score than baseline on holdout set"
        )

    def test_port_8080_provenance_integrity(self):
        """
        Verify that the port 8080 network item has strict, non-contradictory provenance:
        - Observation presence is OBSERVED_ONLY_IN_A.
        - Observation evidence links to Report A (/behavior/network/tcp/1).
        - Policy decision record links to Report B (/submission_info/system_warnings/1).
        - Both pointers resolve bidirectionally in their respective raw documents.
        """
        item_8080 = [n for n in self.comparison.reconciled_network if "8080" in n.connection_key][0]

        # 1. Observation status
        self.assertEqual(item_8080.observation_presence, ObservationPresence.OBSERVED_ONLY_IN_A)
        self.assertEqual(item_8080.causal_explanation, CausalExplanation.POLICY_DECISION_RECORDED)

        # 2. Source evidence in Report A
        ptr_a = item_8080.evidence_links["report_a_cape"]
        self.assertTrue(ptr_a.is_available)
        self.assertEqual(ptr_a.json_pointer, "/behavior/network/tcp/1")
        resolved_a = resolve_json_pointer(self.raw_cape, ptr_a.json_pointer)
        self.assertEqual(resolved_a["dst_port"], 8080)
        self.assertEqual(resolved_a["dst_ip"], "203.0.113.88")

        # 3. Policy decision evidence in Report B
        ptr_policy = item_8080.policy_decision_evidence
        self.assertIsNotNone(ptr_policy)
        self.assertEqual(ptr_policy.report_id, "report_b_falcon")
        self.assertEqual(ptr_policy.json_pointer, "/submission_info/system_warnings/1")
        resolved_b = resolve_json_pointer(self.raw_falcon, ptr_policy.json_pointer)
        self.assertIn("8080", resolved_b["description"])

    def test_neutral_telemetry_semantics_no_c2_speculation(self):
        """
        Verify that the engine does NOT label raw socket streams as 'C2' or 'Command and Control'
        as a definitive telemetry fact; it must maintain neutral socket labels and separate
        telemetry from analytical interpretation.
        """
        item_8080 = [n for n in self.comparison.reconciled_network if "8080" in n.connection_key][0]
        self.assertTrue(item_8080.connection_key.startswith("TCP://"))
        self.assertNotIn("Custom_C2", item_8080.connection_key)
        self.assertIn("relationship between the records is not established", item_8080.epistemic_interpretation)
        self.assertEqual(item_8080.cross_report_correlation, "CONTEXTUAL_SIMILARITY_ONLY")
        self.assertEqual(item_8080.causal_status, "PLAUSIBLE_HYPOTHESIS")

    def test_disaggregated_timing_metrics(self):
        """
        Verify that the timing benchmark measures all discrete pipeline phases with p95.
        """
        benchmark = ExecutionBenchmark.run_benchmark(iterations=25)
        phases = benchmark["disaggregated_phases_ms"]

        self.assertIn("file_io", phases)
        self.assertIn("schema_parsing_and_normalization", phases)
        self.assertIn("entity_matching_and_reconciliation", phases)
        self.assertIn("rfc6901_pointer_verification", phases)

        self.assertGreater(phases["file_io"]["mean"], 0.0)
        self.assertGreater(phases["schema_parsing_and_normalization"]["mean"], 0.0)
        self.assertGreater(phases["entity_matching_and_reconciliation"]["mean"], 0.0)

        end_to_end = benchmark["end_to_end_runtime_ms"]
        self.assertGreater(end_to_end["p95"], 0.0)
        self.assertGreater(end_to_end["median"], 0.0)

    def test_holdout_corpus_audit_and_confidence_intervals(self):
        """
        Audit verification:
        1. All 16 holdout pairs have documented ground-truth rationales.
        2. All 16 holdout pairs specify provenance families and confirm tuning independence.
        3. Evaluator outputs exact Clopper-Pearson 95% confidence intervals.
        """
        from engine.calibration.process_corpus import (
            MultiFactorHeuristicMatcher,
            evaluate_matcher,
            get_holdout_evaluation_corpus,
        )
        holdout = get_holdout_evaluation_corpus()
        self.assertEqual(len(holdout), 16)

        for pair in holdout:
            self.assertTrue(len(pair.ground_truth_rationale) > 10, f"Pair {pair.pair_id} lacks detailed rationale")
            self.assertTrue(len(pair.provenance_family) > 3, f"Pair {pair.pair_id} lacks provenance family")
            self.assertEqual(pair.tuning_influence, "NONE_HELD_OUT", f"Pair {pair.pair_id} violated tuning holdout")

        results = evaluate_matcher(MultiFactorHeuristicMatcher, holdout)
        self.assertEqual(results["true_positives"], 8)
        self.assertEqual(results["recall"], 1.0)
        # Recall 8/8 95% exact Clopper-Pearson CI is (63.1, 100.0)
        self.assertEqual(results["recall_95_ci"], (63.1, 100.0))
        # Precision 8/10 (8 TP, 2 FP) 95% CI is (44.4, 97.5)
        self.assertEqual(results["precision_95_ci"], (44.4, 97.5))
        # False Match Rate 2/8 (2 FP, 6 TN) 95% CI is (3.2, 65.1)
        self.assertEqual(results["false_match_rate_95_ci"], (3.2, 65.1))

    def test_ground_truth_key_pointer_and_hash_integrity(self):
        """
        Verify that all pointers cited in the Ground-Truth Key resolve to exact 64-char
        hexadecimal digests, matching PIDs, and system warnings.
        """
        target_hash = "a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0"

        # 1. Scenario X Dropped payload identity
        node_a_drop = resolve_json_pointer(self.raw_cape, "/behavior/dropped/0")
        self.assertEqual(node_a_drop["sha256"], target_hash)
        self.assertEqual(node_a_drop["name"], "update_payload.exe")

        node_b_drop = resolve_json_pointer(self.raw_falcon, "/execution/created_files/0")
        self.assertEqual(node_b_drop["sha256_hash"], target_hash)
        self.assertTrue(node_b_drop["filename"].endswith("staged_runner.bin"))

        # 2. Scenario X Process alignment
        node_a_proc = resolve_json_pointer(self.raw_cape, "/behavior/processes/2")
        self.assertEqual(node_a_proc["process_id"], 4156)
        self.assertEqual(node_a_proc["process_name"], "powershell.exe")

        node_b_proc = resolve_json_pointer(self.raw_falcon, "/execution/process_tree/0/children/0/children/0")
        self.assertEqual(node_b_proc["pid"], 8896)
        self.assertEqual(node_b_proc["name"], "powershell.exe")

        # 3. Scenario X Network & Policy
        node_a_net = resolve_json_pointer(self.raw_cape, "/behavior/network/tcp/1")
        self.assertEqual(node_a_net["dst_ip"], "203.0.113.88")
        self.assertEqual(node_a_net["dst_port"], 8080)

        node_b_warn = resolve_json_pointer(self.raw_falcon, "/submission_info/system_warnings/1")
        self.assertEqual(node_b_warn["code"], "WARN_EGRESS_POLICY")
        self.assertIn("8080", node_b_warn["description"])


if __name__ == "__main__":
    unittest.main()


