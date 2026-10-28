"""
Unit and Adversarial Acceptance Tests for Sandbox Telemetry Comparator (Milestone 3 Disentangled).
"""

import copy
import json
import unittest
from pathlib import Path

from engine.models import (
    CausalExplanation,
    CollectionLimitation,
    EvidencePointer,
    NetworkObservation,
    NormalizedReport,
    ObservationPresence,
    ProcessMatchConfidence,
    ProcessObservation,
)
from engine.parsers.cape_parser import parse_cape_report
from engine.parsers.falcon_parser import parse_falcon_report
from engine.provenance import resolve_json_pointer
from engine.reconciler import EvidenceComparator
from engine.vt_benchmark import VTBenchmarkEvaluator


class TestMilestone3Comparator(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        parent_dir = Path(__file__).resolve().parent
        base_dir = parent_dir.parent if (parent_dir.parent / "data").exists() else parent_dir
        with open(base_dir / "data/report_format_a_cape.json", "r") as f:
            cls.raw_cape = json.load(f)
        with open(base_dir / "data/report_format_b_falcon.json", "r") as f:
            cls.raw_falcon = json.load(f)
        with open(base_dir / "data/virustotal_behavior_summary_reference.json", "r") as f:
            cls.raw_vt = json.load(f)

        cls.norm_cape = parse_cape_report(cls.raw_cape, "report_a_cape")
        cls.norm_falcon = parse_falcon_report(cls.raw_falcon, "report_b_falcon")
        cls.comparator = EvidenceComparator(cls.norm_cape, cls.norm_falcon)
        cls.comparison = cls.comparator.reconcile()
        cls.vt_evaluator = VTBenchmarkEvaluator(cls.comparison, cls.raw_vt)
        cls.vt_benchmark = cls.vt_evaluator.evaluate_capabilities()

    def test_criterion_1_rfc6901_pointer_compliance_and_resolution(self):
        for proc in self.norm_cape.processes:
            ptr = proc.evidence.json_pointer
            self.assertTrue(ptr.startswith("/"), f"Pointer '{ptr}' must start with '/'")
            resolved = resolve_json_pointer(self.raw_cape, ptr)
            self.assertEqual(resolved["process_id"], proc.source_pid)

        for df in self.norm_cape.dropped_files:
            ptr = df.evidence.json_pointer
            self.assertTrue(ptr.startswith("/"), f"Pointer '{ptr}' must start with '/'")
            resolved = resolve_json_pointer(self.raw_cape, ptr)
            self.assertEqual(resolved["sha256"], df.sha256)

        for proc in self.norm_falcon.processes:
            ptr = proc.evidence.json_pointer
            self.assertTrue(ptr.startswith("/"), f"Pointer '{ptr}' must start with '/'")
            resolved = resolve_json_pointer(self.raw_falcon, ptr)
            self.assertEqual(resolved["pid"], proc.source_pid)

        for cf in self.norm_falcon.dropped_files:
            ptr = cf.evidence.json_pointer
            self.assertTrue(ptr.startswith("/"), f"Pointer '{ptr}' must start with '/'")
            resolved = resolve_json_pointer(self.raw_falcon, ptr)
            self.assertEqual(resolved["sha256_hash"], cf.sha256)

    def test_criterion_2_match_file_by_sha256_across_different_names(self):
        target_hash = "a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0"
        matched = [f for f in self.comparison.reconciled_files if f.sha256 == target_hash]
        self.assertEqual(len(matched), 1)

        file_item = matched[0]
        self.assertEqual(file_item.observation_presence, ObservationPresence.OBSERVED_IN_BOTH)
        self.assertEqual(file_item.causal_explanation, CausalExplanation.CORROBORATED_EXECUTION)
        self.assertEqual(file_item.filenames_by_report["report_a_cape"], "update_payload.exe")
        self.assertEqual(file_item.filenames_by_report["report_b_falcon"], "staged_runner.bin")

        self.assertEqual(file_item.evidence_links["report_a_cape"].json_pointer, "/behavior/dropped/0")
        self.assertEqual(file_item.evidence_links["report_b_falcon"].json_pointer, "/execution/created_files/0")

    def test_criterion_3_calibrated_process_matching_standard(self):
        matched_procs = [p for p in self.comparison.reconciled_processes if p.confidence in [ProcessMatchConfidence.MATCHED, ProcessMatchConfidence.POSSIBLE_MATCH]]
        self.assertGreaterEqual(len(matched_procs), 3)

        ps = [p for p in matched_procs if p.image_name == "powershell.exe"][0]
        self.assertEqual(ps.pids_by_report["report_a_cape"], 4156)
        self.assertEqual(ps.pids_by_report["report_b_falcon"], 8896)
        self.assertGreaterEqual(ps.heuristic_similarity_score, 0.70)

    def test_adversarial_duplicate_powershell_instances(self):
        norm_b_adv = copy.deepcopy(self.norm_falcon)
        benign_ps = ProcessObservation(
            report_id="report_b_falcon",
            source_pid=9999,
            source_ppid=7112,
            image_name="powershell.exe",
            command_line="powershell.exe -Command Get-ComputerInfo; Get-Date",
            lineage_path=["invoice_oct2026.exe", "powershell.exe"],
            tree_depth=2,
            evidence=EvidencePointer(
                report_id="report_b_falcon",
                json_pointer="/execution/process_tree/0/children/1",
                event_summary="Benign PS discovery",
                raw_snippet={}
            )
        )
        norm_b_adv.processes.append(benign_ps)

        comp = EvidenceComparator(self.norm_cape, norm_b_adv).reconcile()
        ps_cape = [p for p in comp.reconciled_processes if p.image_name == "powershell.exe" and p.pids_by_report.get("report_a_cape") == 4156][0]

        self.assertEqual(ps_cape.pids_by_report.get("report_b_falcon"), 8896)

    def test_adversarial_missing_intermediate_wrapper_node(self):
        proc_a = ProcessObservation(
            report_id="rep_a",
            source_pid=100,
            source_ppid=50,
            image_name="powershell.exe",
            command_line="powershell.exe -ExecutionPolicy Bypass -File script.ps1",
            lineage_path=["invoice.exe", "cmd.exe", "powershell.exe"],
            tree_depth=3,
            evidence=EvidencePointer("rep_a", "/procs/1", "A PS", {})
        )
        proc_b = ProcessObservation(
            report_id="rep_b",
            source_pid=200,
            source_ppid=50,
            image_name="powershell.exe",
            command_line="powershell.exe -ExecutionPolicy Bypass -File script.ps1",
            lineage_path=["invoice.exe", "powershell.exe"],
            tree_depth=2,
            evidence=EvidencePointer("rep_b", "/procs/0", "B PS", {})
        )

        rep_a = NormalizedReport("rep_a", "A", "schema", "DOC", "hash", 60, processes=[proc_a])
        rep_b = NormalizedReport("rep_b", "B", "schema", "SYN", "hash", 60, processes=[proc_b])

        comp = EvidenceComparator(rep_a, rep_b).reconcile()
        matched = comp.reconciled_processes[0]
        self.assertIn(matched.confidence, [ProcessMatchConfidence.MATCHED, ProcessMatchConfidence.POSSIBLE_MATCH])
        self.assertEqual(matched.pids_by_report["rep_a"], 100)
        self.assertEqual(matched.pids_by_report["rep_b"], 200)

    def test_criterion_4_disentangled_policy_vs_limitation(self):
        c2 = [n for n in self.comparison.reconciled_network if "8080" in n.connection_key][0]
        self.assertEqual(c2.observation_presence, ObservationPresence.OBSERVED_ONLY_IN_A)
        self.assertEqual(c2.causal_explanation, CausalExplanation.POLICY_DECISION_RECORDED)
        self.assertIsNotNone(c2.policy_decision_record)
        self.assertIn("8080", c2.policy_decision_record)

        mutex_file = [f for f in self.comparison.reconciled_files if "mutex_flag" in f.filenames_by_report.get("report_a_cape", "")][0]
        self.assertEqual(mutex_file.observation_presence, ObservationPresence.OBSERVED_ONLY_IN_A)
        self.assertEqual(mutex_file.causal_explanation, CausalExplanation.POTENTIAL_ENVIRONMENT_LIMITATION)

    def test_epistemic_negative_attribution_safety(self):
        dns_event = NetworkObservation(
            report_id="rep_a",
            protocol="DNS",
            destination="c2-backup-domain.org",
            port=53,
            evidence=EvidencePointer("rep_a", "/net/dns/0", "DNS", {})
        )
        rep_a = NormalizedReport("rep_a", "A", "schema", "DOC", "hash", 60, network_events=[dns_event])
        rep_b = NormalizedReport(
            "rep_b", "B", "schema", "SYN", "hash", 120,
            network_events=[],
            limitations=[
                CollectionLimitation("rep_b", "WARN_EGRESS", "Blocked port 8080 egress", "EGRESS_POLICY", target_pattern="port:8080")
            ]
        )

        comp = EvidenceComparator(rep_a, rep_b).reconcile()
        dns_res = comp.reconciled_network[0]

        self.assertEqual(dns_res.observation_presence, ObservationPresence.OBSERVED_ONLY_IN_A)
        self.assertEqual(dns_res.causal_explanation, CausalExplanation.UNEXPLAINED)
        self.assertIsNone(dns_res.policy_decision_record)

    def test_criterion_6_fair_virustotal_benchmark_and_workflow_metrics(self):
        matrix = self.vt_benchmark["matrix"]
        self.assertTrue(matrix["file_reconciliation"]["prototype"]["automated"])
        self.assertFalse(matrix["file_reconciliation"]["virustotal_individual_reports"]["automated"])

        timing = self.vt_benchmark["measured_runtime_benchmark"]
        self.assertGreater(timing["end_to_end_runtime_ms"]["mean"], 0.0)
        self.assertLess(timing["end_to_end_runtime_ms"]["mean"], 50.0)


if __name__ == "__main__":
    unittest.main()
