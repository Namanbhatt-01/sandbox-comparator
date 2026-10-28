"""
Unit test suite verifying engine hardening and epistemic rigor (Milestone 5 -> Product MVP).
Validates:
1. Duplicate SHA-256 file drop preservation (no silent overwrite).
2. Honest network telemetry semantics (no unwarranted ESTABLISHED/CONFIRMED overclaims).
3. Order-independent process tree bipartite matching.
4. Dynamic schema autodetection (CAPE vs Falcon vs Unknown).
5. Generalized egress policy port extraction.
"""

import unittest
from engine.models import (
    DroppedFileObservation,
    EvidencePointer,
    NetworkObservation,
    NormalizedReport,
    ProcessObservation,
)
from engine.parsers import detect_schema, parse_auto_report
from engine.parsers.falcon_parser import parse_falcon_report
from engine.reconciler import EvidenceComparator


class TestEngineHardening(unittest.TestCase):

    def setUp(self):
        self.dummy_pointer = EvidencePointer(
            report_id="test",
            json_pointer="/test",
            event_summary="Test event",
            raw_snippet={}
        )

    def test_duplicate_hash_no_loss(self):
        """
        Verify that multiple dropped files sharing the same SHA-256 (e.g. dropped to 2 locations)
        are both preserved in reconciliation and not silently overwritten.
        """
        shared_hash = "a" * 64
        rep_a = NormalizedReport(
            report_id="rep_a",
            sandbox_name="CAPE",
            schema_format="cape_json_v2",
            schema_provenance_type="DOCUMENTED_VENDOR_FORMAT",
            sample_sha256="sample_hash",
            duration_seconds=60,
            dropped_files=[
                DroppedFileObservation("rep_a", shared_hash, "C:\\Temp\\drop1.exe", "drop1.exe", 100, "PE32", self.dummy_pointer),
                DroppedFileObservation("rep_a", shared_hash, "C:\\Public\\drop2.exe", "drop2.exe", 100, "PE32", self.dummy_pointer),
            ]
        )
        rep_b = NormalizedReport(
            report_id="rep_b",
            sandbox_name="Falcon",
            schema_format="falcon_v7",
            schema_provenance_type="SYNTHETIC_APPROXIMATION",
            sample_sha256="sample_hash",
            duration_seconds=60,
            dropped_files=[
                DroppedFileObservation("rep_b", shared_hash, "C:\\Public\\drop2.exe", "drop2.exe", 100, "PE32", self.dummy_pointer)
            ]
        )

        comparator = EvidenceComparator(rep_a, rep_b)
        result = comparator.reconcile()

        # Both drops must be present in reconciled files (one matched with B, one observed only in A)
        self.assertEqual(len(result.reconciled_files), 2)
        filenames_a = [f.filenames_by_report.get("rep_a") for f in result.reconciled_files]
        self.assertIn("drop1.exe", filenames_a)
        self.assertIn("drop2.exe", filenames_a)

    def test_network_epistemic_honesty(self):
        """
        Verify that shared socket records are marked SOCKET_RECORD_LOGGED and CORROBORATED_SOCKET,
        not making causal overclaims of ESTABLISHED TCP handshakes or CONFIRMED identical payloads.
        """
        net_ev_a = NetworkObservation("rep_a", "TCP", "198.51.100.1", 443, self.dummy_pointer)
        net_ev_b = NetworkObservation("rep_b", "TCP", "198.51.100.1", 443, self.dummy_pointer)

        rep_a = NormalizedReport("rep_a", "CAPE", "cape", "DOC", "h", 60, network_events=[net_ev_a])
        rep_b = NormalizedReport("rep_b", "Falcon", "falcon", "DOC", "h", 60, network_events=[net_ev_b])

        result = EvidenceComparator(rep_a, rep_b).reconcile()
        self.assertEqual(len(result.reconciled_network), 1)
        net_item = result.reconciled_network[0]

        self.assertEqual(net_item.connection_state, "SOCKET_RECORD_LOGGED")
        self.assertEqual(net_item.causal_status, "CORROBORATED_SOCKET")
        self.assertIn("does not establish full application-layer handshake completion", net_item.epistemic_interpretation)

    def test_process_matching_order_independence(self):
        """
        Verify that candidate processes are matched based on global maximum similarity,
        not order of appearance in Report A.
        """
        # p_a0 has weak similarity with p_b0; p_a1 has high similarity with p_b0
        p_a0 = ProcessObservation("rep_a", 100, None, "cmd.exe", "cmd.exe /c pause", ["cmd.exe"], 1, self.dummy_pointer)
        p_a1 = ProcessObservation("rep_a", 200, None, "powershell.exe", "powershell.exe -enc AAAA", ["powershell.exe"], 1, self.dummy_pointer)

        p_b0 = ProcessObservation("rep_b", 500, None, "powershell.exe", "powershell.exe -enc AAAA", ["powershell.exe"], 1, self.dummy_pointer)

        # In Report A, cmd.exe appears first
        rep_a = NormalizedReport("rep_a", "CAPE", "cape", "DOC", "h", 60, processes=[p_a0, p_a1])
        rep_b = NormalizedReport("rep_b", "Falcon", "falcon", "DOC", "h", 60, processes=[p_b0])

        result = EvidenceComparator(rep_a, rep_b).reconcile()

        # powershell.exe should be MATCHED with p_b0 with high similarity score
        ps_item = [p for p in result.reconciled_processes if p.image_name == "powershell.exe"][0]
        self.assertIn("rep_b", ps_item.pids_by_report)
        self.assertEqual(ps_item.pids_by_report["rep_b"], 500)
        self.assertGreaterEqual(ps_item.heuristic_similarity_score, 0.80)

        # cmd.exe should be UNRESOLVED (not stealing p_b0)
        cmd_item = [p for p in result.reconciled_processes if p.image_name == "cmd.exe"][0]
        self.assertNotIn("rep_b", cmd_item.pids_by_report)

    def test_dynamic_schema_detection(self):
        """
        Verify automatic identification of CAPE and Falcon schemas.
        """
        falcon_raw = {
            "submission_info": {"analyzer": "Falcon Sandbox", "schema": "v7"},
            "execution": {"process_tree": []}
        }
        cape_raw = {
            "info": {"sandbox_name": "CAPE Sandbox v2.5"},
            "behavior": {"processes": []}
        }
        unknown_raw = {"random_key": 123}

        self.assertEqual(detect_schema(falcon_raw), "falcon")
        self.assertEqual(detect_schema(cape_raw), "cape")
        self.assertEqual(detect_schema(unknown_raw), "unknown")

        norm_falcon = parse_auto_report(falcon_raw, "rep_falcon")
        self.assertEqual(norm_falcon.schema_provenance_type, "SYNTHETIC_APPROXIMATION")

        norm_cape = parse_auto_report(cape_raw, "rep_cape")
        self.assertEqual(norm_cape.schema_provenance_type, "DOCUMENTED_VENDOR_FORMAT")

    def test_generalized_egress_port_parsing(self):
        """
        Verify that egress warnings with arbitrary ports (e.g. 443, 8443) extract target_pattern properly.
        """
        raw_falcon = {
            "submission_info": {
                "system_warnings": [
                    {"code": "WARN_EGRESS_BLOCKED", "description": "Egress filter blocked outbound TCP port 8443 to external"}
                ]
            }
        }
        norm = parse_falcon_report(raw_falcon, "falcon_test")
        self.assertEqual(len(norm.limitations), 1)
        self.assertEqual(norm.limitations[0].target_pattern, "port:8443")

    def test_greedy_score_sorted_matching_anchor_preservation(self):
        """
        Demonstrates the concrete trade-off between greedy score-sorted matching
        and global maximum-weight assignment.

        Given candidate similarity matrix:
                    B1 (PID 201)     B2 (PID 202)
        A1 (PID 101)    1.00            0.77
        A2 (PID 102)    0.79            0.25 (< 0.45 threshold)

        - Greedy score-sorted matching locks the highest-scoring anchor pair (A1-B1, score 1.00),
          leaving A2 unmatched (0.0 score) because B1 is consumed and A2-B2 (0.25) is below threshold.
          Aggregate weight = 1.00.
        - A global sum solver (e.g. Munkres) would pair A1-B2 (0.77) and A2-B1 (0.79) to maximize
          aggregate weight (total 1.56 > 1.00), at the cost of displacing the perfect anchor (A1-B1).

        This test asserts the engine's deterministic greedy anchor-preservation behavior.
        """
        p_a1 = ProcessObservation("rep_a", 101, 1, "powershell.exe", "powershell.exe -enc AAA -NoProfile", ["explorer.exe"], 2, EvidencePointer("rep_a", "/p/0", "p1", {}))
        p_a2 = ProcessObservation("rep_a", 102, 1, "powershell.exe", "powershell.exe -enc AAA -WindowStyle Hidden", ["explorer.exe"], 2, EvidencePointer("rep_a", "/p/1", "p2", {}))

        p_b1 = ProcessObservation("rep_b", 201, 1, "powershell.exe", "powershell.exe -enc AAA -NoProfile", ["explorer.exe"], 2, EvidencePointer("rep_b", "/p/0", "p1", {}))
        p_b2 = ProcessObservation("rep_b", 202, 1, "powershell.exe", "powershell.exe -NoProfile", ["explorer.exe"], 2, EvidencePointer("rep_b", "/p/1", "p2", {}))

        norm_a = NormalizedReport("rep_a", "CAPE", "CAPE", "DOCUMENTED_VENDOR_FORMAT", "aaa", 60, processes=[p_a1, p_a2])
        norm_b = NormalizedReport("rep_b", "CAPE", "CAPE", "DOCUMENTED_VENDOR_FORMAT", "aaa", 60, processes=[p_b1, p_b2])

        comparator = EvidenceComparator(norm_a, norm_b)

        # Assert individual candidate scores
        s_a1_b1, _ = comparator._score_process_pair(p_a1, p_b1)
        s_a1_b2, _ = comparator._score_process_pair(p_a1, p_b2)
        s_a2_b1, _ = comparator._score_process_pair(p_a2, p_b1)
        s_a2_b2, _ = comparator._score_process_pair(p_a2, p_b2)

        self.assertEqual(s_a1_b1, 1.00)
        self.assertGreaterEqual(s_a1_b2, 0.70)
        self.assertGreaterEqual(s_a2_b1, 0.70)
        self.assertLess(s_a2_b2, 0.45)  # Below matching threshold

        res = comparator.reconcile()

        # Find reconciled process for A1
        match_a1 = next((p for p in res.reconciled_processes if p.pids_by_report.get("rep_a") == 101), None)
        match_a2 = next((p for p in res.reconciled_processes if p.pids_by_report.get("rep_a") == 102), None)

        self.assertIsNotNone(match_a1)
        self.assertIsNotNone(match_a2)

        # Verify A1 is matched to B1 (201) and NOT displaced to B2 (202)
        self.assertEqual(match_a1.pids_by_report.get("rep_b"), 201)
        self.assertEqual(match_a1.confidence.value, "MATCHED")

        # Verify A2 is left UNRESOLVED because B1 was consumed by anchor A1
        self.assertNotIn("rep_b", match_a2.pids_by_report)
        self.assertEqual(match_a2.confidence.value, "UNRESOLVED")

    def test_network_repeated_events_attribute_alignment_not_blind_position(self):
        """
        Verify that multiple network connections to the same endpoint are paired by
        distinctive attributes (source port, PID, timestamp) rather than naive list index.
        """
        ptr_a1 = EvidencePointer("rep_a", "/network/tcp/0", "Stream 1", {"sport": 51001, "time": 10.0, "pid": 111}, True)
        ptr_a2 = EvidencePointer("rep_a", "/network/tcp/1", "Stream 2", {"sport": 51002, "time": 20.0, "pid": 222}, True)

        # In Report B, order is reversed
        ptr_b1 = EvidencePointer("rep_b", "/network/tcp/0", "Stream 2", {"sport": 51002, "time": 20.0, "pid": 222}, True)
        ptr_b2 = EvidencePointer("rep_b", "/network/tcp/1", "Stream 1", {"sport": 51001, "time": 10.0, "pid": 111}, True)

        net_a1 = NetworkObservation("rep_a", "TCP", "203.0.113.50", 443, ptr_a1)
        net_a2 = NetworkObservation("rep_a", "TCP", "203.0.113.50", 443, ptr_a2)

        net_b1 = NetworkObservation("rep_b", "TCP", "203.0.113.50", 443, ptr_b1)
        net_b2 = NetworkObservation("rep_b", "TCP", "203.0.113.50", 443, ptr_b2)

        rep_a = NormalizedReport("rep_a", "CAPE", "cape", "DOC", "h", 60, network_events=[net_a1, net_a2])
        rep_b = NormalizedReport("rep_b", "Falcon", "falcon", "DOC", "h", 60, network_events=[net_b1, net_b2])

        result = EvidenceComparator(rep_a, rep_b).reconcile()
        self.assertEqual(len(result.reconciled_network), 2)

        for item in result.reconciled_network:
            self.assertEqual(item.observation_presence.value, "OBSERVED_IN_BOTH")
            ptr_a = item.evidence_links.get("rep_a")
            ptr_b = item.evidence_links.get("rep_b")
            self.assertIsNotNone(ptr_a)
            self.assertIsNotNone(ptr_b)
            # Source ports MUST match across paired evidence links
            self.assertEqual(
                ptr_a.raw_snippet.get("sport"),
                ptr_b.raw_snippet.get("sport"),
                f"Mismatched pairing: A sport={ptr_a.raw_snippet.get('sport')} paired with B sport={ptr_b.raw_snippet.get('sport')}"
            )

    def test_possible_match_causal_explanation_and_alternatives_exclusion(self):
        """
        Verify:
        1. When process match confidence is POSSIBLE_MATCH, causal explanation is NOT CORROBORATED_EXECUTION.
        2. Selected match is never included in its own alternative_candidates list.
        """
        ptr = EvidencePointer("rep", "/proc/0", "proc", {}, True)

        p_a0 = ProcessObservation("rep_a", 100, 1, "cmd.exe", "cmd.exe /c script.bat -v -d", ["sample.exe", "cmd.exe"], 1, ptr)
        p_a1 = ProcessObservation("rep_a", 101, 1, "cmd.exe", "cmd.exe /c script.bat -v", ["sample.exe", "cmd.exe"], 1, ptr)

        p_b0 = ProcessObservation("rep_b", 200, 1, "cmd.exe", "cmd.exe /c script.bat -v -d", ["sample.exe", "cmd.exe"], 1, ptr)
        p_b1 = ProcessObservation("rep_b", 201, 1, "cmd.exe", "cmd.exe /c script.bat -v -q", ["sample.exe", "cmd.exe"], 1, ptr)

        rep_a = NormalizedReport("rep_a", "CAPE", "cape", "DOC", "h", 60, processes=[p_a0, p_a1])
        rep_b = NormalizedReport("rep_b", "Falcon", "falcon", "DOC", "h", 60, processes=[p_b0, p_b1])

        comparator = EvidenceComparator(rep_a, rep_b)
        result = comparator.reconcile()

        possible_matches = [p for p in result.reconciled_processes if p.confidence.value == "POSSIBLE_MATCH"]
        self.assertGreater(len(possible_matches), 0, "Expected at least one POSSIBLE_MATCH")

        for proc in possible_matches:
            pid_b = proc.pids_by_report.get("rep_b")
            # Must not claim corroborated execution when match confidence is only possible/ambiguous
            self.assertNotEqual(
                proc.causal_explanation.value,
                "CORROBORATED_EXECUTION",
                "POSSIBLE_MATCH must not be assigned CORROBORATED_EXECUTION"
            )
            # The selected B PID must never appear in its own alternatives
            for alt in proc.alternative_candidates:
                self.assertNotEqual(
                    alt.get("report_b_pid"),
                    pid_b,
                    f"Selected match PID {pid_b} appeared in its own alternative candidates!"
                )


if __name__ == "__main__":
    unittest.main()

