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
    CollectionLimitation,
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


if __name__ == "__main__":
    unittest.main()

