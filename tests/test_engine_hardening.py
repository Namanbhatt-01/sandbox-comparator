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
    CausalExplanation,
    DroppedFileObservation,
    EvidencePointer,
    NetworkObservation,
    NormalizedReport,
    ObservationPresence,
    ProcessMatchConfidence,
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
        Verify that shared socket records are marked SOCKET_RECORD_LOGGED,
        not making causal overclaims of ESTABLISHED TCP handshakes or CONFIRMED identical payloads.
        Singleton records without discriminators receive SINGLETON_ENDPOINT_OVERLAP / ENDPOINT_MATCH.
        Records with matching discriminators receive DIRECT_IDENTIFIER_MATCH / CORROBORATED_SOCKET.
        """
        net_ev_a = NetworkObservation("rep_a", "TCP", "198.51.100.1", 443, self.dummy_pointer)
        net_ev_b = NetworkObservation("rep_b", "TCP", "198.51.100.1", 443, self.dummy_pointer)

        rep_a = NormalizedReport("rep_a", "CAPE", "cape", "DOC", "h", 60, network_events=[net_ev_a])
        rep_b = NormalizedReport("rep_b", "Falcon", "falcon", "DOC", "h", 60, network_events=[net_ev_b])

        result = EvidenceComparator(rep_a, rep_b).reconcile()
        self.assertEqual(len(result.reconciled_network), 1)
        net_item = result.reconciled_network[0]

        self.assertEqual(net_item.connection_state, "SOCKET_RECORD_LOGGED")
        self.assertEqual(net_item.cross_report_correlation, "SINGLETON_ENDPOINT_OVERLAP")
        self.assertEqual(net_item.causal_status, "ENDPOINT_MATCH")
        self.assertEqual(net_item.causal_explanation, CausalExplanation.UNEXPLAINED)
        self.assertIn("lack distinguishing attributes", net_item.epistemic_interpretation)

        # Now test with discriminators (e.g. matching source port)
        ptr_disc_a = EvidencePointer("rep_a", "/test/0", "summary", {"sport": 49152})
        ptr_disc_b = EvidencePointer("rep_b", "/test/1", "summary", {"sport": 49152})
        net_disc_a = NetworkObservation("rep_a", "TCP", "198.51.100.1", 443, ptr_disc_a)
        net_disc_b = NetworkObservation("rep_b", "TCP", "198.51.100.1", 443, ptr_disc_b)
        rep_disc_a = NormalizedReport("rep_a", "CAPE", "cape", "DOC", "h", 60, network_events=[net_disc_a])
        rep_disc_b = NormalizedReport("rep_b", "Falcon", "falcon", "DOC", "h", 60, network_events=[net_disc_b])
        res_disc = EvidenceComparator(rep_disc_a, rep_disc_b).reconcile()
        self.assertEqual(len(res_disc.reconciled_network), 1)
        item_disc = res_disc.reconciled_network[0]
        self.assertEqual(item_disc.cross_report_correlation, "DIRECT_IDENTIFIER_MATCH")
        self.assertEqual(item_disc.causal_status, "CORROBORATED_SOCKET")
        self.assertEqual(item_disc.causal_explanation, CausalExplanation.CORROBORATED_EXECUTION)

    def test_process_matching_order_independence(self):
        """
        Verify that candidate processes are matched based on greedy score sorting (anchor-preserving matching),
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

    def test_deterministic_tie_breaking_under_process_list_permutation(self):
        """
        Verify that when candidate pairs have identical heuristic similarity scores,
        deterministic tie-breaking ensures identical assignment regardless of input list permutation.
        """
        import random

        ptr = EvidencePointer("rep", "/proc/0", "proc", {}, True)

        # Three processes in A with identical structure
        procs_a = [
            ProcessObservation("rep_a", 101, 1, "worker.exe", "worker.exe --task A", ["host.exe", "worker.exe"], 1, ptr),
            ProcessObservation("rep_a", 102, 1, "worker.exe", "worker.exe --task B", ["host.exe", "worker.exe"], 1, ptr),
            ProcessObservation("rep_a", 103, 1, "worker.exe", "worker.exe --task C", ["host.exe", "worker.exe"], 1, ptr),
        ]

        procs_b = [
            ProcessObservation("rep_b", 201, 1, "worker.exe", "worker.exe --task A", ["host.exe", "worker.exe"], 1, ptr),
            ProcessObservation("rep_b", 202, 1, "worker.exe", "worker.exe --task B", ["host.exe", "worker.exe"], 1, ptr),
            ProcessObservation("rep_b", 203, 1, "worker.exe", "worker.exe --task C", ["host.exe", "worker.exe"], 1, ptr),
        ]

        # Baseline run
        rep_a_base = NormalizedReport("rep_a", "CAPE", "cape", "DOC", "h", 60, processes=list(procs_a))
        rep_b_base = NormalizedReport("rep_b", "Falcon", "falcon", "DOC", "h", 60, processes=list(procs_b))
        base_res = EvidenceComparator(rep_a_base, rep_b_base).reconcile()
        base_pairs = {
            p.pids_by_report.get("rep_a"): p.pids_by_report.get("rep_b")
            for p in base_res.reconciled_processes
            if "rep_a" in p.pids_by_report and "rep_b" in p.pids_by_report
        }

        # Run 10 permutations
        rng = random.Random(42)
        for i in range(10):
            shuffled_a = list(procs_a)
            shuffled_b = list(procs_b)
            rng.shuffle(shuffled_a)
            rng.shuffle(shuffled_b)

            rep_a = NormalizedReport("rep_a", "CAPE", "cape", "DOC", "h", 60, processes=shuffled_a)
            rep_b = NormalizedReport("rep_b", "Falcon", "falcon", "DOC", "h", 60, processes=shuffled_b)
            res = EvidenceComparator(rep_a, rep_b).reconcile()

            perm_pairs = {
                p.pids_by_report.get("rep_a"): p.pids_by_report.get("rep_b")
                for p in res.reconciled_processes
                if "rep_a" in p.pids_by_report and "rep_b" in p.pids_by_report
            }

            self.assertEqual(
                base_pairs,
                perm_pairs,
                f"Permutation {i} resulted in divergent process assignment! Expected {base_pairs}, got {perm_pairs}"
            )

    def test_missing_and_malformed_hashes_never_paired_as_identical(self):
        """
        Verify that files with missing, empty, or malformed hashes are NEVER grouped together
        by empty string or matched as CORROBORATED_EXECUTION.
        """
        f_a1 = DroppedFileObservation("rep_a", "", "C:\\temp\\temp1.tmp", "temp1.tmp", 1024, "tmp", self.dummy_pointer, is_malformed_hash=True)
        f_a2 = DroppedFileObservation("rep_a", "not_a_valid_sha256", "C:\\bin\\tool.bin", "tool.bin", 2048, "bin", self.dummy_pointer, is_malformed_hash=True)
        
        f_b1 = DroppedFileObservation("rep_b", "", "C:\\desktop\\ransom.txt", "ransom.txt", 4096, "txt", self.dummy_pointer, is_malformed_hash=True)
        f_b2 = DroppedFileObservation("rep_b", "different_invalid_hash", "C:\\drivers\\driver.sys", "driver.sys", 8192, "sys", self.dummy_pointer, is_malformed_hash=True)

        rep_a = NormalizedReport("rep_a", "CAPE", "cape", "DOC", "h", 60, dropped_files=[f_a1, f_a2])
        rep_b = NormalizedReport("rep_b", "Falcon", "falcon", "DOC", "h", 60, dropped_files=[f_b1, f_b2])

        res = EvidenceComparator(rep_a, rep_b).reconcile()

        # None of these 4 files should ever be paired as OBSERVED_IN_BOTH
        for f in res.reconciled_files:
            self.assertNotEqual(f.observation_presence, ObservationPresence.OBSERVED_IN_BOTH)
            self.assertNotEqual(f.causal_explanation, CausalExplanation.CORROBORATED_EXECUTION)
            self.assertTrue(f.is_malformed_hash)

        # 2 files in A, 2 files in B -> all 4 must remain uncorroborated single-sided observations
        obs_a = [f for f in res.reconciled_files if f.observation_presence == ObservationPresence.OBSERVED_ONLY_IN_A]
        obs_b = [f for f in res.reconciled_files if f.observation_presence == ObservationPresence.OBSERVED_ONLY_IN_B]
        self.assertEqual(len(obs_a), 2)
        self.assertEqual(len(obs_b), 2)

    def test_unrelated_root_processes_with_empty_cli_do_not_match(self):
        """
        Verify that two completely unrelated root processes with different executable names
        and empty command lines do NOT receive similarity bonuses for absence of evidence.
        Score must be <= 0.10 (well below tau = 0.45), preventing false candidate matching.
        """
        p_a = ProcessObservation("rep_a", 1001, None, "notepad.exe", "", ["notepad.exe"], 0, self.dummy_pointer)
        p_b = ProcessObservation("rep_b", 2002, None, "calc.exe", "", ["calc.exe"], 0, self.dummy_pointer)

        rep_a = NormalizedReport("rep_a", "CAPE", "cape", "DOC", "h", 60, processes=[p_a])
        rep_b = NormalizedReport("rep_b", "Falcon", "falcon", "DOC", "h", 60, processes=[p_b])

        comp = EvidenceComparator(rep_a, rep_b)
        score, rationale = comp._score_process_pair(p_a, p_b)

        # Only identical tree depth (0.10) can apply; no argument or ancestry similarity bonus
        self.assertLessEqual(score, 0.10)
        self.assertLess(score, 0.45)

        res = comp.reconcile()
        # Both processes must remain single-sided
        self.assertEqual(len(res.reconciled_processes), 2)
        for p in res.reconciled_processes:
            self.assertNotEqual(p.observation_presence, ObservationPresence.OBSERVED_IN_BOTH)
            self.assertEqual(p.confidence, ProcessMatchConfidence.UNRESOLVED)

    def test_aggregate_network_endpoints_structured_fields(self):
        """
        Verify that repeated network streams without distinct discriminators receive
        cross_report_correlation = 'AGGREGATE_ENDPOINT_CLUSTER',
        causal_status = 'AGGREGATE_ENDPOINT_CORROBORATION' and causal_explanation = UNEXPLAINED
        in a single consolidated cluster record, preventing false claims of 1-to-1 socket bijection.
        """
        n_a1 = NetworkObservation("rep_a", "TCP", "203.0.113.5", 443, self.dummy_pointer)
        n_a2 = NetworkObservation("rep_a", "TCP", "203.0.113.5", 443, self.dummy_pointer)
        n_b1 = NetworkObservation("rep_b", "TCP", "203.0.113.5", 443, self.dummy_pointer)
        n_b2 = NetworkObservation("rep_b", "TCP", "203.0.113.5", 443, self.dummy_pointer)

        rep_a = NormalizedReport("rep_a", "CAPE", "cape", "DOC", "h", 60, network_events=[n_a1, n_a2])
        rep_b = NormalizedReport("rep_b", "Falcon", "falcon", "DOC", "h", 60, network_events=[n_b1, n_b2])

        res = EvidenceComparator(rep_a, rep_b).reconcile()

        # Undifferentiated repeated items must be consolidated into an aggregate endpoint cluster
        self.assertEqual(len(res.reconciled_network), 1)
        cluster = res.reconciled_network[0]
        self.assertEqual(cluster.cross_report_correlation, "AGGREGATE_ENDPOINT_CLUSTER")
        self.assertEqual(cluster.causal_status, "AGGREGATE_ENDPOINT_CORROBORATION")
        self.assertEqual(cluster.causal_explanation, CausalExplanation.UNEXPLAINED)
        self.assertIn("lacking distinct source ports or timestamps", cluster.epistemic_interpretation)

    def test_sample_hash_mismatch_flagged_with_limitation(self):
        """
        Verify that reports with different non-empty sample hashes trigger an explicit
        SAMPLE_HASH_MISMATCH collection limitation, cross-sample prefix, and warning note.
        """
        hash_a = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        hash_b = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        rep_a = NormalizedReport("rep_a", "CAPE", "cape", "DOC", hash_a, 60)
        rep_b = NormalizedReport("rep_b", "Falcon", "falcon", "DOC", hash_b, 60)

        res = EvidenceComparator(rep_a, rep_b).reconcile()
        self.assertTrue(res.sample_sha256.startswith("CROSS_SAMPLE:"))
        self.assertTrue(any("SAMPLE_HASH_MISMATCH" == lim.code for lim in res.collection_limitations["rep_a"]))
        self.assertTrue(any("Cross-sample comparison" in note for note in res.epistemic_uncertainty_notes))

    def test_missing_ancestry_does_not_trigger_disjoint_penalty(self):
        """
        Verify that missing ancestry in one report does NOT penalize a matching process down to 0.15.
        Disjoint tree penalty must only fire when BOTH reports provide ancestors and they conflict.
        """
        # rep_a has lineage; rep_b has empty lineage (unrecorded ancestry)
        p_a = ProcessObservation("rep_a", 100, 10, "calc.exe", "calc.exe /test", ["explorer.exe", "calc.exe"], 2, self.dummy_pointer)
        p_b = ProcessObservation("rep_b", 200, None, "calc.exe", "calc.exe /test", [], 0, self.dummy_pointer)

        rep_a = NormalizedReport("rep_a", "CAPE", "cape", "DOC", "h", 60, processes=[p_a])
        rep_b = NormalizedReport("rep_b", "Falcon", "falcon", "DOC", "h", 60, processes=[p_b])

        res = EvidenceComparator(rep_a, rep_b).reconcile()
        self.assertEqual(len(res.reconciled_processes), 1)
        proc = res.reconciled_processes[0]
        # Should score well above 0.15 disjoint penalty threshold (Image 0.35 + Args 0.35 = 0.70)
        self.assertGreaterEqual(proc.heuristic_similarity_score, 0.70)

    def test_competing_sibling_ambiguity_demotes_to_possible_match(self):
        """
        Verify that when two sibling nodes in Report A compete for the same Report B node
        with close scores, reverse ambiguity detection flags the match as POSSIBLE_MATCH
        rather than high-confidence MATCHED.
        """
        p_a1 = ProcessObservation("rep_a", 101, 10, "worker.exe", "worker.exe --pool worker", ["app.exe", "worker.exe"], 2, self.dummy_pointer)
        p_a2 = ProcessObservation("rep_a", 102, 10, "worker.exe", "worker.exe --pool worker", ["app.exe", "worker.exe"], 2, self.dummy_pointer)
        p_b1 = ProcessObservation("rep_b", 201, 20, "worker.exe", "worker.exe --pool worker", ["app.exe", "worker.exe"], 2, self.dummy_pointer)

        rep_a = NormalizedReport("rep_a", "CAPE", "cape", "DOC", "h", 60, processes=[p_a1, p_a2])
        rep_b = NormalizedReport("rep_b", "Falcon", "falcon", "DOC", "h", 60, processes=[p_b1])

        res = EvidenceComparator(rep_a, rep_b).reconcile()
        matched = [p for p in res.reconciled_processes if p.observation_presence == ObservationPresence.OBSERVED_IN_BOTH]
        self.assertEqual(len(matched), 1)
        # Because p_a2 also competed for p_b1 with identical score, it must be flagged ambiguous
        self.assertEqual(matched[0].confidence, ProcessMatchConfidence.POSSIBLE_MATCH)

    def test_falcon_malformed_pid_receives_surrogate_no_collision(self):
        """
        Verify that Falcon parser assigns surrogate IDs when PID is missing or malformed,
        preventing synthetic PID 0 collisions across distinct nodes.
        """
        from engine.parsers.falcon_parser import parse_falcon_report
        data = {
            "submission_info": {"sample_metadata": {"sha256": "abc"}},
            "execution": {
                "process_tree": [
                    {"name": "proc_a.exe", "pid": "invalid_pid", "cmdline": "proc_a.exe"},
                    {"name": "proc_b.exe", "cmdline": "proc_b.exe"}  # missing pid
                ]
            }
        }
        rep = parse_falcon_report(data, "test_rep")
        self.assertEqual(len(rep.processes), 2)
        pids = [p.source_pid for p in rep.processes]
        self.assertNotIn(0, pids)
        self.assertNotEqual(pids[0], pids[1])
        self.assertTrue(all(pid >= 0x80000000 for pid in pids))


if __name__ == "__main__":
    unittest.main()

