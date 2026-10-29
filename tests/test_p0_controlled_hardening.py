#!/usr/bin/env python3
"""
Phase 1 Controlled Hardening Suite for Sandbox Comparator.

Locks down two P0 integrity risks:
1. Conflicting Sample Hashes:
   Two reports with different valid SHA-256 hashes but similar process trees and network endpoints.
   Verifies:
   - The sample-identity mismatch is explicit.
   - Behavioral similarities can still be reported as similarities.
   - The tool never claims the reports contain the same sample solely because their behavior looks alike.

2. PID Reassignment and Order Shuffling:
   Equivalent reports with changed PIDs and shuffled record order.
   Verifies:
   - Semantic matches remain stable when the evidence supports them.
   - Confidence does not change arbitrarily because of PID changes.
   - Equally plausible matches remain unresolved (POSSIBLE_MATCH with alternatives).
"""

import unittest
from cli import classify_cross_report_activity, format_markdown_report
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
from engine.reconciler import EvidenceComparator


class TestP0ControlledHardening(unittest.TestCase):
    def setUp(self):
        self.dummy_pointer = EvidencePointer(
            report_id="test_rep",
            json_pointer="/test/ptr",
            event_summary="Test event summary",
            raw_snippet={"pid": 1234, "sport": 49152}
        )

    # =========================================================================
    # P0 Risk 1: Conflicting Sample Hashes
    # =========================================================================
    def test_conflicting_sample_hashes_explicit_mismatch_and_behavioral_reporting(self):
        """
        Verify that when two reports have different valid SHA-256 hashes:
        1. The sample identity mismatch is explicit in comparison.sample_sha256 and collection limitations.
        2. Behavioral similarities (processes, files, sockets) are still accurately reported.
        3. The tool NEVER claims the reports contain the same sample or asserts same-sample cross-run corroboration.
        """
        hash_a = "1111111111111111111111111111111111111111111111111111111111111111"
        hash_b = "2222222222222222222222222222222222222222222222222222222222222222"
        file_sha256 = "3333333333333333333333333333333333333333333333333333333333333333"

        # Similar process tree in both reports
        proc_a1 = ProcessObservation(
            "rep_a", 1000, None, "dropper.exe", "dropper.exe /install", ["explorer.exe", "dropper.exe"], 2, self.dummy_pointer
        )
        proc_a2 = ProcessObservation(
            "rep_a", 1004, 1000, "cmd.exe", "cmd.exe /c start", ["explorer.exe", "dropper.exe", "cmd.exe"], 3, self.dummy_pointer
        )

        proc_b1 = ProcessObservation(
            "rep_b", 4000, None, "dropper.exe", "dropper.exe /install", ["explorer.exe", "dropper.exe"], 2, self.dummy_pointer
        )
        proc_b2 = ProcessObservation(
            "rep_b", 4004, 4000, "cmd.exe", "cmd.exe /c start", ["explorer.exe", "dropper.exe", "cmd.exe"], 3, self.dummy_pointer
        )

        # Dropped file in both reports
        file_a = DroppedFileObservation("rep_a", file_sha256, r"C:\Windows\Temp\payload.dll", "payload.dll", 40960, "PE32", self.dummy_pointer)
        file_b = DroppedFileObservation("rep_b", file_sha256, r"C:\Windows\Temp\payload.dll", "payload.dll", 40960, "PE32", self.dummy_pointer)

        # Network connection in both reports with matching source port discriminator
        net_ptr_a = EvidencePointer("rep_a", "/net/0", "TCP connect", {"sport": 49152})
        net_ptr_b = EvidencePointer("rep_b", "/net/0", "TCP connect", {"sport": 49152})
        net_a = NetworkObservation("rep_a", "TCP", "198.51.100.25", 443, net_ptr_a)
        net_b = NetworkObservation("rep_b", "TCP", "198.51.100.25", 443, net_ptr_b)

        rep_a = NormalizedReport(
            "rep_a", "CAPE Sandbox", "cape_v2", "DOC", hash_a, 60,
            processes=[proc_a1, proc_a2], dropped_files=[file_a], network_events=[net_a]
        )
        rep_b = NormalizedReport(
            "rep_b", "Falcon Sandbox", "falcon_v3", "SYNTH", hash_b, 60,
            processes=[proc_b1, proc_b2], dropped_files=[file_b], network_events=[net_b]
        )

        comparison = EvidenceComparator(rep_a, rep_b).reconcile()

        # ---------------------------------------------------------------------
        # Verification 1: Explicit Sample-Identity Mismatch
        # ---------------------------------------------------------------------
        # Must NOT silently select hash_a or hash_b
        self.assertNotEqual(comparison.sample_sha256, hash_a)
        self.assertNotEqual(comparison.sample_sha256, hash_b)
        self.assertTrue(comparison.sample_sha256.startswith("CROSS_SAMPLE:"))
        self.assertIn(hash_a[:12], comparison.sample_sha256)
        self.assertIn(hash_b[:12], comparison.sample_sha256)

        # Must record SAMPLE_HASH_MISMATCH collection limitation for both reports
        self.assertTrue(
            any(lim.code == "SAMPLE_HASH_MISMATCH" for lim in comparison.collection_limitations["rep_a"]),
            "Missing SAMPLE_HASH_MISMATCH limitation in Report A limitations"
        )
        self.assertTrue(
            any(lim.code == "SAMPLE_HASH_MISMATCH" for lim in comparison.collection_limitations["rep_b"]),
            "Missing SAMPLE_HASH_MISMATCH limitation in Report B limitations"
        )

        # Epistemic notes must carry explicit warning
        self.assertTrue(
            any("Cross-sample comparison" in note for note in comparison.epistemic_uncertainty_notes),
            "Missing cross-sample warning in epistemic uncertainty notes"
        )

        # ---------------------------------------------------------------------
        # Verification 2: Behavioral Similarities ARE Still Reported as Similarities
        # ---------------------------------------------------------------------
        # Processes matched based on behavioral properties
        matched_procs = [p for p in comparison.reconciled_processes if p.observation_presence == ObservationPresence.OBSERVED_IN_BOTH]
        self.assertEqual(len(matched_procs), 2, "Both processes should be aligned as behavioral matches")
        for p in matched_procs:
            self.assertEqual(p.confidence, ProcessMatchConfidence.MATCHED)
            self.assertGreaterEqual(p.heuristic_similarity_score, 0.80)

        # Dropped file matched by verified SHA-256
        self.assertEqual(len(comparison.reconciled_files), 1)
        reconciled_file = comparison.reconciled_files[0]
        self.assertEqual(reconciled_file.sha256, file_sha256)
        self.assertEqual(reconciled_file.observation_presence, ObservationPresence.OBSERVED_IN_BOTH)
        self.assertEqual(reconciled_file.causal_explanation, CausalExplanation.CORROBORATED_EXECUTION)

        # Network endpoint corroborated with discriminator
        self.assertEqual(len(comparison.reconciled_network), 1)
        reconciled_net = comparison.reconciled_network[0]
        self.assertEqual(reconciled_net.observation_presence, ObservationPresence.OBSERVED_IN_BOTH)
        self.assertEqual(reconciled_net.cross_report_correlation, "DIRECT_IDENTIFIER_MATCH")

        # ---------------------------------------------------------------------
        # Verification 3: Tool NEVER Claims Same-Sample Provenance or Cross-Run Corroboration
        # ---------------------------------------------------------------------
        is_cross_sample = comparison.sample_sha256.startswith("CROSS_SAMPLE:")
        verdict, summary = classify_cross_report_activity(
            matched_procs=len(matched_procs),
            matched_files=len(comparison.reconciled_files),
            is_cross_sample=is_cross_sample
        )

        # Verdict must NOT say CROSS-RUN ACTIVITY CORROBORATED
        self.assertNotEqual(verdict, "CROSS-RUN ACTIVITY CORROBORATED")
        self.assertEqual(verdict, "CROSS-SAMPLE BEHAVIORAL SIMILARITY")
        self.assertIn("different malware samples", summary)
        self.assertIn("NOT same-sample execution reproducibility", summary)

        # Markdown report must render cross-sample warning banner
        md_report = format_markdown_report(comparison)
        self.assertIn("[!WARNING] **Cross-Sample Comparison**", md_report)
        self.assertIn("Behavioral alignments indicate heuristic overlap, not same-sample execution reproducibility", md_report)

        # Web UI findings cards must reflect cross-sample similarity, not corroborated execution
        from web.app import serialize_comparison
        serialized = serialize_comparison(comparison)
        findings = serialized["investigation_findings"]
        proc_f = next((f for f in findings if f["category"] == "EXECUTION"), None)
        self.assertIsNotNone(proc_f)
        self.assertEqual(proc_f["title"], "Cross-Sample Process Similarity")
        self.assertIn("NOT same-sample execution reproducibility", proc_f["detail"])

        file_f = next((f for f in findings if f["category"] == "PERSISTENCE"), None)
        self.assertIsNotNone(file_f)
        self.assertEqual(file_f["title"], "Shared Artifact Hashes Across Samples")
        self.assertIn("without establishing same-sample identity", file_f["detail"])

    # =========================================================================
    # P0 Risk 2: PID Reassignment & Order Shuffling
    # =========================================================================
    def test_pid_reassignment_and_shuffled_order_semantic_stability(self):
        """
        Verify that equivalent reports with changed PIDs and shuffled record order:
        1. Semantic matches remain stable when evidence supports them (anchors match with identical confidence).
        2. Confidence does not change arbitrarily because of PID changes.
        3. Equally plausible matches remain unresolved (competing siblings stay POSSIBLE_MATCH).
        """
        # --- Run 1: Base PID Allocation & Natural Tree Order ---
        # A: Root dropper, child cmd, and two identical competing workers under cmd
        p_a1_r1 = ProcessObservation("rep_a", 1000, None, "launcher.exe", "launcher.exe --start", ["explorer.exe", "launcher.exe"], 2, self.dummy_pointer)
        p_a2_r1 = ProcessObservation("rep_a", 1004, 1000, "cmd.exe", "cmd.exe /c run.bat", ["explorer.exe", "launcher.exe", "cmd.exe"], 3, self.dummy_pointer)
        p_a3_r1 = ProcessObservation("rep_a", 1008, 1004, "worker.exe", "worker.exe --task run", ["explorer.exe", "launcher.exe", "cmd.exe", "worker.exe"], 4, self.dummy_pointer)
        p_a4_r1 = ProcessObservation("rep_a", 1012, 1004, "worker.exe", "worker.exe --task run", ["explorer.exe", "launcher.exe", "cmd.exe", "worker.exe"], 4, self.dummy_pointer)

        # B: Same tree, single worker
        p_b1_r1 = ProcessObservation("rep_b", 5000, None, "launcher.exe", "launcher.exe --start", ["explorer.exe", "launcher.exe"], 2, self.dummy_pointer)
        p_b2_r1 = ProcessObservation("rep_b", 5004, 5000, "cmd.exe", "cmd.exe /c run.bat", ["explorer.exe", "launcher.exe", "cmd.exe"], 3, self.dummy_pointer)
        p_b3_r1 = ProcessObservation("rep_b", 5008, 5004, "worker.exe", "worker.exe --task run", ["explorer.exe", "launcher.exe", "cmd.exe", "worker.exe"], 4, self.dummy_pointer)

        rep_a_r1 = NormalizedReport("rep_a", "CAPE", "cape", "DOC", "sample_hash", 60, processes=[p_a1_r1, p_a2_r1, p_a3_r1, p_a4_r1])
        rep_b_r1 = NormalizedReport("rep_b", "Falcon", "falcon", "DOC", "sample_hash", 60, processes=[p_b1_r1, p_b2_r1, p_b3_r1])

        res_r1 = EvidenceComparator(rep_a_r1, rep_b_r1).reconcile()

        # --- Run 2: Completely Reassigned PIDs & Shuffled Order ---
        # A: PIDs reassigned to completely different numbers, order shuffled: [a3, a1, a4, a2]
        p_a1_r2 = ProcessObservation("rep_a", 9901, None, "launcher.exe", "launcher.exe --start", ["explorer.exe", "launcher.exe"], 2, self.dummy_pointer)
        p_a2_r2 = ProcessObservation("rep_a", 9902, 9901, "cmd.exe", "cmd.exe /c run.bat", ["explorer.exe", "launcher.exe", "cmd.exe"], 3, self.dummy_pointer)
        p_a3_r2 = ProcessObservation("rep_a", 9903, 9902, "worker.exe", "worker.exe --task run", ["explorer.exe", "launcher.exe", "cmd.exe", "worker.exe"], 4, self.dummy_pointer)
        p_a4_r2 = ProcessObservation("rep_a", 9904, 9902, "worker.exe", "worker.exe --task run", ["explorer.exe", "launcher.exe", "cmd.exe", "worker.exe"], 4, self.dummy_pointer)

        # B: PIDs reassigned to completely different numbers, order reversed: [b2, b3, b1]
        p_b1_r2 = ProcessObservation("rep_b", 7701, None, "launcher.exe", "launcher.exe --start", ["explorer.exe", "launcher.exe"], 2, self.dummy_pointer)
        p_b2_r2 = ProcessObservation("rep_b", 7702, 7701, "cmd.exe", "cmd.exe /c run.bat", ["explorer.exe", "launcher.exe", "cmd.exe"], 3, self.dummy_pointer)
        p_b3_r2 = ProcessObservation("rep_b", 7703, 7702, "worker.exe", "worker.exe --task run", ["explorer.exe", "launcher.exe", "cmd.exe", "worker.exe"], 4, self.dummy_pointer)

        rep_a_r2 = NormalizedReport("rep_a", "CAPE", "cape", "DOC", "sample_hash", 60, processes=[p_a3_r2, p_a1_r2, p_a4_r2, p_a2_r2])
        rep_b_r2 = NormalizedReport("rep_b", "Falcon", "falcon", "DOC", "sample_hash", 60, processes=[p_b2_r2, p_b3_r2, p_b1_r2])

        res_r2 = EvidenceComparator(rep_a_r2, rep_b_r2).reconcile()

        # ---------------------------------------------------------------------
        # Verification 1: Anchor Matches Remain Stable Across PID & Order Variations
        # ---------------------------------------------------------------------
        for res, label in [(res_r1, "Run 1 (Base)"), (res_r2, "Run 2 (Shuffled PIDs)")]:
            launcher_matches = [p for p in res.reconciled_processes if p.image_name == "launcher.exe" and p.observation_presence == ObservationPresence.OBSERVED_IN_BOTH]
            self.assertEqual(len(launcher_matches), 1, f"{label}: Exactly one launcher.exe match")
            self.assertEqual(launcher_matches[0].confidence, ProcessMatchConfidence.MATCHED, f"{label}: launcher.exe must be MATCHED")
            self.assertEqual(launcher_matches[0].causal_explanation, CausalExplanation.CORROBORATED_EXECUTION)

            cmd_matches = [p for p in res.reconciled_processes if p.image_name == "cmd.exe" and p.observation_presence == ObservationPresence.OBSERVED_IN_BOTH]
            self.assertEqual(len(cmd_matches), 1, f"{label}: Exactly one cmd.exe match")
            self.assertEqual(cmd_matches[0].confidence, ProcessMatchConfidence.MATCHED, f"{label}: cmd.exe must be MATCHED")
            self.assertEqual(cmd_matches[0].causal_explanation, CausalExplanation.CORROBORATED_EXECUTION)

        # Scores between Run 1 and Run 2 must be identical for anchors
        launcher_score_r1 = next(p.heuristic_similarity_score for p in res_r1.reconciled_processes if p.image_name == "launcher.exe")
        launcher_score_r2 = next(p.heuristic_similarity_score for p in res_r2.reconciled_processes if p.image_name == "launcher.exe")
        self.assertAlmostEqual(launcher_score_r1, launcher_score_r2, places=4, msg="Launcher match score must be PID-invariant")

        cmd_score_r1 = next(p.heuristic_similarity_score for p in res_r1.reconciled_processes if p.image_name == "cmd.exe")
        cmd_score_r2 = next(p.heuristic_similarity_score for p in res_r2.reconciled_processes if p.image_name == "cmd.exe")
        self.assertAlmostEqual(cmd_score_r1, cmd_score_r2, places=4, msg="Cmd match score must be PID-invariant")

        # ---------------------------------------------------------------------
        # Verification 2: Equally Plausible Competing Matches Remain Unresolved
        # ---------------------------------------------------------------------
        # Two workers in A compete with identical score for the single worker in B.
        # In BOTH runs, the matched worker MUST be demoted to POSSIBLE_MATCH due to ambiguity.
        # It must NEVER be promoted to MATCHED.
        for res, label in [(res_r1, "Run 1 (Base)"), (res_r2, "Run 2 (Shuffled PIDs)")]:
            worker_matches = [
                p for p in res.reconciled_processes
                if p.image_name == "worker.exe" and p.observation_presence == ObservationPresence.OBSERVED_IN_BOTH
            ]
            self.assertEqual(len(worker_matches), 1, f"{label}: Exactly one worker paired in output")
            matched_worker = worker_matches[0]
            self.assertEqual(
                matched_worker.confidence,
                ProcessMatchConfidence.POSSIBLE_MATCH,
                f"{label}: Competing worker sibling MUST remain POSSIBLE_MATCH due to ambiguity, never MATCHED"
            )
            self.assertEqual(matched_worker.causal_explanation, CausalExplanation.UNEXPLAINED)
            self.assertIn("ambiguity across candidate nodes prevents definitive corroboration", matched_worker.epistemic_interpretation)

            # Unmatched worker in A must be OBSERVED_ONLY_IN_A / UNRESOLVED
            unmatched_workers = [
                p for p in res.reconciled_processes
                if p.image_name == "worker.exe" and p.observation_presence == ObservationPresence.OBSERVED_ONLY_IN_A
            ]
            self.assertEqual(len(unmatched_workers), 1, f"{label}: Second competing worker must be OBSERVED_ONLY_IN_A")
            self.assertEqual(unmatched_workers[0].confidence, ProcessMatchConfidence.UNRESOLVED)

    # =========================================================================
    # Phase 2 Integrity & Forensic Hardening Tests
    # =========================================================================
    def test_network_conflicting_metadata_divergent_endpoint_attributes(self):
        """
        When two reports have single network records to the same endpoint but with conflicting
        discriminators (e.g. conflicting source ports), the comparator must label the match
        as DIVERGENT_ENDPOINT_ATTRIBUTES and UNEXPLAINED, never a direct identifier match.
        """
        net_ptr_a = EvidencePointer("rep_a", "/net/0", "TCP connect", {"sport": 50000})
        net_ptr_b = EvidencePointer("rep_b", "/net/0", "TCP connect", {"sport": 50001})
        net_a = NetworkObservation("rep_a", "TCP", "198.51.100.25", 443, net_ptr_a)
        net_b = NetworkObservation("rep_b", "TCP", "198.51.100.25", 443, net_ptr_b)

        rep_a = NormalizedReport("rep_a", "CAPE", "cape", "DOC", "hash1", 60, network_events=[net_a])
        rep_b = NormalizedReport("rep_b", "Falcon", "falcon", "DOC", "hash1", 60, network_events=[net_b])

        res = EvidenceComparator(rep_a, rep_b).reconcile()
        self.assertEqual(len(res.reconciled_network), 1)
        net_item = res.reconciled_network[0]
        self.assertEqual(net_item.observation_presence, ObservationPresence.OBSERVED_IN_BOTH)
        self.assertEqual(net_item.cross_report_correlation, "DIVERGENT_ENDPOINT_ATTRIBUTES")
        self.assertEqual(net_item.causal_status, "DIVERGENT_ENDPOINT_ATTRIBUTES")
        self.assertEqual(net_item.causal_explanation, CausalExplanation.UNEXPLAINED)
        self.assertIn("conflicting attributes", net_item.epistemic_interpretation)

    def test_falcon_parser_duplicate_pids_and_conflicting_parents(self):
        """
        Falcon parser must detect duplicate PIDs in process trees and emit warnings for
        both PID reuse and nodes declaring a ppid that conflicts with their parent node's PID.
        """
        from engine.parsers.falcon_parser import parse_falcon_report

        raw_falcon = {
            "submission_info": {
                "analyzer": "Falcon Test",
                "schema": "falcon_hybrid_synthetic_v3",
                "sample_metadata": {"sha256": "a" * 64}
            },
            "execution": {
                "process_tree": [
                    {
                        "pid": 1000,
                        "name": "root.exe",
                        "cmdline": "root.exe",
                        "children": [
                            {
                                "pid": 2000,
                                "ppid": 9999,  # Conflicting PPID: parent is 1000, but declared is 9999
                                "name": "child1.exe",
                                "cmdline": "child1.exe",
                                "children": []
                            },
                            {
                                "pid": 1000,  # Duplicate PID reuse
                                "ppid": 1000,
                                "name": "reused.exe",
                                "cmdline": "reused.exe",
                                "children": []
                            }
                        ]
                    }
                ]
            }
        }

        norm = parse_falcon_report(raw_falcon, "falcon_test")
        self.assertTrue(
            any("Duplicate PID 1000 detected in Falcon process tree" in w for w in norm.parser_warnings),
            f"Expected duplicate PID warning, got: {norm.parser_warnings}"
        )
        self.assertTrue(
            any("Process PID 2000 declared ppid=9999 but is nested under PID 1000" in w for w in norm.parser_warnings),
            f"Expected conflicting PPID warning, got: {norm.parser_warnings}"
        )

    def test_observation_accounting_invariants(self):
        """
        Verifies the epistemic observation accounting invariant:
        Total observations in A = Matched observations + Unmatched A observations
        Total observations in B = Matched observations + Unmatched B observations
        No evidence item is silently dropped or unaccounted for.
        """
        p_a1 = ProcessObservation("rep_a", 100, None, "proc1.exe", "proc1.exe", ["proc1.exe"], 1, self.dummy_pointer)
        p_a2 = ProcessObservation("rep_a", 200, 100, "proc2.exe", "proc2.exe", ["proc1.exe", "proc2.exe"], 2, self.dummy_pointer)
        p_a3 = ProcessObservation("rep_a", 300, 100, "proc3.exe", "proc3.exe", ["proc1.exe", "proc3.exe"], 2, self.dummy_pointer)

        p_b1 = ProcessObservation("rep_b", 500, None, "proc1.exe", "proc1.exe", ["proc1.exe"], 1, self.dummy_pointer)
        p_b2 = ProcessObservation("rep_b", 600, 500, "proc4.exe", "proc4.exe", ["proc1.exe", "proc4.exe"], 2, self.dummy_pointer)

        f_a1 = DroppedFileObservation("rep_a", "1" * 64, r"C:\f1.dll", "f1.dll", 100, "PE", self.dummy_pointer)
        f_a2 = DroppedFileObservation("rep_a", "2" * 64, r"C:\f2.dll", "f2.dll", 200, "PE", self.dummy_pointer)
        f_b1 = DroppedFileObservation("rep_b", "1" * 64, r"C:\f1.dll", "f1.dll", 100, "PE", self.dummy_pointer)

        n_a1 = NetworkObservation("rep_a", "TCP", "1.1.1.1", 80, self.dummy_pointer)
        n_a2 = NetworkObservation("rep_a", "TCP", "2.2.2.2", 443, self.dummy_pointer)
        n_b1 = NetworkObservation("rep_b", "TCP", "1.1.1.1", 80, self.dummy_pointer)

        rep_a = NormalizedReport("rep_a", "A", "cape", "DOC", "h" * 64, 60, processes=[p_a1, p_a2, p_a3], dropped_files=[f_a1, f_a2], network_events=[n_a1, n_a2])
        rep_b = NormalizedReport("rep_b", "B", "falcon", "DOC", "h" * 64, 60, processes=[p_b1, p_b2], dropped_files=[f_b1], network_events=[n_b1])

        res = EvidenceComparator(rep_a, rep_b).reconcile()

        # Process accounting
        matched_p = sum(1 for p in res.reconciled_processes if p.observation_presence == ObservationPresence.OBSERVED_IN_BOTH)
        only_a_p = sum(1 for p in res.reconciled_processes if p.observation_presence == ObservationPresence.OBSERVED_ONLY_IN_A)
        only_b_p = sum(1 for p in res.reconciled_processes if p.observation_presence == ObservationPresence.OBSERVED_ONLY_IN_B)

        self.assertEqual(matched_p + only_a_p, len(rep_a.processes), "Process accounting violated for Report A")
        self.assertEqual(matched_p + only_b_p, len(rep_b.processes), "Process accounting violated for Report B")

        # File accounting
        matched_f = sum(1 for f in res.reconciled_files if f.observation_presence == ObservationPresence.OBSERVED_IN_BOTH)
        only_a_f = sum(1 for f in res.reconciled_files if f.observation_presence == ObservationPresence.OBSERVED_ONLY_IN_A)
        only_b_f = sum(1 for f in res.reconciled_files if f.observation_presence == ObservationPresence.OBSERVED_ONLY_IN_B)

        self.assertEqual(matched_f + only_a_f, len(rep_a.dropped_files), "File accounting violated for Report A")
        self.assertEqual(matched_f + only_b_f, len(rep_b.dropped_files), "File accounting violated for Report B")

        # Network accounting
        matched_n = sum(1 for n in res.reconciled_network if n.observation_presence == ObservationPresence.OBSERVED_IN_BOTH)
        only_a_n = sum(1 for n in res.reconciled_network if n.observation_presence == ObservationPresence.OBSERVED_ONLY_IN_A)
        only_b_n = sum(1 for n in res.reconciled_network if n.observation_presence == ObservationPresence.OBSERVED_ONLY_IN_B)

        self.assertEqual(matched_n + only_a_n, len(rep_a.network_events), "Network accounting violated for Report A")
        self.assertEqual(matched_n + only_b_n, len(rep_b.network_events), "Network accounting violated for Report B")


if __name__ == "__main__":
    unittest.main()
