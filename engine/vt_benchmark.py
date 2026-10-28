"""
Benchmark comparison against VirusTotal's Behavior capabilities (Milestone 3 Disentangled).
Distinguishes measured automated runtime from preliminary manual workload models.
"""

from typing import Any, Dict, List
from .models import CausalExplanation, ComparisonReport, ObservationPresence, ProcessMatchConfidence
from .timing_benchmark import ExecutionBenchmark


class VTBenchmarkEvaluator:
    def __init__(self, comparison_report: ComparisonReport, vt_summary_raw: Dict[str, Any]):
        self.comparison = comparison_report
        self.vt_summary = vt_summary_raw.get("virustotal_sample_behavior", {})

    def evaluate_capabilities(self) -> Dict[str, Any]:
        agg = self.vt_summary.get("aggregated_observations", {})
        vt_dropped_files = agg.get("files_dropped", [])
        vt_processes = agg.get("processes_created", [])

        # 1. File Hash Reconciliation Analysis
        matched_files_in_proto = [
            f for f in self.comparison.reconciled_files
            if f.observation_presence == ObservationPresence.OBSERVED_IN_BOTH and len(f.filenames_by_report) > 1
        ]

        # 2. Process Matching Analysis
        proto_matched_procs = [
            p for p in self.comparison.reconciled_processes
            if p.confidence in [ProcessMatchConfidence.MATCHED, ProcessMatchConfidence.POSSIBLE_MATCH]
        ]

        # 3. Policy decisions & limitations
        policy_blocked = [
            n for n in self.comparison.reconciled_network
            if n.causal_explanation == CausalExplanation.POLICY_DECISION_RECORDED
        ]

        # Measured micro-benchmark
        timing_stats = ExecutionBenchmark.run_benchmark(iterations=50)

        comparison_matrix = {
            "file_reconciliation": {
                "capability": "Cross-sandbox file matching across filename discrepancies",
                "prototype": {
                    "supported": True,
                    "automated": True,
                    "behavior": f"Automatically reconciled {len(matched_files_in_proto)} payload(s) by SHA-256 ('update_payload.exe' == 'staged_runner.bin').",
                    "provenance": "RFC 6901 pointers (/behavior/dropped/0 and /execution/created_files/0)."
                },
                "virustotal_individual_reports": {
                    "supported": True,
                    "automated": False,
                    "behavior": "Contains SHA-256 hashes inside each engine tab, but requires manual copy-paste across tabs to verify equivalence.",
                    "provenance": "Per-sandbox JSON available via API."
                },
                "virustotal_merged_summary": {
                    "supported": False,
                    "automated": True,
                    "behavior": f"Flattens paths into {len(vt_dropped_files)} entries; lists disparate names as separate files without cross-referencing hashes.",
                    "provenance": "Aggregated string list without per-engine provenance."
                }
            },
            "process_comparison": {
                "capability": "Cross-engine process execution alignment across randomized PIDs",
                "prototype": {
                    "supported": True,
                    "automated": True,
                    "behavior": f"Reconciled {len(proto_matched_procs)} process nodes using calibrated multi-factor heuristic scoring.",
                    "provenance": "Preserves both ephemeral PIDs linked to exact RFC 6901 node addresses."
                },
                "virustotal_individual_reports": {
                    "supported": True,
                    "automated": False,
                    "behavior": "Visualizes tree per sandbox engine, but provides no cross-tree alignment, diffing, or node correlation.",
                    "provenance": "Individual engine execution trees."
                },
                "virustotal_merged_summary": {
                    "supported": False,
                    "automated": True,
                    "behavior": f"Collapses commands into {len(vt_processes)} flat strings; destroys execution hierarchy, parentage, and order.",
                    "provenance": "Engine attribution omitted."
                }
            },
            "causal_attribution": {
                "capability": "Disentangle presence from explanations (policy decisions vs environment limitations)",
                "prototype": {
                    "supported": True,
                    "automated": True,
                    "behavior": (
                        f"Disentangled presence from cause: flagged {len(policy_blocked)} connection(s) with recorded policy blocks, "
                        f"while preserving epistemic interpretation that absence in telemetry does not establish non-occurrence."
                    ),
                    "provenance": "Directly links missing telemetry to sandbox system warnings."
                },
                "virustotal_individual_reports": {
                    "supported": False,
                    "automated": False,
                    "behavior": "Displays raw sandbox logs; analyst must manually inspect warning sections to deduce why an observation was missed.",
                    "provenance": "Raw execution logs."
                },
                "virustotal_merged_summary": {
                    "supported": False,
                    "automated": True,
                    "behavior": "Displays union set of IOCs. Silent on which engines saw which indicators and why engines differed.",
                    "provenance": "None."
                }
            }
        }

        # Preliminary manual workload model (explicitly labeled as an analyst estimate)
        manual_workflow_steps = [
            {
                "step_number": 1,
                "task": "Identify identical dropped payloads with different names",
                "vt_method": "Switch between CAPE and Falcon tabs; copy SHA-256 strings into external notepad; manually compare.",
                "prototype_method": "Automated hash-keyed reconciliation table.",
                "estimated_manual_time_mins": 4
            },
            {
                "step_number": 2,
                "task": "Align process execution flow across runs",
                "vt_method": "Open separate tree views in two browser tabs; trace PID 2488 vs PID 7112; manually verify command arguments.",
                "prototype_method": "Calibrated process tree alignment with heuristic scores.",
                "estimated_manual_time_mins": 8
            },
            {
                "step_number": 3,
                "task": "Investigate why Falcon missed C2 traffic observed by CAPE",
                "vt_method": "Open Falcon raw execution warnings; search through JSON for firewall drops or timeout notices.",
                "prototype_method": "Disentangled policy-decision attribution linking C2 to WARN_EGRESS_POLICY.",
                "estimated_manual_time_mins": 6
            }
        ]

        total_manual_time = sum(s["estimated_manual_time_mins"] for s in manual_workflow_steps)

        return {
            "evaluation_verdict": (
                "VirusTotal provides robust per-engine telemetry (hashes and process trees) and merged IOC lists. "
                "However, cross-sandbox comparison remains entirely manual, requiring an estimated 18 minutes of "
                "tab-switching, copy-pasting, and raw-log inspection per sample. "
                f"The prototype automates this reconciliation in {timing_stats['end_to_end_runtime_ms']['mean']:.2f} ms (measured execution time)."
            ),
            "matrix": comparison_matrix,
            "manual_workflow_model": {
                "model_description": "Preliminary Workload Model (Estimated Analyst Workload)",
                "steps": manual_workflow_steps,
                "total_estimated_manual_time_minutes": total_manual_time
            },
            "measured_runtime_benchmark": timing_stats
        }
