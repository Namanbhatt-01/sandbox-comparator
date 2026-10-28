#!/usr/bin/env python3
"""
CLI runner for Evidence-Aware Sandbox Telemetry Comparison (Milestone 3 Disentangled).
"""

import argparse
import json
import sys
from pathlib import Path
from engine.parsers import parse_auto_report
from engine.provenance import resolve_json_pointer
from engine.reconciler import EvidenceComparator
from engine.vt_benchmark import VTBenchmarkEvaluator


def format_markdown_report(comparison, vt_eval=None) -> str:
    lines = []
    lines.append(f"# Evidence-Aware Sandbox Comparison Report")
    lines.append(f"**Target Sample SHA-256**: `{comparison.sample_sha256}`\n")
    
    meta_a = comparison.provenance_metadata.get(comparison.report_a_id, {})
    meta_b = comparison.provenance_metadata.get(comparison.report_b_id, {})
    lines.append(f"- **Report A**: `{comparison.report_a_id}` ({meta_a.get('sandbox')}) — Provenance: `{meta_a.get('provenance_type')}`")
    lines.append(f"- **Report B**: `{comparison.report_b_id}` ({meta_b.get('sandbox')}) — Provenance: `{meta_b.get('provenance_type')}`\n")

    lines.append("## 1. Dropped Files Reconciliation (Disentangled Presence & Explanation)")
    lines.append("| SHA-256 | Observation Presence | Causal Explanation | Filename in A | Filename in B | RFC 6901 Evidence Pointers |")
    lines.append("| :--- | :--- | :--- | :--- | :--- | :--- |")
    for f in comparison.reconciled_files:
        name_a = f.filenames_by_report.get(comparison.report_a_id, "*(not recorded)*")
        name_b = f.filenames_by_report.get(comparison.report_b_id, "*(not recorded)*")
        ptr_a = f.evidence_links.get(comparison.report_a_id)
        ptr_b = f.evidence_links.get(comparison.report_b_id)
        ptrs = []
        if ptr_a and ptr_a.is_available:
            ptrs.append(f"A: `{ptr_a.json_pointer}`")
        if ptr_b and ptr_b.is_available:
            ptrs.append(f"B: `{ptr_b.json_pointer}`")
        malformed_flag = " [MALFORMED HASH]" if f.is_malformed_hash else ""
        lines.append(f"| `{f.sha256[:12]}...`{malformed_flag} | `{f.observation_presence.value}` | `{f.causal_explanation.value}` | `{name_a}` | `{name_b}` | {', '.join(ptrs)} |")

    lines.append("\n**File Epistemic Interpretations**:")
    for f in comparison.reconciled_files:
        lines.append(f"- **`{f.sha256[:16]}...`**: {f.epistemic_interpretation}")

    lines.append("\n## 2. Process Tree Reconciliation (Calibrated Heuristic Scoring)")
    lines.append("| Semantic Process Node | Confidence | Heuristic Score | Presence | Lineage Depth | PID in A | PID in B | RFC 6901 Pointer |")
    lines.append("| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |")
    for p in comparison.reconciled_processes:
        pid_a = p.pids_by_report.get(comparison.report_a_id, "N/A")
        pid_b = p.pids_by_report.get(comparison.report_b_id, "N/A")
        ptr_a = p.evidence_links.get(comparison.report_a_id)
        ptr_b = p.evidence_links.get(comparison.report_b_id)
        ptrs = []
        if ptr_a and ptr_a.is_available:
            ptrs.append(f"A: `{ptr_a.json_pointer}`")
        if ptr_b and ptr_b.is_available:
            ptrs.append(f"B: `{ptr_b.json_pointer}`")
        lines.append(f"| `{p.image_name}` | `{p.confidence.value}` | {p.heuristic_similarity_score:.2f} | `{p.observation_presence.value}` | {len(p.lineage_path)} | `{pid_a}` | `{pid_b}` | {', '.join(ptrs)} |")

    lines.append("\n**Process Lineage Detail & Heuristic Rationale**:")
    for p in comparison.reconciled_processes:
        lines.append(f"- `{p.image_name}`: {p.matching_rationale} | *Interpretation*: {p.epistemic_interpretation}")

    lines.append("\n## 3. Network Reconciliation (Disentangled Presence & Policy Decisions)")
    lines.append("| Connection Key | Observation Type | State | Presence | Causal Status | Policy Record / Context |")
    lines.append("| :--- | :--- | :--- | :--- | :--- | :--- |")
    for n in comparison.reconciled_network:
        policy_rec = n.policy_decision_record or "*(None recorded)*"
        lines.append(f"| `{n.connection_key}` | `{n.observation_type}` | `{n.connection_state}` | `{n.observation_presence.value}` | `{n.causal_status}` | {policy_rec} |")

    lines.append("\n**Network Epistemic Interpretations**:")
    for n in comparison.reconciled_network:
        lines.append(f"- **`{n.connection_key}`** ({n.cross_report_correlation}): {n.epistemic_interpretation}")

    lines.append("\n## 4. Collection Limitations & Schema Coverage")
    for rep_id, lims in comparison.collection_limitations.items():
        lines.append(f"### Limitations recorded by `{rep_id}`:")
        if not lims:
            lines.append("- *(No collection warnings recorded)*")
        for lim in lims:
            lines.append(f"- **[{lim.code}]** ({lim.category}): {lim.description}")

    # Surface unmapped schema fields
    for rep_id, meta in comparison.provenance_metadata.items():
        unmapped = meta.get("parser_warnings", [])
        if unmapped:
            lines.append(f"\n### Unmapped / Unsupported Fields for `{rep_id}`:")
            for u in unmapped:
                lines.append(f"- {u}")

    if vt_eval:
        lines.append("\n## 5. Performance & Competitor Benchmark Evaluation")
        timing = vt_eval.get("measured_runtime_benchmark", {})
        e2e = timing.get("end_to_end_runtime_ms", {})
        workload = vt_eval.get("manual_workflow_model", {})
        lines.append(f"- **Measured Machine Runtime (Mean / Median / p95)**: `{e2e.get('mean')} ms / {e2e.get('median')} ms / {e2e.get('p95')} ms` (N={timing.get('iterations')} runs on in-memory fixtures)")
        lines.append(f"- **Estimated Analyst Cognitive Review Time**: `~60 to 120 seconds` (reading & verifying diff table)")
        lines.append(f"- **Preliminary Manual Workload Model (VirusTotal Tabs)**: `~{workload.get('total_estimated_manual_time_minutes')} minutes` across 3 cross-tab inspection tasks\n")

        matrix = vt_eval.get("matrix", {})
        lines.append("| Capability | Prototype (Automated) | VT Individual Reports (Manual) | VT Merged Summary |")
        lines.append("| :--- | :--- | :--- | :--- |")
        for dim, data in matrix.items():
            proto_b = data["prototype"]["behavior"]
            vt_ind = data["virustotal_individual_reports"]["behavior"]
            vt_mrg = data["virustotal_merged_summary"]["behavior"]
            lines.append(f"| **{data['capability']}** | {proto_b} | {vt_ind} | {vt_mrg} |")

        lines.append(f"\n**Verdict**: {vt_eval.get('evaluation_verdict')}")
    return "\n".join(lines)


def main():
    # Seamless routing for subcommands: "sandbox-comparator ui" or "sandbox-comparator compare ..."
    if len(sys.argv) > 1 and sys.argv[1] == "ui":
        from run_app import main as run_ui
        sys.argv.pop(1)
        run_ui()
        return

    if len(sys.argv) > 1 and sys.argv[1] == "compare":
        sys.argv.pop(1)

    parser = argparse.ArgumentParser(
        prog="sandbox-comparator",
        description="Evidence-Aware Malware Sandbox Report Comparator (Offline-First Product CLI)"
    )
    parser.add_argument("--report-a", default="data/report_format_a_cape.json", help="Path to Report A JSON")
    parser.add_argument("--report-b", default="data/report_format_b_falcon.json", help="Path to Report B JSON")
    parser.add_argument("--vt-ref", default=None, help="Optional path to VT summary JSON for benchmark comparison")
    parser.add_argument("--format", choices=["text", "json", "markdown"], default="markdown", help="Output format")
    args = parser.parse_args()

    base_dir = Path(__file__).resolve().parent
    path_a = base_dir / args.report_a if not Path(args.report_a).is_absolute() else Path(args.report_a)
    path_b = base_dir / args.report_b if not Path(args.report_b).is_absolute() else Path(args.report_b)

    with open(path_a, "r") as fa:
        raw_a = json.load(fa)
    with open(path_b, "r") as fb:
        raw_b = json.load(fb)

    norm_a = parse_auto_report(raw_a, report_id=path_a.stem)
    norm_b = parse_auto_report(raw_b, report_id=path_b.stem)

    comparator = EvidenceComparator(norm_a, norm_b)
    comparison = comparator.reconcile()

    benchmark_res = None
    if args.vt_ref:
        path_vt = base_dir / args.vt_ref if not Path(args.vt_ref).is_absolute() else Path(args.vt_ref)
        if path_vt.exists():
            with open(path_vt, "r") as fvt:
                raw_vt = json.load(fvt)
            vt_evaluator = VTBenchmarkEvaluator(comparison, raw_vt)
            benchmark_res = vt_evaluator.evaluate_capabilities()

    if args.format == "markdown":
        md = format_markdown_report(comparison, benchmark_res)
        print(md)
    elif args.format == "json":
        out_dict = {
            "sample_sha256": comparison.sample_sha256,
            "provenance_metadata": comparison.provenance_metadata,
            "reconciled_files": [
                {
                    "sha256": f.sha256,
                    "observation_presence": f.observation_presence.value,
                    "causal_explanation": f.causal_explanation.value,
                    "filenames": f.filenames_by_report,
                    "paths": f.file_paths_by_report,
                    "epistemic_interpretation": f.epistemic_interpretation,
                    "is_malformed_hash": f.is_malformed_hash,
                    "evidence_pointers": {k: v.to_dict() for k, v in f.evidence_links.items()}
                }
                for f in comparison.reconciled_files
            ],
            "reconciled_processes": [
                {
                    "image": p.image_name,
                    "observation_presence": p.observation_presence.value,
                    "confidence": p.confidence.value,
                    "heuristic_similarity_score": p.heuristic_similarity_score,
                    "matching_rationale": p.matching_rationale,
                    "causal_explanation": p.causal_explanation.value,
                    "epistemic_interpretation": p.epistemic_interpretation,
                    "pids": p.pids_by_report,
                    "evidence_pointers": {k: v.to_dict() for k, v in p.evidence_links.items()}
                }
                for p in comparison.reconciled_processes
            ],
            "reconciled_network": [
                {
                    "connection": n.connection_key,
                    "observation_presence": n.observation_presence.value,
                    "causal_explanation": n.causal_explanation.value,
                    "policy_decision_record": n.policy_decision_record,
                    "epistemic_interpretation": n.epistemic_interpretation,
                    "observed_in": n.observed_in_reports,
                    "unobserved_in": n.unobserved_in_reports,
                    "evidence_pointers": {k: v.to_dict() for k, v in n.evidence_links.items()}
                }
                for n in comparison.reconciled_network
            ],
            "benchmark_evaluation": benchmark_res
        }
        print(json.dumps(out_dict, indent=2))
    else:
        print("=== Evidence-Aware Sandbox Comparison Summary (Milestone 3) ===")
        print(f"Sample: {comparison.sample_sha256}")
        print(f"Files Reconciled: {len(comparison.reconciled_files)}")
        print(f"Processes Reconciled: {len(comparison.reconciled_processes)}")
        print(f"Network Events Reconciled: {len(comparison.reconciled_network)}")


if __name__ == "__main__":
    main()
