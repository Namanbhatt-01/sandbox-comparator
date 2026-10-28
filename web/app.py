"""
FastAPI application for Evidence-Aware Sandbox Comparator (Local-First MVP).
Provides offline-first reconciliation endpoints and serves the modern dark-mode dashboard.
"""

import json
from pathlib import Path
from typing import Any, Dict, Optional
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from pydantic import BaseModel

from engine.parsers import parse_auto_report
from engine.reconciler import EvidenceComparator
from cli import format_markdown_report

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"

app = FastAPI(
    title="Evidence-Aware Sandbox Comparator",
    description="Offline-first malware sandbox comparison and evidence verification platform.",
    version="1.0.0"
)


class CompareRequest(BaseModel):
    preset_id: Optional[str] = None
    report_a_raw: Optional[Dict[str, Any]] = None
    report_b_raw: Optional[Dict[str, Any]] = None
    report_a_name: Optional[str] = "Report A"
    report_b_name: Optional[str] = "Report B"


def serialize_comparison(comparison) -> Dict[str, Any]:
    """Helper to turn ComparisonReport into JSON-serializable dictionary."""
    files_out = [
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
    ]

    procs_out = [
        {
            "image": p.image_name,
            "lineage_path": p.lineage_path,
            "depth": len(p.lineage_path),
            "observation_presence": p.observation_presence.value,
            "confidence": p.confidence.value,
            "heuristic_similarity_score": p.heuristic_similarity_score,
            "matching_rationale": p.matching_rationale,
            "causal_explanation": p.causal_explanation.value,
            "epistemic_interpretation": p.epistemic_interpretation,
            "pids": p.pids_by_report,
            "commands": p.commands_by_report,
            "evidence_pointers": {k: v.to_dict() for k, v in p.evidence_links.items()},
            "alternatives": p.alternative_candidates
        }
        for p in comparison.reconciled_processes
    ]

    net_out = [
        {
            "connection": n.connection_key,
            "observation_presence": n.observation_presence.value,
            "connection_state": n.connection_state,
            "causal_status": n.causal_status,
            "causal_explanation": n.causal_explanation.value,
            "policy_record": n.policy_decision_record,
            "cross_report_correlation": n.cross_report_correlation,
            "epistemic_interpretation": n.epistemic_interpretation,
            "observed_in": n.observed_in_reports,
            "unobserved_in": n.unobserved_in_reports,
            "evidence_pointers": {k: v.to_dict() for k, v in n.evidence_links.items()}
        }
        for n in comparison.reconciled_network
    ]

    limitations_out = {}
    for rep_id, lims in comparison.collection_limitations.items():
        limitations_out[rep_id] = [
            {
                "code": l.code,
                "description": l.description,
                "category": l.category,
                "target_pattern": l.target_pattern,
                "evidence": l.evidence.to_dict() if l.evidence else None
            }
            for l in lims
        ]

    # Metrics calculation
    matched_procs = sum(1 for p in procs_out if p["observation_presence"] == "OBSERVED_IN_BOTH")
    unresolved_procs = sum(1 for p in procs_out if p["observation_presence"] != "OBSERVED_IN_BOTH")
    matched_files = sum(1 for f in files_out if f["observation_presence"] == "OBSERVED_IN_BOTH")
    unresolved_files = sum(1 for f in files_out if f["observation_presence"] != "OBSERVED_IN_BOTH")
    matched_net = sum(1 for n in net_out if n["observation_presence"] == "OBSERVED_IN_BOTH")
    unresolved_net = sum(1 for n in net_out if n["observation_presence"] != "OBSERVED_IN_BOTH")

    return {
        "sample_sha256": comparison.sample_sha256,
        "report_a_id": comparison.report_a_id,
        "report_b_id": comparison.report_b_id,
        "provenance_metadata": comparison.provenance_metadata,
        "reconciled_files": files_out,
        "reconciled_processes": procs_out,
        "reconciled_network": net_out,
        "collection_limitations": limitations_out,
        "metrics": {
            "matched_processes": matched_procs,
            "unresolved_processes": unresolved_procs,
            "matched_files": matched_files,
            "unresolved_files": unresolved_files,
            "matched_network": matched_net,
            "unresolved_network": unresolved_net,
            "total_limitations": sum(len(v) for v in limitations_out.values())
        }
    }


@app.get("/api/health")
def health():
    return {"status": "ok", "architecture": "offline-first-local-mvp"}


@app.get("/api/presets")
def get_presets():
    return [
        {
            "id": "scenario_y",
            "name": "Scenario Y: Schema Divergence (CAPE v2.4 export vs Synthetic Falcon approximation)",
            "description": "Cross-sandbox behavioral reconciliation of invoice_oct2026.exe across schemas (CAPE fixture vs synthetic Falcon-like approximation).",
            "file_a": "report_format_a_cape.json",
            "file_b": "report_format_b_falcon.json"
        },
        {
            "id": "scenario_x",
            "name": "Scenario X: Structural Variation (CAPE v2.4 fixture vs Sanitized CAPE v2.2 native fixture)",
            "description": "Cross-version schema variation comparing a CAPE v2.4 fixture with a real sanitized CAPE v2.2 export.",
            "file_a": "report_format_a_cape.json",
            "file_b": "real_sanitized_cape_v2_export.json"
        }
    ]


@app.post("/api/compare")
def compare_reports(req: CompareRequest):
    raw_a: Dict[str, Any] = {}
    raw_b: Dict[str, Any] = {}
    id_a = req.report_a_name or "report_a"
    id_b = req.report_b_name or "report_b"

    if req.preset_id:
        if req.preset_id == "scenario_y":
            file_a = DATA_DIR / "report_format_a_cape.json"
            file_b = DATA_DIR / "report_format_b_falcon.json"
            id_a = "cape_v2.4_fixture"
            id_b = "synthetic_falcon_approx"
        elif req.preset_id == "scenario_x":
            file_a = DATA_DIR / "report_format_a_cape.json"
            file_b = DATA_DIR / "real_sanitized_cape_v2_export.json"
            id_a = "cape_v2.4_fixture"
            id_b = "sanitized_cape_v2.2_export"
        else:
            raise HTTPException(status_code=404, detail="Preset not found")

        with open(file_a, "r") as fa:
            raw_a = json.load(fa)
        with open(file_b, "r") as fb:
            raw_b = json.load(fb)
    else:
        if not req.report_a_raw or not req.report_b_raw:
            raise HTTPException(status_code=400, detail="Both report_a_raw and report_b_raw must be provided")
        raw_a = req.report_a_raw
        raw_b = req.report_b_raw

    norm_a = parse_auto_report(raw_a, report_id=id_a)
    norm_b = parse_auto_report(raw_b, report_id=id_b)

    comparator = EvidenceComparator(norm_a, norm_b)
    comparison = comparator.reconcile()

    serialized = serialize_comparison(comparison)
    serialized["markdown_report"] = format_markdown_report(comparison)
    return serialized


@app.get("/", response_class=HTMLResponse)
def serve_ui():
    html_file = Path(__file__).resolve().parent / "static" / "index.html"
    if html_file.exists():
        with open(html_file, "r") as f:
            return f.read()
    return "<h1>Sandbox Comparator UI Not Found</h1>"
