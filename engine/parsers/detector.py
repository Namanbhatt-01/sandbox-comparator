"""
Schema autodetection and unified report ingestion.
Allows automatic ingestion of CAPE Sandbox and Falcon-like sandbox reports without hardcoding.
"""

from typing import Any, Dict, Optional
from ..models import NormalizedReport
from .cape_parser import parse_cape_report
from .falcon_parser import parse_falcon_report


def detect_schema(raw: Optional[Dict[str, Any]]) -> str:
    """
    Detects the sandbox report schema from JSON dictionary structure.
    Returns: 'falcon' | 'cape' | 'unknown'
    """
    if not isinstance(raw, dict):
        return "unknown"

    # Falcon-like signatures
    sub_info = raw.get("submission_info")
    if isinstance(sub_info, dict) and ("analyzer" in sub_info or "sample_metadata" in sub_info):
        return "falcon"
    if "submission_info" in raw:
        return "falcon"
    if isinstance(raw.get("execution"), dict) and "process_tree" in raw["execution"]:
        return "falcon"

    # CAPE v2 / Cuckoo signatures
    if "info" in raw or "report_metadata" in raw:
        return "cape"
    if "behavior" in raw or "target" in raw or "dropped" in raw:
        return "cape"

    return "unknown"


def parse_auto_report(raw: Optional[Dict[str, Any]], report_id: str = "report") -> NormalizedReport:
    """
    Autodetects the report format and routes to the appropriate parser.
    Supports comparing any combination (CAPE vs CAPE, Falcon vs Falcon, CAPE vs Falcon).
    """
    schema = detect_schema(raw)
    if schema == "falcon":
        return parse_falcon_report(raw, report_id=report_id)
    else:
        # Defaults to CAPE parser (handles native root layout, wrapped layout, and generic structures)
        norm = parse_cape_report(raw, report_id=report_id)
        if schema == "unknown":
            norm.parser_warnings.append("Schema could not be conclusively identified; defaulted to CAPE/Cuckoo defensive parser.")
        return norm

