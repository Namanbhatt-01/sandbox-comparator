"""
Parser for Falcon-like Sandbox Cloud JSON reports.
Provenance: Synthetic Falcon-like Schema (v7.x approximation).
Note: Models hierarchical process trees and perimeter warning dictionaries,
but is a synthetic approximation rather than an officially certified vendor export.

Implements defensive ingestion:
- Validates cryptographic SHA-256 integrity (detects malformed/absent hashes).
- Robustly handles missing sections, null dictionaries, and string PIDs.
- Formats evidence paths as RFC 6901 JSON Pointers.
"""

import re
from typing import Any, Dict, List, Optional, Union
from ..models import (
    CollectionLimitation,
    DroppedFileObservation,
    EvidencePointer,
    NetworkObservation,
    NormalizedReport,
    ProcessObservation,
)
from ..provenance import build_rfc6901_pointer

HEX_SHA256_REGEX = re.compile(r"^[a-fA-F0-9]{64}$")


def parse_falcon_report(raw: Optional[Dict[str, Any]], report_id: str = "report_b_falcon") -> NormalizedReport:
    if raw is None or not isinstance(raw, dict):
        raw = {}

    sub_info = raw.get("submission_info") or {}
    sample_meta = sub_info.get("sample_metadata") or {}
    execution = raw.get("execution") or {}

    norm_report = NormalizedReport(
        report_id=report_id,
        sandbox_name=sub_info.get("analyzer", "Synthetic Falcon-like Sandbox (v7.x approximation)"),
        schema_format=sub_info.get("schema", "falcon_hybrid_synthetic_v3"),
        schema_provenance_type="SYNTHETIC_APPROXIMATION",
        sample_sha256=str(sample_meta.get("sha256", "")).lower().strip(),
        duration_seconds=sub_info.get("runtime_budget_seconds"),
        limitations=[],
        parser_warnings=[],
        unsupported_fields=[]
    )

    # Surface unmapped sections
    for unmapped in ["signatures", "mitre_attacks", "registry_events", "memory_injections"]:
        if unmapped in execution or unmapped in raw:
            norm_report.unsupported_fields.append(f"Falcon-like section '{unmapped}' is unmapped in current normalized schema")

    # 1. Limitations & system warnings
    raw_warnings = sub_info.get("system_warnings") or []
    for idx, warn in enumerate(raw_warnings):
        if not isinstance(warn, dict):
            continue
        code = str(warn.get("code") or "WARN_GENERIC")
        desc = str(warn.get("description") or "")
        category = "TIMEOUT" if "TIMEOUT" in code else ("EGRESS_POLICY" if "EGRESS" in code else "ENVIRONMENT")
        target_pattern = "port:8080" if "8080" in desc else None
        
        warn_pointer = EvidencePointer(
            report_id=report_id,
            json_pointer=build_rfc6901_pointer(["submission_info", "system_warnings", idx]),
            event_summary=f"System warning [{code}]: {desc}",
            raw_snippet=warn,
            is_available=True
        )
        
        norm_report.limitations.append(
            CollectionLimitation(
                report_id=report_id,
                code=code,
                description=desc,
                category=category,
                target_pattern=target_pattern,
                evidence=warn_pointer
            )
        )

    # 2. Hierarchical process tree with RFC 6901 pointers
    def traverse_node(node: Dict[str, Any], parent_lineage: List[str], token_path: List[Union[str, int]]):
        if not isinstance(node, dict):
            return
        try:
            pid = int(node.get("pid", 0))
        except (ValueError, TypeError):
            pid = 0
            norm_report.parser_warnings.append(f"Non-integer pid in process tree: {node.get('pid')}")

        parent_raw = node.get("ppid")
        ppid = int(parent_raw) if parent_raw is not None and str(parent_raw).isdigit() else None
        name = str(node.get("name") or "unknown")
        cmd = str(node.get("cmdline") or "")
        current_lineage = parent_lineage + [name]

        pointer_str = build_rfc6901_pointer(token_path)
        pointer = EvidencePointer(
            report_id=report_id,
            json_pointer=pointer_str,
            event_summary=f"PID {pid} ({name}) created with cmd: {cmd[:60]}...",
            raw_snippet={
                "pid": pid,
                "ppid": ppid,
                "name": name,
                "cmdline": cmd,
                "integrity_level": node.get("integrity_level")
            },
            is_available=True
        )

        norm_report.processes.append(
            ProcessObservation(
                report_id=report_id,
                source_pid=pid,
                source_ppid=ppid,
                image_name=name,
                command_line=cmd,
                lineage_path=current_lineage,
                tree_depth=len(current_lineage),
                evidence=pointer
            )
        )

        children = node.get("children") or []
        for c_idx, child in enumerate(children):
            traverse_node(child, current_lineage, token_path + ["children", c_idx])

    root_processes = execution.get("process_tree") or []
    for r_idx, root_node in enumerate(root_processes):
        traverse_node(root_node, [], ["execution", "process_tree", r_idx])

    # 3. Created files
    created_files = execution.get("created_files") or []
    for idx, cf in enumerate(created_files):
        if not isinstance(cf, dict):
            continue
        fname = str(cf.get("filename") or "unnamed_artifact")
        base_name = fname.replace("\\", "/").split("/")[-1]
        raw_hash = str(cf.get("sha256_hash") or "").lower().strip()
        is_malformed = not bool(HEX_SHA256_REGEX.match(raw_hash))
        if is_malformed:
            norm_report.parser_warnings.append(f"Created file at index {idx} has malformed/missing SHA-256: '{raw_hash}'")

        try:
            size = int(cf.get("file_bytes", 0))
        except (ValueError, TypeError):
            size = 0
        magic = str(cf.get("magic") or "")

        pointer_str = build_rfc6901_pointer(["execution", "created_files", idx])
        pointer = EvidencePointer(
            report_id=report_id,
            json_pointer=pointer_str,
            event_summary=f"Created file '{base_name}' with SHA256 {raw_hash[:12]}...",
            raw_snippet={
                "filename": fname,
                "sha256_hash": raw_hash,
                "file_bytes": size,
                "magic": magic,
                "origin_pid": cf.get("origin_pid")
            },
            is_available=True
        )

        norm_report.dropped_files.append(
            DroppedFileObservation(
                report_id=report_id,
                sha256=raw_hash,
                file_path=fname,
                file_name=base_name,
                file_size=size,
                file_type=magic,
                evidence=pointer,
                is_malformed_hash=is_malformed
            )
        )

    # 4. Network traffic
    net = execution.get("network_traffic") or {}
    for idx, dns in enumerate(net.get("dns_requests") or []):
        if not isinstance(dns, dict):
            continue
        host = str(dns.get("hostname") or "")
        ip_list = dns.get("ip_addresses") or [""]
        resolved = str(ip_list[0]) if ip_list else ""
        pointer_str = build_rfc6901_pointer(["execution", "network_traffic", "dns_requests", idx])
        pointer = EvidencePointer(
            report_id=report_id,
            json_pointer=pointer_str,
            event_summary=f"DNS query for '{host}' (resolved: {resolved})",
            raw_snippet=dns,
            is_available=True
        )
        norm_report.network_events.append(
            NetworkObservation(
                report_id=report_id,
                protocol="DNS",
                destination=host,
                port=53,
                evidence=pointer
            )
        )

    for idx, http in enumerate(net.get("http_transactions") or []):
        if not isinstance(http, dict):
            continue
        uri = str(http.get("uri") or "")
        method = str(http.get("method") or "GET")
        pointer_str = build_rfc6901_pointer(["execution", "network_traffic", "http_transactions", idx])
        pointer = EvidencePointer(
            report_id=report_id,
            json_pointer=pointer_str,
            event_summary=f"HTTP {method} to '{uri}'",
            raw_snippet=http,
            is_available=True
        )
        norm_report.network_events.append(
            NetworkObservation(
                report_id=report_id,
                protocol="HTTP",
                destination=uri,
                port=80 if uri.startswith("http://") else 443,
                evidence=pointer
            )
        )

    for idx, tcp in enumerate(net.get("active_tcp_streams") or []):
        if not isinstance(tcp, dict):
            continue
        dip = str(tcp.get("destination_ip") or "")
        try:
            dport = int(tcp.get("destination_port", 0))
        except (ValueError, TypeError):
            dport = 0

        pointer_str = build_rfc6901_pointer(["execution", "network_traffic", "active_tcp_streams", idx])
        pointer = EvidencePointer(
            report_id=report_id,
            json_pointer=pointer_str,
            event_summary=f"Active TCP connection to {dip}:{dport}",
            raw_snippet=tcp,
            is_available=True
        )
        norm_report.network_events.append(
            NetworkObservation(
                report_id=report_id,
                protocol="TCP",
                destination=dip,
                port=dport,
                evidence=pointer
            )
        )

    return norm_report
