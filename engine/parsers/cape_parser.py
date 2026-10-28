"""
Parser for CAPE Sandbox v2.5 JSON reports.
Provenance: Documented open-source community schema (CAPE Sandbox v2.5 / Cuckoo-derived).
Reference: https://capev2.readthedocs.io/

Implements defensive ingestion:
- Supports authentic native CAPE v2 root layout (info, target.file, network, dropped)
  as well as wrapped community/fixture formats.
- Validates cryptographic SHA-256 integrity (detects malformed/absent hashes).
- Robustly handles missing sections, null dictionaries, and string PIDs.
- Formats evidence paths as RFC 6901 JSON Pointers that resolve directly to source keys.
- Surfaces unmapped / unsupported authentic sections (signatures, memory, apistats, debug).
"""

import re
from typing import Any, Dict, List, Optional
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


def parse_cape_report(raw: Optional[Dict[str, Any]], report_id: str = "report_a_cape") -> NormalizedReport:
    if raw is None or not isinstance(raw, dict):
        raw = {}

    # Support authentic native CAPE v2 root layout as well as wrapped community layout
    info = raw.get("info") or raw.get("report_metadata") or {}
    raw_target = raw.get("target") or info.get("target") or {}

    # Target file in CAPE v2 is often under target["file"] or directly in target
    if isinstance(raw_target.get("file"), dict):
        target_dict = raw_target["file"]
    elif isinstance(raw_target, dict):
        target_dict = raw_target
    else:
        target_dict = {}

    sample_sha256 = str(target_dict.get("sha256", "")).lower().strip()

    env = raw.get("environment") or info.get("environment") or {}
    duration = env.get("analysis_duration_seconds") or info.get("duration")

    sandbox_name = info.get("sandbox_name") or f"CAPE Sandbox {info.get('version', 'v2.5')}"
    schema_format = info.get("report_format") or (f"cape_v2_native_{info.get('version')}" if "version" in info else "cape_json_v2")

    norm_report = NormalizedReport(
        report_id=report_id,
        sandbox_name=sandbox_name,
        schema_format=schema_format,
        schema_provenance_type="DOCUMENTED_VENDOR_FORMAT",
        sample_sha256=sample_sha256,
        duration_seconds=duration,
        limitations=[],
        parser_warnings=[],
        unsupported_fields=[]
    )

    behavior = raw.get("behavior") if isinstance(raw.get("behavior"), dict) else {}

    # Surface unmapped vendor sections
    for unmapped in ["signatures", "memory", "debug", "apistats", "virustotal", "strings", "curtain", "extracted"]:
        if unmapped in raw or unmapped in behavior:
            norm_report.unsupported_fields.append(f"CAPE v2.2 schema section '{unmapped}' is unmapped in current normalized schema")

    if "summary" in behavior:
        summary_obj = behavior["summary"]
        if isinstance(summary_obj, dict):
            if summary_obj.get("keys"):
                norm_report.unsupported_fields.append("CAPE v2.2 schema 'behavior.summary.keys' (registry) is unmapped")
            if summary_obj.get("mutexes"):
                norm_report.unsupported_fields.append("CAPE v2.2 schema 'behavior.summary.mutexes' is unmapped")

    # 1. Limitations or warnings
    raw_warnings = info.get("errors_or_warnings") or raw.get("debug", {}).get("errors") or []
    if not isinstance(raw_warnings, list):
        raw_warnings = []
    for idx, warn in enumerate(raw_warnings):
        norm_report.limitations.append(
            CollectionLimitation(
                report_id=report_id,
                code=f"CAPE_WARN_{idx}",
                description=str(warn),
                category="RUNTIME_WARNING"
            )
        )

    # 2. Process tree & lineage
    raw_processes = behavior.get("processes") if isinstance(behavior.get("processes"), list) else []
    pid_to_proc: Dict[int, Dict[str, Any]] = {}
    for p in raw_processes:
        if isinstance(p, dict) and "process_id" in p:
            try:
                pid_int = int(p["process_id"])
                pid_to_proc[pid_int] = p
            except (ValueError, TypeError):
                norm_report.parser_warnings.append(f"Invalid non-integer process_id: {p.get('process_id')}")

    def resolve_lineage(pid: int, visited: Optional[set] = None) -> List[str]:
        if visited is None:
            visited = set()
        if pid in visited or pid not in pid_to_proc:
            return []
        visited.add(pid)
        proc = pid_to_proc[pid]
        parent_raw = proc.get("parent_id")
        parent_id = None
        if parent_raw is not None:
            try:
                parent_id = int(parent_raw)
            except (ValueError, TypeError):
                parent_id = None
        parent_lineage = resolve_lineage(parent_id, visited) if parent_id else []
        name = str(proc.get("process_name") or "unknown")
        return parent_lineage + [name]

    for idx, proc in enumerate(raw_processes):
        if not isinstance(proc, dict):
            continue
        try:
            pid = int(proc.get("process_id", 0))
        except (ValueError, TypeError):
            pid = 0

        parent_raw = proc.get("parent_id")
        ppid = int(parent_raw) if parent_raw is not None and str(parent_raw).isdigit() else None
        name = str(proc.get("process_name") or "unknown")
        cmd = str(proc.get("command_line") or "")
        lineage = resolve_lineage(pid)
        if not lineage:
            lineage = [name]

        pointer_str = build_rfc6901_pointer(["behavior", "processes", idx])
        pointer = EvidencePointer(
            report_id=report_id,
            json_pointer=pointer_str,
            event_summary=f"PID {pid} ({name}) created with cmd: {cmd[:60]}...",
            raw_snippet={
                "process_id": pid,
                "parent_id": ppid,
                "process_name": name,
                "command_line": cmd,
                "first_seen": proc.get("first_seen")
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
                lineage_path=lineage,
                tree_depth=len(lineage),
                evidence=pointer
            )
        )

    # 3. Dropped files (Check root "dropped" first, then "behavior.dropped")
    if "dropped" in raw and isinstance(raw["dropped"], list):
        raw_dropped = raw["dropped"]
        dropped_pointer_base = ["dropped"]
    else:
        raw_dropped = behavior.get("dropped") if isinstance(behavior.get("dropped"), list) else []
        dropped_pointer_base = ["behavior", "dropped"]

    for idx, df in enumerate(raw_dropped):
        if not isinstance(df, dict):
            continue
        name = str(df.get("name") or "unnamed_artifact")
        guest_paths = df.get("guest_paths") or []
        path = guest_paths[0] if guest_paths else str(df.get("path") or "")
        raw_hash = str(df.get("sha256") or "").lower().strip()
        is_malformed = not bool(HEX_SHA256_REGEX.match(raw_hash))
        if is_malformed:
            norm_report.parser_warnings.append(f"Dropped file at index {idx} has malformed/missing SHA-256: '{raw_hash}'")

        try:
            size = int(df.get("size", 0))
        except (ValueError, TypeError):
            size = 0
        ftype = str(df.get("type") or "")

        pointer_str = build_rfc6901_pointer(dropped_pointer_base + [idx])
        pointer = EvidencePointer(
            report_id=report_id,
            json_pointer=pointer_str,
            event_summary=f"Dropped file '{name}' with SHA256 {raw_hash[:12]}...",
            raw_snippet={
                "name": name,
                "path": path,
                "sha256": raw_hash,
                "size": size,
                "type": ftype,
                "dropped_by_pid": df.get("dropped_by_pid")
            },
            is_available=True
        )

        norm_report.dropped_files.append(
            DroppedFileObservation(
                report_id=report_id,
                sha256=raw_hash,
                file_path=path,
                file_name=name,
                file_size=size,
                file_type=ftype,
                evidence=pointer,
                is_malformed_hash=is_malformed
            )
        )

    # 4. Network (Check root "network" first, then "behavior.network")
    if "network" in raw and isinstance(raw["network"], dict):
        network = raw["network"]
        network_pointer_base = ["network"]
    else:
        network = behavior.get("network") or {}
        network_pointer_base = ["behavior", "network"]

    dns_list = network.get("dns") if isinstance(network.get("dns"), list) else []
    for idx, dns in enumerate(dns_list):
        if not isinstance(dns, dict):
            continue
        domain = str(dns.get("domain") or "")
        resolved = str(dns.get("resolved_ip") or "")
        pointer_str = build_rfc6901_pointer(network_pointer_base + ["dns", idx])
        pointer = EvidencePointer(
            report_id=report_id,
            json_pointer=pointer_str,
            event_summary=f"DNS query for '{domain}' resolved to '{resolved}'",
            raw_snippet=dns,
            is_available=True
        )
        norm_report.network_events.append(
            NetworkObservation(
                report_id=report_id,
                protocol="DNS",
                destination=domain,
                port=53,
                evidence=pointer
            )
        )

    http_list = network.get("http") if isinstance(network.get("http"), list) else []
    for idx, http in enumerate(http_list):
        if not isinstance(http, dict):
            continue
        url = str(http.get("url") or "")
        method = str(http.get("method") or "GET")
        pointer_str = build_rfc6901_pointer(network_pointer_base + ["http", idx])
        pointer = EvidencePointer(
            report_id=report_id,
            json_pointer=pointer_str,
            event_summary=f"HTTP {method} request to '{url}'",
            raw_snippet=http,
            is_available=True
        )
        norm_report.network_events.append(
            NetworkObservation(
                report_id=report_id,
                protocol="HTTP",
                destination=url,
                port=80 if url.startswith("http://") else 443,
                evidence=pointer
            )
        )

    tcp_list = network.get("tcp") if isinstance(network.get("tcp"), list) else []
    for idx, tcp in enumerate(tcp_list):
        if not isinstance(tcp, dict):
            continue
        dst_ip = str(tcp.get("dst_ip") or "")
        try:
            dst_port = int(tcp.get("dst_port", 0))
        except (ValueError, TypeError):
            dst_port = 0

        pointer_str = build_rfc6901_pointer(network_pointer_base + ["tcp", idx])
        pointer = EvidencePointer(
            report_id=report_id,
            json_pointer=pointer_str,
            event_summary=f"TCP stream to {dst_ip}:{dst_port}",
            raw_snippet=tcp,
            is_available=True
        )
        norm_report.network_events.append(
            NetworkObservation(
                report_id=report_id,
                protocol="TCP",
                destination=dst_ip,
                port=dst_port,
                evidence=pointer
            )
        )

    return norm_report
