use crate::models::{
    CollectionLimitation, DroppedFileObservation, EvidencePointer, NetworkObservation,
    NormalizedReport, ProcessObservation,
};
use crate::provenance::{build_rfc6901_pointer, preview_str};
use serde_json::Value;
use std::collections::{HashMap, HashSet};

fn is_valid_sha256(s: &str) -> bool {
    s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())
}

pub fn parse_cape_report(raw: &Value, report_id: &str) -> NormalizedReport {
    let empty_obj = serde_json::Map::new();
    let root = raw.as_object().unwrap_or(&empty_obj);

    let info = root
        .get("info")
        .and_then(|v| v.as_object())
        .or_else(|| root.get("report_metadata").and_then(|v| v.as_object()));

    // Target sample SHA-256
    let raw_target = root
        .get("target")
        .and_then(|v| v.as_object())
        .or_else(|| info.and_then(|i| i.get("target")).and_then(|v| v.as_object()));

    let target_dict = if let Some(t) = raw_target {
        if let Some(f) = t.get("file").and_then(|v| v.as_object()) {
            Some(f)
        } else {
            Some(t)
        }
    } else {
        None
    };

    let sample_sha256 = target_dict
        .and_then(|t| t.get("sha256"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_ascii_lowercase()
        .trim()
        .to_string();

    let env = root
        .get("environment")
        .and_then(|v| v.as_object())
        .or_else(|| info.and_then(|i| i.get("environment")).and_then(|v| v.as_object()));

    let duration_seconds = env
        .and_then(|e| e.get("analysis_duration_seconds"))
        .and_then(|v| v.as_u64())
        .or_else(|| info.and_then(|i| i.get("duration")).and_then(|v| v.as_u64()));

    let sandbox_name = info
        .and_then(|i| i.get("sandbox_name"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| {
            let ver = info
                .and_then(|i| i.get("version"))
                .and_then(|v| v.as_str())
                .unwrap_or("v2.5");
            format!("CAPE Sandbox {}", ver)
        });

    let schema_format = info
        .and_then(|i| i.get("report_format"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| {
            if let Some(ver) = info.and_then(|i| i.get("version")).and_then(|v| v.as_str()) {
                format!("cape_v2_native_{}", ver)
            } else {
                "cape_json_v2".to_string()
            }
        });

    let behavior = root.get("behavior").and_then(|v| v.as_object());

    let mut norm_report = NormalizedReport {
        report_id: report_id.to_string(),
        sandbox_name,
        schema_format,
        schema_provenance_type: "DOCUMENTED_VENDOR_FORMAT".to_string(),
        sample_sha256,
        duration_seconds,
        processes: Vec::new(),
        dropped_files: Vec::new(),
        network_events: Vec::new(),
        limitations: Vec::new(),
        parser_warnings: Vec::new(),
        unsupported_fields: Vec::new(),
    };

    // Unmapped sections check
    for unmapped in &[
        "signatures", "memory", "debug", "apistats", "virustotal", "strings", "curtain", "extracted",
    ] {
        if root.contains_key(*unmapped) || behavior.is_some_and(|b| b.contains_key(*unmapped)) {
            norm_report
                .unsupported_fields
                .push(format!("CAPE v2.2 schema section '{}' is unmapped in current normalized schema", unmapped));
        }
    }

    if let Some(beh) = behavior {
        if let Some(summary_obj) = beh.get("summary").and_then(|v| v.as_object()) {
            if summary_obj.contains_key("keys") {
                norm_report
                    .unsupported_fields
                    .push("CAPE v2.2 schema 'behavior.summary.keys' (registry) is unmapped".to_string());
            }
            if summary_obj.contains_key("mutexes") {
                norm_report
                    .unsupported_fields
                    .push("CAPE v2.2 schema 'behavior.summary.mutexes' is unmapped".to_string());
            }
        }
    }

    // 1. Limitations or warnings
    let raw_warnings = info
        .and_then(|i| i.get("errors_or_warnings"))
        .and_then(|v| v.as_array())
        .or_else(|| {
            root.get("debug")
                .and_then(|d| d.get("errors"))
                .and_then(|v| v.as_array())
        });

    if let Some(warnings) = raw_warnings {
        for (idx, warn) in warnings.iter().enumerate() {
            let warn_str = warn.as_str().unwrap_or(&warn.to_string()).to_string();
            norm_report.limitations.push(CollectionLimitation {
                report_id: report_id.to_string(),
                code: format!("CAPE_WARN_{}", idx),
                description: warn_str,
                category: "RUNTIME_WARNING".to_string(),
                target_pattern: None,
                evidence: None,
            });
        }
    }

    // 2. Processes
    let raw_processes = behavior
        .and_then(|b| b.get("processes"))
        .and_then(|v| v.as_array());

    if let Some(procs) = raw_processes {
        let mut pid_to_proc: HashMap<u32, &Value> = HashMap::new();
        for p in procs {
            if let Some(pid_val) = p.get("process_id") {
                let pid_u32 = pid_val.as_u64().map(|n| n as u32).or_else(|| {
                    pid_val.as_str().and_then(|s| s.parse::<u32>().ok())
                });
                if let Some(pid) = pid_u32 {
                    pid_to_proc.insert(pid, p);
                } else {
                    norm_report
                        .parser_warnings
                        .push(format!("Invalid non-integer process_id: {}", pid_val));
                }
            }
        }

        fn resolve_lineage(
            pid: u32,
            pid_to_proc: &HashMap<u32, &Value>,
            visited: &mut HashSet<u32>,
        ) -> Vec<String> {
            if visited.contains(&pid) || !pid_to_proc.contains_key(&pid) {
                return Vec::new();
            }
            visited.insert(pid);
            let proc = pid_to_proc[&pid];
            let parent_id = proc.get("parent_id").and_then(|v| {
                v.as_u64()
                    .map(|n| n as u32)
                    .or_else(|| v.as_str().and_then(|s| s.parse::<u32>().ok()))
            });

            let mut lineage = if let Some(ppid) = parent_id {
                resolve_lineage(ppid, pid_to_proc, visited)
            } else {
                Vec::new()
            };

            let name = proc
                .get("process_name")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();
            lineage.push(name);
            lineage
        }

        for (idx, proc) in procs.iter().enumerate() {
            let pid = proc
                .get("process_id")
                .and_then(|v| v.as_u64().map(|n| n as u32).or_else(|| v.as_str().and_then(|s| s.parse::<u32>().ok())))
                .unwrap_or(0);

            let ppid = proc.get("parent_id").and_then(|v| {
                v.as_u64()
                    .map(|n| n as u32)
                    .or_else(|| v.as_str().and_then(|s| s.parse::<u32>().ok()))
            });

            let name = proc
                .get("process_name")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();

            let cmd = proc
                .get("command_line")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            let mut visited = HashSet::new();
            let mut lineage = resolve_lineage(pid, &pid_to_proc, &mut visited);
            if lineage.is_empty() {
                lineage = vec![name.clone()];
            }

            let pointer_str = build_rfc6901_pointer(&[
                "behavior".to_string(),
                "processes".to_string(),
                idx.to_string(),
            ]);

            let cmd_preview = preview_str(&cmd, 60);

            let pointer = EvidencePointer::available(
                report_id,
                &pointer_str,
                &format!("PID {} ({}) created with cmd: {}", pid, name, cmd_preview),
                serde_json::json!({
                    "process_id": pid,
                    "parent_id": ppid,
                    "process_name": name,
                    "command_line": cmd,
                    "first_seen": proc.get("first_seen")
                }),
            );

            norm_report.processes.push(ProcessObservation {
                report_id: report_id.to_string(),
                source_pid: pid,
                source_ppid: ppid,
                image_name: name,
                command_line: cmd,
                lineage_path: lineage.clone(),
                tree_depth: lineage.len(),
                evidence: pointer,
            });
        }
    }

    // 3. Dropped Files
    let (raw_dropped, pointer_base) = if let Some(d) = root.get("dropped").and_then(|v| v.as_array()) {
        (Some(d), vec!["dropped".to_string()])
    } else if let Some(d) = behavior.and_then(|b| b.get("dropped")).and_then(|v| v.as_array()) {
        (Some(d), vec!["behavior".to_string(), "dropped".to_string()])
    } else {
        (None, vec!["behavior".to_string(), "dropped".to_string()])
    };

    if let Some(dropped_files) = raw_dropped {
        for (idx, df) in dropped_files.iter().enumerate() {
            let name = df
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("unnamed_artifact")
                .to_string();

            let path = df
                .get("guest_paths")
                .and_then(|gp| gp.as_array())
                .and_then(|arr| arr.first())
                .and_then(|p| p.as_str())
                .or_else(|| df.get("path").and_then(|p| p.as_str()))
                .unwrap_or("")
                .to_string();

            let raw_hash = df
                .get("sha256")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_ascii_lowercase()
                .trim()
                .to_string();

            let is_malformed = !is_valid_sha256(&raw_hash);
            if is_malformed {
                norm_report.parser_warnings.push(format!(
                    "Dropped file at index {} has malformed/missing SHA-256: '{}'",
                    idx, raw_hash
                ));
            }

            let size = df.get("size").and_then(|v| v.as_u64()).unwrap_or(0);
            let ftype = df
                .get("type")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            let mut token_path = pointer_base.clone();
            token_path.push(idx.to_string());
            let pointer_str = build_rfc6901_pointer(&token_path);

            let hash_preview = preview_str(&raw_hash, 12);

            let pointer = EvidencePointer::available(
                report_id,
                &pointer_str,
                &format!("Dropped file '{}' with SHA256 {}", name, hash_preview),
                serde_json::json!({
                    "name": name,
                    "path": path,
                    "sha256": raw_hash,
                    "size": size,
                    "type": ftype,
                    "dropped_by_pid": df.get("dropped_by_pid")
                }),
            );

            norm_report.dropped_files.push(DroppedFileObservation {
                report_id: report_id.to_string(),
                sha256: raw_hash,
                file_path: path,
                file_name: name,
                file_size: size,
                file_type: ftype,
                evidence: pointer,
                is_malformed_hash: is_malformed,
            });
        }
    }

    // 4. Network
    let (network, net_pointer_base) = if let Some(n) = root.get("network").and_then(|v| v.as_object()) {
        (Some(n), vec!["network".to_string()])
    } else if let Some(n) = behavior.and_then(|b| b.get("network")).and_then(|v| v.as_object()) {
        (Some(n), vec!["behavior".to_string(), "network".to_string()])
    } else {
        (None, vec!["behavior".to_string(), "network".to_string()])
    };

    if let Some(net) = network {
        // DNS
        if let Some(dns_list) = net.get("dns").and_then(|v| v.as_array()) {
            for (idx, dns) in dns_list.iter().enumerate() {
                let domain = dns
                    .get("domain")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let resolved = dns
                    .get("resolved_ip")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();

                let mut ptr_tokens = net_pointer_base.clone();
                ptr_tokens.push("dns".to_string());
                ptr_tokens.push(idx.to_string());
                let pointer_str = build_rfc6901_pointer(&ptr_tokens);

                let pointer = EvidencePointer::available(
                    report_id,
                    &pointer_str,
                    &format!("DNS query for '{}' resolved to '{}'", domain, resolved),
                    dns.clone(),
                );

                norm_report.network_events.push(NetworkObservation {
                    report_id: report_id.to_string(),
                    protocol: "DNS".to_string(),
                    destination: domain,
                    port: Some(53),
                    evidence: pointer,
                });
            }
        }

        // HTTP
        if let Some(http_list) = net.get("http").and_then(|v| v.as_array()) {
            for (idx, http) in http_list.iter().enumerate() {
                let url = http
                    .get("url")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let method = http
                    .get("method")
                    .and_then(|v| v.as_str())
                    .unwrap_or("GET")
                    .to_string();

                let port = if url.starts_with("http://") { 80 } else { 443 };

                let mut ptr_tokens = net_pointer_base.clone();
                ptr_tokens.push("http".to_string());
                ptr_tokens.push(idx.to_string());
                let pointer_str = build_rfc6901_pointer(&ptr_tokens);

                let pointer = EvidencePointer::available(
                    report_id,
                    &pointer_str,
                    &format!("HTTP {} request to '{}'", method, url),
                    http.clone(),
                );

                norm_report.network_events.push(NetworkObservation {
                    report_id: report_id.to_string(),
                    protocol: "HTTP".to_string(),
                    destination: url,
                    port: Some(port),
                    evidence: pointer,
                });
            }
        }

        // TCP
        if let Some(tcp_list) = net.get("tcp").and_then(|v| v.as_array()) {
            for (idx, tcp) in tcp_list.iter().enumerate() {
                let dst_ip = tcp
                    .get("dst_ip")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let dst_port = tcp
                    .get("dst_port")
                    .and_then(|v| v.as_u64().map(|n| n as u16).or_else(|| v.as_str().and_then(|s| s.parse::<u16>().ok())))
                    .unwrap_or(0);

                let mut ptr_tokens = net_pointer_base.clone();
                ptr_tokens.push("tcp".to_string());
                ptr_tokens.push(idx.to_string());
                let pointer_str = build_rfc6901_pointer(&ptr_tokens);

                let pointer = EvidencePointer::available(
                    report_id,
                    &pointer_str,
                    &format!("TCP stream to {}:{}", dst_ip, dst_port),
                    tcp.clone(),
                );

                norm_report.network_events.push(NetworkObservation {
                    report_id: report_id.to_string(),
                    protocol: "TCP".to_string(),
                    destination: dst_ip,
                    port: Some(dst_port),
                    evidence: pointer,
                });
            }
        }
    }

    norm_report
}

