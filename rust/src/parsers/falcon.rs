use crate::models::{
    CollectionLimitation, DroppedFileObservation, EvidencePointer, NetworkObservation,
    NormalizedReport, ProcessObservation,
};
use crate::provenance::{build_rfc6901_pointer, preview_str};
use serde_json::Value;

fn is_valid_sha256(s: &str) -> bool {
    s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())
}

pub fn parse_falcon_report(raw: &Value, report_id: &str) -> NormalizedReport {
    let empty_obj = serde_json::Map::new();
    let root = raw.as_object().unwrap_or(&empty_obj);

    let sub_info = root.get("submission_info").and_then(|v| v.as_object());
    let sample_meta = sub_info.and_then(|s| s.get("sample_metadata")).and_then(|v| v.as_object());
    let execution = root.get("execution").and_then(|v| v.as_object());

    let sample_sha256 = sample_meta
        .and_then(|m| m.get("sha256"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_ascii_lowercase()
        .trim()
        .to_string();

    let duration_seconds = sub_info
        .and_then(|s| s.get("runtime_budget_seconds"))
        .and_then(|v| v.as_u64());

    let analyzer = sub_info
        .and_then(|s| s.get("analyzer"))
        .and_then(|v| v.as_str())
        .unwrap_or("Synthetic Falcon-like Sandbox (v7.x approximation)")
        .to_string();

    let schema_format = sub_info
        .and_then(|s| s.get("schema"))
        .and_then(|v| v.as_str())
        .unwrap_or("falcon_hybrid_synthetic_v3")
        .to_string();

    let mut norm_report = NormalizedReport {
        report_id: report_id.to_string(),
        sandbox_name: analyzer,
        schema_format,
        schema_provenance_type: "SYNTHETIC_APPROXIMATION".to_string(),
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
    for unmapped in &["signatures", "mitre_attacks", "registry_events", "memory_injections"] {
        if root.contains_key(*unmapped) || execution.map_or(false, |e| e.contains_key(*unmapped)) {
            norm_report.unsupported_fields.push(format!(
                "Falcon-like section '{}' is unmapped in current normalized schema",
                unmapped
            ));
        }
    }

    // 1. Limitations & System Warnings
    if let Some(warnings) = sub_info.and_then(|s| s.get("system_warnings")).and_then(|v| v.as_array()) {
        for (idx, warn) in warnings.iter().enumerate() {
            if let Some(w) = warn.as_object() {
                let code = w.get("code").and_then(|v| v.as_str()).unwrap_or("WARN_GENERIC").to_string();
                let desc = w.get("description").and_then(|v| v.as_str()).unwrap_or("").to_string();

                let category = if code.contains("TIMEOUT") {
                    "TIMEOUT".to_string()
                } else if code.contains("EGRESS") {
                    "EGRESS_POLICY".to_string()
                } else {
                    "ENVIRONMENT".to_string()
                };

                let mut target_pattern = None;
                if category == "EGRESS_POLICY" {
                    if desc.contains("8080") {
                        target_pattern = Some("port:8080".to_string());
                    }
                }

                let ptr_str = build_rfc6901_pointer(&[
                    "submission_info".to_string(),
                    "system_warnings".to_string(),
                    idx.to_string(),
                ]);

                let pointer = EvidencePointer::available(
                    report_id,
                    &ptr_str,
                    &format!("System warning [{}]: {}", code, desc),
                    warn.clone(),
                );

                norm_report.limitations.push(CollectionLimitation {
                    report_id: report_id.to_string(),
                    code,
                    description: desc,
                    category,
                    target_pattern,
                    evidence: Some(pointer),
                });
            }
        }
    }

    // 2. Hierarchical Process Tree
    fn traverse_node(
        node: &Value,
        parent_lineage: &[String],
        token_path: &[String],
        report_id: &str,
        norm_report: &mut NormalizedReport,
    ) {
        if let Some(obj) = node.as_object() {
            let pid = obj
                .get("pid")
                .and_then(|v| v.as_u64().map(|n| n as u32).or_else(|| v.as_str().and_then(|s| s.parse::<u32>().ok())))
                .unwrap_or(0);

            let ppid = obj.get("ppid").and_then(|v| {
                v.as_u64()
                    .map(|n| n as u32)
                    .or_else(|| v.as_str().and_then(|s| s.parse::<u32>().ok()))
            });

            let name = obj.get("name").and_then(|v| v.as_str()).unwrap_or("unknown").to_string();
            let cmd = obj.get("cmdline").and_then(|v| v.as_str()).unwrap_or("").to_string();

            let mut current_lineage = parent_lineage.to_vec();
            current_lineage.push(name.clone());

            let pointer_str = build_rfc6901_pointer(token_path);
            let cmd_preview = preview_str(&cmd, 60);

            let pointer = EvidencePointer::available(
                report_id,
                &pointer_str,
                &format!("PID {} ({}) created with cmd: {}", pid, name, cmd_preview),
                serde_json::json!({
                    "pid": pid,
                    "ppid": ppid,
                    "name": name,
                    "cmdline": cmd,
                    "integrity_level": obj.get("integrity_level")
                }),
            );

            norm_report.processes.push(ProcessObservation {
                report_id: report_id.to_string(),
                source_pid: pid,
                source_ppid: ppid,
                image_name: name,
                command_line: cmd,
                lineage_path: current_lineage.clone(),
                tree_depth: current_lineage.len(),
                evidence: pointer,
            });

            if let Some(children) = obj.get("children").and_then(|v| v.as_array()) {
                for (c_idx, child) in children.iter().enumerate() {
                    let mut child_path = token_path.to_vec();
                    child_path.push("children".to_string());
                    child_path.push(c_idx.to_string());
                    traverse_node(child, &current_lineage, &child_path, report_id, norm_report);
                }
            }
        }
    }

    if let Some(exec) = execution {
        if let Some(roots) = exec.get("process_tree").and_then(|v| v.as_array()) {
            for (r_idx, root_node) in roots.iter().enumerate() {
                let token_path = vec![
                    "execution".to_string(),
                    "process_tree".to_string(),
                    r_idx.to_string(),
                ];
                traverse_node(root_node, &[], &token_path, report_id, &mut norm_report);
            }
        }

        // 3. Created Files
        if let Some(created) = exec.get("created_files").and_then(|v| v.as_array()) {
            for (idx, cf) in created.iter().enumerate() {
                if let Some(obj) = cf.as_object() {
                    let fname = obj
                        .get("filename")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unnamed_artifact")
                        .to_string();

                    let base_name = fname
                        .replace('\\', "/")
                        .rsplit('/')
                        .next()
                        .unwrap_or(&fname)
                        .to_string();

                    let raw_hash = obj
                        .get("sha256_hash")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_ascii_lowercase()
                        .trim()
                        .to_string();

                    let is_malformed = !is_valid_sha256(&raw_hash);
                    if is_malformed {
                        norm_report.parser_warnings.push(format!(
                            "Created file at index {} has malformed/missing SHA-256: '{}'",
                            idx, raw_hash
                        ));
                    }

                    let size = obj.get("file_bytes").and_then(|v| v.as_u64()).unwrap_or(0);
                    let magic = obj.get("magic").and_then(|v| v.as_str()).unwrap_or("").to_string();

                    let pointer_str = build_rfc6901_pointer(&[
                        "execution".to_string(),
                        "created_files".to_string(),
                        idx.to_string(),
                    ]);

                    let hash_preview = preview_str(&raw_hash, 12);

                    let pointer = EvidencePointer::available(
                        report_id,
                        &pointer_str,
                        &format!("Created file '{}' with SHA256 {}", base_name, hash_preview),
                        serde_json::json!({
                            "filename": fname,
                            "sha256_hash": raw_hash,
                            "file_bytes": size,
                            "magic": magic,
                            "origin_pid": obj.get("origin_pid")
                        }),
                    );

                    norm_report.dropped_files.push(DroppedFileObservation {
                        report_id: report_id.to_string(),
                        sha256: raw_hash,
                        file_path: fname,
                        file_name: base_name,
                        file_size: size,
                        file_type: magic,
                        evidence: pointer,
                        is_malformed_hash: is_malformed,
                    });
                }
            }
        }

        // 4. Network Traffic
        if let Some(net) = exec.get("network_traffic").and_then(|v| v.as_object()) {
            // DNS
            if let Some(dns_list) = net.get("dns_requests").and_then(|v| v.as_array()) {
                for (idx, dns) in dns_list.iter().enumerate() {
                    let host = dns.get("hostname").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    let resolved = dns
                        .get("ip_addresses")
                        .and_then(|v| v.as_array())
                        .and_then(|arr| arr.first())
                        .and_then(|s| s.as_str())
                        .unwrap_or("")
                        .to_string();

                    let pointer_str = build_rfc6901_pointer(&[
                        "execution".to_string(),
                        "network_traffic".to_string(),
                        "dns_requests".to_string(),
                        idx.to_string(),
                    ]);

                    let pointer = EvidencePointer::available(
                        report_id,
                        &pointer_str,
                        &format!("DNS query for '{}' (resolved: {})", host, resolved),
                        dns.clone(),
                    );

                    norm_report.network_events.push(NetworkObservation {
                        report_id: report_id.to_string(),
                        protocol: "DNS".to_string(),
                        destination: host,
                        port: Some(53),
                        evidence: pointer,
                    });
                }
            }

            // HTTP
            if let Some(http_list) = net.get("http_transactions").and_then(|v| v.as_array()) {
                for (idx, http) in http_list.iter().enumerate() {
                    let uri = http.get("uri").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    let method = http.get("method").and_then(|v| v.as_str()).unwrap_or("GET").to_string();
                    let port = if uri.starts_with("http://") { 80 } else { 443 };

                    let pointer_str = build_rfc6901_pointer(&[
                        "execution".to_string(),
                        "network_traffic".to_string(),
                        "http_transactions".to_string(),
                        idx.to_string(),
                    ]);

                    let pointer = EvidencePointer::available(
                        report_id,
                        &pointer_str,
                        &format!("HTTP {} to '{}'", method, uri),
                        http.clone(),
                    );

                    norm_report.network_events.push(NetworkObservation {
                        report_id: report_id.to_string(),
                        protocol: "HTTP".to_string(),
                        destination: uri,
                        port: Some(port),
                        evidence: pointer,
                    });
                }
            }

            // TCP
            if let Some(tcp_list) = net.get("active_tcp_streams").and_then(|v| v.as_array()) {
                for (idx, tcp) in tcp_list.iter().enumerate() {
                    let dip = tcp.get("destination_ip").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    let dport = tcp
                        .get("destination_port")
                        .and_then(|v| v.as_u64().map(|n| n as u16).or_else(|| v.as_str().and_then(|s| s.parse::<u16>().ok())))
                        .unwrap_or(0);

                    let pointer_str = build_rfc6901_pointer(&[
                        "execution".to_string(),
                        "network_traffic".to_string(),
                        "active_tcp_streams".to_string(),
                        idx.to_string(),
                    ]);

                    let pointer = EvidencePointer::available(
                        report_id,
                        &pointer_str,
                        &format!("Active TCP connection to {}:{}", dip, dport),
                        tcp.clone(),
                    );

                    norm_report.network_events.push(NetworkObservation {
                        report_id: report_id.to_string(),
                        protocol: "TCP".to_string(),
                        destination: dip,
                        port: Some(dport),
                        evidence: pointer,
                    });
                }
            }
        }
    }

    norm_report
}

