use sandbox_comparator::models::*;
use sandbox_comparator::parsers::parse_auto_report;
use sandbox_comparator::provenance::{build_rfc6901_pointer, escape_rfc6901_token, resolve_json_pointer};
use sandbox_comparator::reconciler::EvidenceComparator;
use std::fs;
use std::path::Path;

fn find_file(relative: &str) -> String {
    let p = Path::new(relative);
    if p.exists() {
        return relative.to_string();
    }
    let parent = Path::new("..").join(relative);
    if parent.exists() {
        return parent.to_str().unwrap().to_string();
    }
    relative.to_string()
}

#[test]
fn test_scenario_y_cross_schema_parity() {
    let path_a = find_file("data/report_format_a_cape.json");
    let path_b = find_file("data/report_format_b_falcon.json");

    let raw_a: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&path_a).expect("read cape")).expect("parse json a");
    let raw_b: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&path_b).expect("read falcon")).expect("parse json b");

    let norm_a = parse_auto_report(&raw_a, "cape_report");
    let norm_b = parse_auto_report(&raw_b, "falcon_report");

    let comparator = EvidenceComparator::new(&norm_a, &norm_b);
    let comparison = comparator.reconcile();

    // 1. Target SHA-256
    assert_eq!(
        comparison.sample_sha256,
        "7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069"
    );

    // 2. Reconciled Files
    assert_eq!(comparison.reconciled_files.len(), 3);

    let corroborated_file = comparison
        .reconciled_files
        .iter()
        .find(|f| f.observation_presence == ObservationPresence::OBSERVED_IN_BOTH)
        .expect("corroborated file missing");
    assert_eq!(corroborated_file.causal_explanation, CausalExplanation::CORROBORATED_EXECUTION);
    assert_eq!(
        corroborated_file.filenames_by_report.get("cape_report").map(|s| s.as_str()),
        Some("update_payload.exe")
    );
    assert_eq!(
        corroborated_file.filenames_by_report.get("falcon_report").map(|s| s.as_str()),
        Some("staged_runner.bin")
    );

    let file_only_a = comparison
        .reconciled_files
        .iter()
        .find(|f| f.observation_presence == ObservationPresence::OBSERVED_ONLY_IN_A)
        .expect("file only in A missing");
    assert_eq!(file_only_a.causal_explanation, CausalExplanation::POTENTIAL_ENVIRONMENT_LIMITATION);

    let file_only_b = comparison
        .reconciled_files
        .iter()
        .find(|f| f.observation_presence == ObservationPresence::OBSERVED_ONLY_IN_B)
        .expect("file only in B missing");
    assert_eq!(file_only_b.causal_explanation, CausalExplanation::UNEXPLAINED);

    // 3. Reconciled Processes
    assert_eq!(comparison.reconciled_processes.len(), 4);
    for p in &comparison.reconciled_processes {
        assert_eq!(p.confidence, ProcessMatchConfidence::MATCHED);
        assert_eq!(p.observation_presence, ObservationPresence::OBSERVED_IN_BOTH);
        assert!(p.heuristic_similarity_score >= 0.80);
    }

    let p0 = &comparison.reconciled_processes[0];
    assert_eq!(p0.image_name, "invoice_oct2026.exe");
    assert_eq!(*p0.pids_by_report.get("cape_report").unwrap(), 2488);
    assert_eq!(*p0.pids_by_report.get("falcon_report").unwrap(), 7112);

    // 4. Reconciled Network
    assert_eq!(comparison.reconciled_network.len(), 4);
    let net_8080 = comparison
        .reconciled_network
        .iter()
        .find(|n| n.connection_key == "TCP://203.0.113.88:8080")
        .expect("port 8080 missing");
    assert_eq!(net_8080.observation_presence, ObservationPresence::OBSERVED_ONLY_IN_A);
    assert_eq!(net_8080.causal_status, "PLAUSIBLE_HYPOTHESIS");
    assert_eq!(net_8080.causal_explanation, CausalExplanation::POLICY_DECISION_RECORDED);
    assert_eq!(net_8080.connection_state, "UNKNOWN");
    assert!(net_8080.policy_decision_record.as_ref().unwrap().contains("WARN_EGRESS_POLICY"));

    // 5. Limitations
    let lims_b = comparison.collection_limitations.get("falcon_report").unwrap();
    assert_eq!(lims_b.len(), 2);
    assert!(lims_b.iter().any(|l| l.code == "WARN_TIMEOUT"));
    assert!(lims_b.iter().any(|l| l.code == "WARN_EGRESS_POLICY"));
}

#[test]
fn test_scenario_x_real_sanitized_cape_ingestion() {
    let path_a = find_file("data/report_format_a_cape.json");
    let path_b = find_file("data/real_sanitized_cape_v2_export.json");

    let raw_a: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&path_a).expect("read cape a")).expect("parse json a");
    let raw_b: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&path_b).expect("read cape b")).expect("parse json b");

    let norm_a = parse_auto_report(&raw_a, "cape_fixture");
    let norm_b = parse_auto_report(&raw_b, "sanitized_cape_v2");

    assert_eq!(norm_b.sandbox_name, "CAPE Sandbox 2.2-CAPE");
    assert_eq!(norm_b.schema_format, "cape_v2_native_2.2-CAPE");
    assert_eq!(norm_b.duration_seconds, Some(123));
    assert_eq!(norm_b.schema_provenance_type, "DOCUMENTED_VENDOR_FORMAT");
    assert_eq!(norm_b.processes.len(), 4);
    assert!(!norm_b.dropped_files.is_empty());
    assert!(!norm_b.network_events.is_empty());

    let comparator = EvidenceComparator::new(&norm_a, &norm_b);
    let comparison = comparator.reconcile();
    assert!(!comparison.reconciled_processes.is_empty());
}

#[test]
fn test_rfc6901_provenance_resolution() {
    let doc = serde_json::json!({
        "behavior": {
            "processes": [
                {
                    "pid": 100,
                    "name": "malware.exe"
                }
            ],
            "dropped": [
                {
                    "name": "payload.bin",
                    "sha256": "abcdef"
                }
            ]
        }
    });

    let val = resolve_json_pointer(&doc, "/behavior/processes/0/name").expect("resolve proc name");
    assert_eq!(val.as_str().unwrap(), "malware.exe");

    let val_dropped = resolve_json_pointer(&doc, "/behavior/dropped/0/sha256").expect("resolve dropped");
    assert_eq!(val_dropped.as_str().unwrap(), "abcdef");

    let constructed = build_rfc6901_pointer(&[
        "behavior".to_string(),
        "dropped".to_string(),
        "0".to_string(),
        "name".to_string(),
    ]);
    assert_eq!(constructed, "/behavior/dropped/0/name");
    assert_eq!(escape_rfc6901_token("foo/bar~baz"), "foo~1bar~0baz");
}

#[test]
fn test_engine_hardening_hash_deduplication() {
    let dummy_pointer = EvidencePointer::available("rep_a", "/test/0", "dummy", serde_json::json!({}));

    // Two observations with identical SHA-256 but different paths/names
    let file1 = DroppedFileObservation {
        report_id: "rep_a".to_string(),
        sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
        file_path: "C:\\Windows\\Temp\\marker1.tmp".to_string(),
        file_name: "marker1.tmp".to_string(),
        file_size: 0,
        file_type: "empty".to_string(),
        evidence: dummy_pointer.clone(),
        is_malformed_hash: false,
    };
    let file2 = DroppedFileObservation {
        report_id: "rep_a".to_string(),
        sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
        file_path: "C:\\Users\\Public\\marker2.tmp".to_string(),
        file_name: "marker2.tmp".to_string(),
        file_size: 0,
        file_type: "empty".to_string(),
        evidence: dummy_pointer.clone(),
        is_malformed_hash: false,
    };

    let norm_a = NormalizedReport {
        report_id: "rep_a".to_string(),
        sandbox_name: "Sandbox A".to_string(),
        schema_format: "test".to_string(),
        schema_provenance_type: "TEST".to_string(),
        sample_sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
        duration_seconds: Some(30),
        processes: Vec::new(),
        dropped_files: vec![file1, file2],
        network_events: Vec::new(),
        limitations: Vec::new(),
        parser_warnings: Vec::new(),
        unsupported_fields: Vec::new(),
    };

    let norm_b = NormalizedReport {
        report_id: "rep_b".to_string(),
        sandbox_name: "Sandbox B".to_string(),
        schema_format: "test".to_string(),
        schema_provenance_type: "TEST".to_string(),
        sample_sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
        duration_seconds: Some(30),
        processes: Vec::new(),
        dropped_files: Vec::new(),
        network_events: Vec::new(),
        limitations: Vec::new(),
        parser_warnings: Vec::new(),
        unsupported_fields: Vec::new(),
    };

    let comparator = EvidenceComparator::new(&norm_a, &norm_b);
    let comparison = comparator.reconcile();

    // Verify BOTH file observations are preserved, neither is overwritten!
    assert_eq!(comparison.reconciled_files.len(), 2);
    let names: Vec<_> = comparison
        .reconciled_files
        .iter()
        .map(|f| f.filenames_by_report.get("rep_a").unwrap().as_str())
        .collect();
    assert!(names.contains(&"marker1.tmp"));
    assert!(names.contains(&"marker2.tmp"));
}

#[test]
fn test_greedy_score_sorted_matching_anchor_preservation_parity() {
    let dummy_pointer = EvidencePointer {
        report_id: "rep".to_string(),
        json_pointer: "/dummy".to_string(),
        event_summary: "dummy".to_string(),
        is_available: true,
        missing_reason: None,
        raw_snippet: serde_json::json!({}),
    };

    let p_a1 = ProcessObservation {
        report_id: "rep_a".to_string(),
        source_pid: 101,
        source_ppid: Some(1),
        image_name: "powershell.exe".to_string(),
        command_line: "powershell.exe -enc AAA -NoProfile".to_string(),
        lineage_path: vec!["explorer.exe".to_string()],
        tree_depth: 2,
        evidence: dummy_pointer.clone(),
    };
    let p_a2 = ProcessObservation {
        report_id: "rep_a".to_string(),
        source_pid: 102,
        source_ppid: Some(1),
        image_name: "powershell.exe".to_string(),
        command_line: "powershell.exe -enc AAA -WindowStyle Hidden".to_string(),
        lineage_path: vec!["explorer.exe".to_string()],
        tree_depth: 2,
        evidence: dummy_pointer.clone(),
    };

    let p_b1 = ProcessObservation {
        report_id: "rep_b".to_string(),
        source_pid: 201,
        source_ppid: Some(1),
        image_name: "powershell.exe".to_string(),
        command_line: "powershell.exe -enc AAA -NoProfile".to_string(),
        lineage_path: vec!["explorer.exe".to_string()],
        tree_depth: 2,
        evidence: dummy_pointer.clone(),
    };
    let p_b2 = ProcessObservation {
        report_id: "rep_b".to_string(),
        source_pid: 202,
        source_ppid: Some(1),
        image_name: "powershell.exe".to_string(),
        command_line: "powershell.exe -NoProfile".to_string(),
        lineage_path: vec!["explorer.exe".to_string()],
        tree_depth: 2,
        evidence: dummy_pointer.clone(),
    };

    let norm_a = NormalizedReport {
        report_id: "rep_a".to_string(),
        sandbox_name: "CAPE".to_string(),
        schema_format: "CAPE".to_string(),
        schema_provenance_type: "DOCUMENTED_VENDOR_FORMAT".to_string(),
        sample_sha256: "aaa".to_string(),
        duration_seconds: Some(60),
        processes: vec![p_a1, p_a2],
        dropped_files: Vec::new(),
        network_events: Vec::new(),
        limitations: Vec::new(),
        parser_warnings: Vec::new(),
        unsupported_fields: Vec::new(),
    };
    let norm_b = NormalizedReport {
        report_id: "rep_b".to_string(),
        sandbox_name: "CAPE".to_string(),
        schema_format: "CAPE".to_string(),
        schema_provenance_type: "DOCUMENTED_VENDOR_FORMAT".to_string(),
        sample_sha256: "aaa".to_string(),
        duration_seconds: Some(60),
        processes: vec![p_b1, p_b2],
        dropped_files: Vec::new(),
        network_events: Vec::new(),
        limitations: Vec::new(),
        parser_warnings: Vec::new(),
        unsupported_fields: Vec::new(),
    };

    let comparator = EvidenceComparator::new(&norm_a, &norm_b);
    let comparison = comparator.reconcile();

    // Find match for A1 (PID 101)
    let match_a1 = comparison
        .reconciled_processes
        .iter()
        .find(|p| p.pids_by_report.get("rep_a") == Some(&101))
        .expect("A1 present");
    let match_a2 = comparison
        .reconciled_processes
        .iter()
        .find(|p| p.pids_by_report.get("rep_a") == Some(&102))
        .expect("A2 present");

    // A1 is matched to B1 (201) and NOT displaced to B2 (202)
    assert_eq!(match_a1.pids_by_report.get("rep_b"), Some(&201));
    assert_eq!(match_a1.confidence, ProcessMatchConfidence::MATCHED);

    // A2 is UNRESOLVED because B1 was greedily consumed by anchor A1
    assert_eq!(match_a2.pids_by_report.get("rep_b"), None);
    assert_eq!(match_a2.confidence, ProcessMatchConfidence::UNRESOLVED);
}

#[test]
fn test_network_repeated_events_attribute_alignment_not_blind_position_parity() {
    let ptr_a1 = EvidencePointer::available(
        "rep_a",
        "/network/tcp/0",
        "Stream 1",
        serde_json::json!({"sport": 51001, "time": 10.0, "pid": 111}),
    );
    let ptr_a2 = EvidencePointer::available(
        "rep_a",
        "/network/tcp/1",
        "Stream 2",
        serde_json::json!({"sport": 51002, "time": 20.0, "pid": 222}),
    );

    // In Report B, order is reversed
    let ptr_b1 = EvidencePointer::available(
        "rep_b",
        "/network/tcp/0",
        "Stream 2",
        serde_json::json!({"sport": 51002, "time": 20.0, "pid": 222}),
    );
    let ptr_b2 = EvidencePointer::available(
        "rep_b",
        "/network/tcp/1",
        "Stream 1",
        serde_json::json!({"sport": 51001, "time": 10.0, "pid": 111}),
    );

    let net_a1 = NetworkObservation {
        report_id: "rep_a".to_string(),
        protocol: "TCP".to_string(),
        destination: "203.0.113.50".to_string(),
        port: Some(443),
        evidence: ptr_a1,
    };
    let net_a2 = NetworkObservation {
        report_id: "rep_a".to_string(),
        protocol: "TCP".to_string(),
        destination: "203.0.113.50".to_string(),
        port: Some(443),
        evidence: ptr_a2,
    };

    let net_b1 = NetworkObservation {
        report_id: "rep_b".to_string(),
        protocol: "TCP".to_string(),
        destination: "203.0.113.50".to_string(),
        port: Some(443),
        evidence: ptr_b1,
    };
    let net_b2 = NetworkObservation {
        report_id: "rep_b".to_string(),
        protocol: "TCP".to_string(),
        destination: "203.0.113.50".to_string(),
        port: Some(443),
        evidence: ptr_b2,
    };

    let norm_a = NormalizedReport {
        report_id: "rep_a".to_string(),
        sandbox_name: "CAPE".to_string(),
        schema_format: "CAPE".to_string(),
        schema_provenance_type: "DOCUMENTED_VENDOR_FORMAT".to_string(),
        sample_sha256: "aaa".to_string(),
        duration_seconds: Some(60),
        processes: Vec::new(),
        dropped_files: Vec::new(),
        network_events: vec![net_a1, net_a2],
        limitations: Vec::new(),
        parser_warnings: Vec::new(),
        unsupported_fields: Vec::new(),
    };
    let norm_b = NormalizedReport {
        report_id: "rep_b".to_string(),
        sandbox_name: "Falcon".to_string(),
        schema_format: "Falcon".to_string(),
        schema_provenance_type: "DOCUMENTED_VENDOR_FORMAT".to_string(),
        sample_sha256: "aaa".to_string(),
        duration_seconds: Some(60),
        processes: Vec::new(),
        dropped_files: Vec::new(),
        network_events: vec![net_b1, net_b2],
        limitations: Vec::new(),
        parser_warnings: Vec::new(),
        unsupported_fields: Vec::new(),
    };

    let comparator = EvidenceComparator::new(&norm_a, &norm_b);
    let comparison = comparator.reconcile();

    assert_eq!(comparison.reconciled_network.len(), 2);
    for item in &comparison.reconciled_network {
        assert_eq!(item.observation_presence, ObservationPresence::OBSERVED_IN_BOTH);
        let ptr_a = item.evidence_links.get("rep_a").expect("rep_a link");
        let ptr_b = item.evidence_links.get("rep_b").expect("rep_b link");
        let sport_a = ptr_a.raw_snippet.get("sport").and_then(|v| v.as_i64());
        let sport_b = ptr_b.raw_snippet.get("sport").and_then(|v| v.as_i64());
        assert_eq!(
            sport_a,
            sport_b,
            "Paired network events must have matching source ports: {:?} vs {:?}",
            sport_a,
            sport_b
        );
    }
}
