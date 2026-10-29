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
        assert!(
            p.confidence == ProcessMatchConfidence::MATCHED
                || p.confidence == ProcessMatchConfidence::POSSIBLE_MATCH
        );
        assert_eq!(p.observation_presence, ObservationPresence::OBSERVED_IN_BOTH);
        assert!(p.heuristic_similarity_score >= 0.45);
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

#[test]
fn test_possible_match_causal_explanation_and_alternatives_exclusion_parity() {
    let ptr = EvidencePointer::available("rep", "/proc/0", "proc", serde_json::json!({}));

    let p_a0 = ProcessObservation {
        report_id: "rep_a".to_string(),
        source_pid: 100,
        source_ppid: Some(1),
        image_name: "cmd.exe".to_string(),
        command_line: "cmd.exe /c script.bat -v -d".to_string(),
        lineage_path: vec!["sample.exe".to_string(), "cmd.exe".to_string()],
        tree_depth: 1,
        evidence: ptr.clone(),
    };
    let p_a1 = ProcessObservation {
        report_id: "rep_a".to_string(),
        source_pid: 101,
        source_ppid: Some(1),
        image_name: "cmd.exe".to_string(),
        command_line: "cmd.exe /c script.bat -v".to_string(),
        lineage_path: vec!["sample.exe".to_string(), "cmd.exe".to_string()],
        tree_depth: 1,
        evidence: ptr.clone(),
    };

    let p_b0 = ProcessObservation {
        report_id: "rep_b".to_string(),
        source_pid: 200,
        source_ppid: Some(1),
        image_name: "cmd.exe".to_string(),
        command_line: "cmd.exe /c script.bat -v -d".to_string(),
        lineage_path: vec!["sample.exe".to_string(), "cmd.exe".to_string()],
        tree_depth: 1,
        evidence: ptr.clone(),
    };
    let p_b1 = ProcessObservation {
        report_id: "rep_b".to_string(),
        source_pid: 201,
        source_ppid: Some(1),
        image_name: "cmd.exe".to_string(),
        command_line: "cmd.exe /c script.bat -v -q".to_string(),
        lineage_path: vec!["sample.exe".to_string(), "cmd.exe".to_string()],
        tree_depth: 1,
        evidence: ptr,
    };

    let norm_a = NormalizedReport {
        report_id: "rep_a".to_string(),
        sandbox_name: "CAPE".to_string(),
        schema_format: "CAPE".to_string(),
        schema_provenance_type: "DOCUMENTED_VENDOR_FORMAT".to_string(),
        sample_sha256: "aaa".to_string(),
        duration_seconds: Some(60),
        processes: vec![p_a0, p_a1],
        dropped_files: Vec::new(),
        network_events: Vec::new(),
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
        processes: vec![p_b0, p_b1],
        dropped_files: Vec::new(),
        network_events: Vec::new(),
        limitations: Vec::new(),
        parser_warnings: Vec::new(),
        unsupported_fields: Vec::new(),
    };

    let comparator = EvidenceComparator::new(&norm_a, &norm_b);
    let comparison = comparator.reconcile();

    let possible_matches: Vec<_> = comparison
        .reconciled_processes
        .iter()
        .filter(|p| p.confidence == ProcessMatchConfidence::POSSIBLE_MATCH)
        .collect();

    assert!(!possible_matches.is_empty(), "Expected at least one POSSIBLE_MATCH");

    for proc in possible_matches {
        let pid_b = proc.pids_by_report.get("rep_b");
        assert_ne!(
            proc.causal_explanation,
            CausalExplanation::CORROBORATED_EXECUTION,
            "POSSIBLE_MATCH must not be assigned CORROBORATED_EXECUTION"
        );
        for alt in &proc.alternative_candidates {
            assert_ne!(
                Some(&alt.report_b_pid),
                pid_b,
                "Selected match PID {:?} appeared in its own alternative candidates!",
                pid_b
            );
        }
    }
}

#[test]
fn test_missing_and_malformed_hashes_never_paired_as_identical_parity() {
    let dummy_ptr = EvidencePointer {
        report_id: "test".to_string(),
        json_pointer: "/test".to_string(),
        event_summary: "test".to_string(),
        raw_snippet: serde_json::json!({}),
        is_available: true,
        missing_reason: None,
    };

    let f_a1 = DroppedFileObservation {
        report_id: "rep_a".to_string(),
        sha256: "".to_string(),
        file_path: "C:\\temp\\temp1.tmp".to_string(),
        file_name: "temp1.tmp".to_string(),
        file_size: 1024,
        file_type: "tmp".to_string(),
        evidence: dummy_ptr.clone(),
        is_malformed_hash: true,
    };
    let f_a2 = DroppedFileObservation {
        report_id: "rep_a".to_string(),
        sha256: "not_a_valid_sha256".to_string(),
        file_path: "C:\\bin\\tool.bin".to_string(),
        file_name: "tool.bin".to_string(),
        file_size: 2048,
        file_type: "bin".to_string(),
        evidence: dummy_ptr.clone(),
        is_malformed_hash: true,
    };

    let f_b1 = DroppedFileObservation {
        report_id: "rep_b".to_string(),
        sha256: "".to_string(),
        file_path: "C:\\desktop\\ransom.txt".to_string(),
        file_name: "ransom.txt".to_string(),
        file_size: 4096,
        file_type: "txt".to_string(),
        evidence: dummy_ptr.clone(),
        is_malformed_hash: true,
    };
    let f_b2 = DroppedFileObservation {
        report_id: "rep_b".to_string(),
        sha256: "different_invalid_hash".to_string(),
        file_path: "C:\\drivers\\driver.sys".to_string(),
        file_name: "driver.sys".to_string(),
        file_size: 8192,
        file_type: "sys".to_string(),
        evidence: dummy_ptr.clone(),
        is_malformed_hash: true,
    };

    let norm_a = NormalizedReport {
        report_id: "rep_a".to_string(),
        sandbox_name: "CAPE".to_string(),
        schema_format: "cape".to_string(),
        schema_provenance_type: "DOC".to_string(),
        sample_sha256: "h".to_string(),
        duration_seconds: Some(60),
        processes: Vec::new(),
        dropped_files: vec![f_a1, f_a2],
        network_events: Vec::new(),
        limitations: Vec::new(),
        parser_warnings: Vec::new(),
        unsupported_fields: Vec::new(),
    };
    let norm_b = NormalizedReport {
        report_id: "rep_b".to_string(),
        sandbox_name: "Falcon".to_string(),
        schema_format: "falcon".to_string(),
        schema_provenance_type: "DOC".to_string(),
        sample_sha256: "h".to_string(),
        duration_seconds: Some(60),
        processes: Vec::new(),
        dropped_files: vec![f_b1, f_b2],
        network_events: Vec::new(),
        limitations: Vec::new(),
        parser_warnings: Vec::new(),
        unsupported_fields: Vec::new(),
    };

    let res = EvidenceComparator::new(&norm_a, &norm_b).reconcile();

    for f in &res.reconciled_files {
        assert_ne!(f.observation_presence, ObservationPresence::OBSERVED_IN_BOTH);
        assert_ne!(f.causal_explanation, CausalExplanation::CORROBORATED_EXECUTION);
        assert!(f.is_malformed_hash);
    }

    let obs_a: Vec<_> = res.reconciled_files.iter().filter(|f| f.observation_presence == ObservationPresence::OBSERVED_ONLY_IN_A).collect();
    let obs_b: Vec<_> = res.reconciled_files.iter().filter(|f| f.observation_presence == ObservationPresence::OBSERVED_ONLY_IN_B).collect();
    assert_eq!(obs_a.len(), 2);
    assert_eq!(obs_b.len(), 2);
}

#[test]
fn test_unrelated_root_processes_with_empty_cli_do_not_match_parity() {
    let dummy_ptr = EvidencePointer {
        report_id: "test".to_string(),
        json_pointer: "/test".to_string(),
        event_summary: "test".to_string(),
        raw_snippet: serde_json::json!({}),
        is_available: true,
        missing_reason: None,
    };

    let p_a = ProcessObservation {
        report_id: "rep_a".to_string(),
        source_pid: 1001,
        source_ppid: None,
        image_name: "notepad.exe".to_string(),
        command_line: "".to_string(),
        lineage_path: vec!["notepad.exe".to_string()],
        tree_depth: 0,
        evidence: dummy_ptr.clone(),
    };
    let p_b = ProcessObservation {
        report_id: "rep_b".to_string(),
        source_pid: 2002,
        source_ppid: None,
        image_name: "calc.exe".to_string(),
        command_line: "".to_string(),
        lineage_path: vec!["calc.exe".to_string()],
        tree_depth: 0,
        evidence: dummy_ptr.clone(),
    };

    let norm_a = NormalizedReport {
        report_id: "rep_a".to_string(),
        sandbox_name: "CAPE".to_string(),
        schema_format: "cape".to_string(),
        schema_provenance_type: "DOC".to_string(),
        sample_sha256: "h".to_string(),
        duration_seconds: Some(60),
        processes: vec![p_a],
        dropped_files: Vec::new(),
        network_events: Vec::new(),
        limitations: Vec::new(),
        parser_warnings: Vec::new(),
        unsupported_fields: Vec::new(),
    };
    let norm_b = NormalizedReport {
        report_id: "rep_b".to_string(),
        sandbox_name: "Falcon".to_string(),
        schema_format: "falcon".to_string(),
        schema_provenance_type: "DOC".to_string(),
        sample_sha256: "h".to_string(),
        duration_seconds: Some(60),
        processes: vec![p_b],
        dropped_files: Vec::new(),
        network_events: Vec::new(),
        limitations: Vec::new(),
        parser_warnings: Vec::new(),
        unsupported_fields: Vec::new(),
    };

    let res = EvidenceComparator::new(&norm_a, &norm_b).reconcile();
    assert_eq!(res.reconciled_processes.len(), 2);
    for p in &res.reconciled_processes {
        assert_ne!(p.observation_presence, ObservationPresence::OBSERVED_IN_BOTH);
        assert_eq!(p.confidence, ProcessMatchConfidence::UNRESOLVED);
    }
}

#[test]
fn test_sample_hash_mismatch_parity() {
    let norm_a = NormalizedReport {
        report_id: "rep_a".to_string(),
        sandbox_name: "CAPE".to_string(),
        schema_format: "cape".to_string(),
        schema_provenance_type: "DOC".to_string(),
        sample_sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
        duration_seconds: Some(60),
        processes: Vec::new(),
        dropped_files: Vec::new(),
        network_events: Vec::new(),
        limitations: Vec::new(),
        parser_warnings: Vec::new(),
        unsupported_fields: Vec::new(),
    };
    let norm_b = NormalizedReport {
        report_id: "rep_b".to_string(),
        sandbox_name: "Falcon".to_string(),
        schema_format: "falcon".to_string(),
        schema_provenance_type: "DOC".to_string(),
        sample_sha256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
        duration_seconds: Some(60),
        processes: Vec::new(),
        dropped_files: Vec::new(),
        network_events: Vec::new(),
        limitations: Vec::new(),
        parser_warnings: Vec::new(),
        unsupported_fields: Vec::new(),
    };

    let res = EvidenceComparator::new(&norm_a, &norm_b).reconcile();
    assert!(res.sample_sha256.starts_with("CROSS_SAMPLE:"));
    let lims_a = res.collection_limitations.get("rep_a").unwrap();
    assert!(lims_a.iter().any(|l| l.code == "SAMPLE_HASH_MISMATCH"));
    assert!(res.epistemic_uncertainty_notes.iter().any(|n| n.contains("Cross-sample comparison")));
}

#[test]
fn test_missing_ancestry_does_not_trigger_disjoint_penalty_parity() {
    let dummy_ptr = EvidencePointer {
        report_id: "rep".to_string(),
        json_pointer: "/ptr".to_string(),
        event_summary: "sum".to_string(),
        is_available: true,
        missing_reason: None,
        raw_snippet: serde_json::json!({}),
    };
    let p_a = ProcessObservation {
        report_id: "rep_a".to_string(),
        source_pid: 100,
        source_ppid: Some(10),
        image_name: "calc.exe".to_string(),
        command_line: "calc.exe /test".to_string(),
        lineage_path: vec!["explorer.exe".to_string(), "calc.exe".to_string()],
        tree_depth: 2,
        evidence: dummy_ptr.clone(),
    };
    let p_b = ProcessObservation {
        report_id: "rep_b".to_string(),
        source_pid: 200,
        source_ppid: None,
        image_name: "calc.exe".to_string(),
        command_line: "calc.exe /test".to_string(),
        lineage_path: Vec::new(),
        tree_depth: 0,
        evidence: dummy_ptr.clone(),
    };

    let norm_a = NormalizedReport {
        report_id: "rep_a".to_string(),
        sandbox_name: "CAPE".to_string(),
        schema_format: "cape".to_string(),
        schema_provenance_type: "DOC".to_string(),
        sample_sha256: "h".to_string(),
        duration_seconds: Some(60),
        processes: vec![p_a],
        dropped_files: Vec::new(),
        network_events: Vec::new(),
        limitations: Vec::new(),
        parser_warnings: Vec::new(),
        unsupported_fields: Vec::new(),
    };
    let norm_b = NormalizedReport {
        report_id: "rep_b".to_string(),
        sandbox_name: "Falcon".to_string(),
        schema_format: "falcon".to_string(),
        schema_provenance_type: "DOC".to_string(),
        sample_sha256: "h".to_string(),
        duration_seconds: Some(60),
        processes: vec![p_b],
        dropped_files: Vec::new(),
        network_events: Vec::new(),
        limitations: Vec::new(),
        parser_warnings: Vec::new(),
        unsupported_fields: Vec::new(),
    };

    let res = EvidenceComparator::new(&norm_a, &norm_b).reconcile();
    assert_eq!(res.reconciled_processes.len(), 1);
    let p = &res.reconciled_processes[0];
    assert!(p.heuristic_similarity_score >= 0.70);
}

#[test]
fn test_singleton_and_repeated_network_honest_semantics_parity() {
    let dummy_ptr = EvidencePointer {
        report_id: "rep".to_string(),
        json_pointer: "/ptr".to_string(),
        event_summary: "sum".to_string(),
        is_available: true,
        missing_reason: None,
        raw_snippet: serde_json::json!({}),
    };

    // 1. Singleton without discriminators
    let n_a = NetworkObservation {
        report_id: "rep_a".to_string(),
        protocol: "TCP".to_string(),
        destination: "198.51.100.1".to_string(),
        port: Some(443),
        evidence: dummy_ptr.clone(),
    };
    let n_b = NetworkObservation {
        report_id: "rep_b".to_string(),
        protocol: "TCP".to_string(),
        destination: "198.51.100.1".to_string(),
        port: Some(443),
        evidence: dummy_ptr.clone(),
    };
    let norm_a = NormalizedReport {
        report_id: "rep_a".to_string(),
        sandbox_name: "CAPE".to_string(),
        schema_format: "cape".to_string(),
        schema_provenance_type: "DOC".to_string(),
        sample_sha256: "h".to_string(),
        duration_seconds: Some(60),
        processes: Vec::new(),
        dropped_files: Vec::new(),
        network_events: vec![n_a],
        limitations: Vec::new(),
        parser_warnings: Vec::new(),
        unsupported_fields: Vec::new(),
    };
    let norm_b = NormalizedReport {
        report_id: "rep_b".to_string(),
        sandbox_name: "Falcon".to_string(),
        schema_format: "falcon".to_string(),
        schema_provenance_type: "DOC".to_string(),
        sample_sha256: "h".to_string(),
        duration_seconds: Some(60),
        processes: Vec::new(),
        dropped_files: Vec::new(),
        network_events: vec![n_b],
        limitations: Vec::new(),
        parser_warnings: Vec::new(),
        unsupported_fields: Vec::new(),
    };

    let res = EvidenceComparator::new(&norm_a, &norm_b).reconcile();
    assert_eq!(res.reconciled_network.len(), 1);
    let item = &res.reconciled_network[0];
    assert_eq!(item.cross_report_correlation, "SINGLETON_ENDPOINT_OVERLAP");
    assert_eq!(item.causal_status, "ENDPOINT_MATCH");
    assert_eq!(item.causal_explanation, CausalExplanation::UNEXPLAINED);

    // 2. Repeated undifferentiated network events
    let n_a1 = NetworkObservation {
        report_id: "rep_a".to_string(),
        protocol: "TCP".to_string(),
        destination: "203.0.113.5".to_string(),
        port: Some(443),
        evidence: dummy_ptr.clone(),
    };
    let n_a2 = NetworkObservation {
        report_id: "rep_a".to_string(),
        protocol: "TCP".to_string(),
        destination: "203.0.113.5".to_string(),
        port: Some(443),
        evidence: dummy_ptr.clone(),
    };
    let n_b1 = NetworkObservation {
        report_id: "rep_b".to_string(),
        protocol: "TCP".to_string(),
        destination: "203.0.113.5".to_string(),
        port: Some(443),
        evidence: dummy_ptr.clone(),
    };
    let n_b2 = NetworkObservation {
        report_id: "rep_b".to_string(),
        protocol: "TCP".to_string(),
        destination: "203.0.113.5".to_string(),
        port: Some(443),
        evidence: dummy_ptr.clone(),
    };

    let norm_rep_a = NormalizedReport {
        report_id: "rep_a".to_string(),
        sandbox_name: "CAPE".to_string(),
        schema_format: "cape".to_string(),
        schema_provenance_type: "DOC".to_string(),
        sample_sha256: "h".to_string(),
        duration_seconds: Some(60),
        processes: Vec::new(),
        dropped_files: Vec::new(),
        network_events: vec![n_a1, n_a2],
        limitations: Vec::new(),
        parser_warnings: Vec::new(),
        unsupported_fields: Vec::new(),
    };
    let norm_rep_b = NormalizedReport {
        report_id: "rep_b".to_string(),
        sandbox_name: "Falcon".to_string(),
        schema_format: "falcon".to_string(),
        schema_provenance_type: "DOC".to_string(),
        sample_sha256: "h".to_string(),
        duration_seconds: Some(60),
        processes: Vec::new(),
        dropped_files: Vec::new(),
        network_events: vec![n_b1, n_b2],
        limitations: Vec::new(),
        parser_warnings: Vec::new(),
        unsupported_fields: Vec::new(),
    };

    let res_rep = EvidenceComparator::new(&norm_rep_a, &norm_rep_b).reconcile();
    assert_eq!(res_rep.reconciled_network.len(), 1);
    let cluster = &res_rep.reconciled_network[0];
    assert_eq!(cluster.cross_report_correlation, "AGGREGATE_ENDPOINT_CLUSTER");
    assert_eq!(cluster.causal_status, "AGGREGATE_ENDPOINT_CORROBORATION");
    assert_eq!(cluster.causal_explanation, CausalExplanation::UNEXPLAINED);
}

#[test]
fn test_competing_sibling_ambiguity_demotes_to_possible_match_parity() {
    let dummy_ptr = EvidencePointer {
        report_id: "rep".to_string(),
        json_pointer: "/ptr".to_string(),
        event_summary: "sum".to_string(),
        is_available: true,
        missing_reason: None,
        raw_snippet: serde_json::json!({}),
    };

    let p_a1 = ProcessObservation {
        report_id: "rep_a".to_string(),
        source_pid: 101,
        source_ppid: Some(10),
        image_name: "worker.exe".to_string(),
        command_line: "worker.exe --pool worker".to_string(),
        lineage_path: vec!["app.exe".to_string(), "worker.exe".to_string()],
        tree_depth: 2,
        evidence: dummy_ptr.clone(),
    };
    let p_a2 = ProcessObservation {
        report_id: "rep_a".to_string(),
        source_pid: 102,
        source_ppid: Some(10),
        image_name: "worker.exe".to_string(),
        command_line: "worker.exe --pool worker".to_string(),
        lineage_path: vec!["app.exe".to_string(), "worker.exe".to_string()],
        tree_depth: 2,
        evidence: dummy_ptr.clone(),
    };
    let p_b1 = ProcessObservation {
        report_id: "rep_b".to_string(),
        source_pid: 201,
        source_ppid: Some(20),
        image_name: "worker.exe".to_string(),
        command_line: "worker.exe --pool worker".to_string(),
        lineage_path: vec!["app.exe".to_string(), "worker.exe".to_string()],
        tree_depth: 2,
        evidence: dummy_ptr.clone(),
    };

    let norm_a = NormalizedReport {
        report_id: "rep_a".to_string(),
        sandbox_name: "CAPE".to_string(),
        schema_format: "cape".to_string(),
        schema_provenance_type: "DOC".to_string(),
        sample_sha256: "h".to_string(),
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
        sandbox_name: "Falcon".to_string(),
        schema_format: "falcon".to_string(),
        schema_provenance_type: "DOC".to_string(),
        sample_sha256: "h".to_string(),
        duration_seconds: Some(60),
        processes: vec![p_b1],
        dropped_files: Vec::new(),
        network_events: Vec::new(),
        limitations: Vec::new(),
        parser_warnings: Vec::new(),
        unsupported_fields: Vec::new(),
    };

    let res = EvidenceComparator::new(&norm_a, &norm_b).reconcile();
    let matched: Vec<_> = res.reconciled_processes.iter().filter(|p| p.observation_presence == ObservationPresence::OBSERVED_IN_BOTH).collect();
    assert_eq!(matched.len(), 1);
    assert_eq!(matched[0].confidence, ProcessMatchConfidence::POSSIBLE_MATCH);
}

#[test]
fn test_pid_reassignment_and_order_shuffle_stability_parity() {
    let dummy_ptr = EvidencePointer {
        report_id: "rep".to_string(),
        json_pointer: "/ptr".to_string(),
        event_summary: "sum".to_string(),
        is_available: true,
        missing_reason: None,
        raw_snippet: serde_json::json!({}),
    };

    // --- Run 1: Natural order, base PIDs ---
    let p_a1 = ProcessObservation {
        report_id: "rep_a".to_string(),
        source_pid: 1000,
        source_ppid: None,
        image_name: "launcher.exe".to_string(),
        command_line: "launcher.exe --start".to_string(),
        lineage_path: vec!["explorer.exe".to_string(), "launcher.exe".to_string()],
        tree_depth: 2,
        evidence: dummy_ptr.clone(),
    };
    let p_a2 = ProcessObservation {
        report_id: "rep_a".to_string(),
        source_pid: 1004,
        source_ppid: Some(1000),
        image_name: "cmd.exe".to_string(),
        command_line: "cmd.exe /c run.bat".to_string(),
        lineage_path: vec!["explorer.exe".to_string(), "launcher.exe".to_string(), "cmd.exe".to_string()],
        tree_depth: 3,
        evidence: dummy_ptr.clone(),
    };
    let p_a3 = ProcessObservation {
        report_id: "rep_a".to_string(),
        source_pid: 1008,
        source_ppid: Some(1004),
        image_name: "worker.exe".to_string(),
        command_line: "worker.exe --task run".to_string(),
        lineage_path: vec!["explorer.exe".to_string(), "launcher.exe".to_string(), "cmd.exe".to_string(), "worker.exe".to_string()],
        tree_depth: 4,
        evidence: dummy_ptr.clone(),
    };
    let p_a4 = ProcessObservation {
        report_id: "rep_a".to_string(),
        source_pid: 1012,
        source_ppid: Some(1004),
        image_name: "worker.exe".to_string(),
        command_line: "worker.exe --task run".to_string(),
        lineage_path: vec!["explorer.exe".to_string(), "launcher.exe".to_string(), "cmd.exe".to_string(), "worker.exe".to_string()],
        tree_depth: 4,
        evidence: dummy_ptr.clone(),
    };

    let p_b1 = ProcessObservation {
        report_id: "rep_b".to_string(),
        source_pid: 5000,
        source_ppid: None,
        image_name: "launcher.exe".to_string(),
        command_line: "launcher.exe --start".to_string(),
        lineage_path: vec!["explorer.exe".to_string(), "launcher.exe".to_string()],
        tree_depth: 2,
        evidence: dummy_ptr.clone(),
    };
    let p_b2 = ProcessObservation {
        report_id: "rep_b".to_string(),
        source_pid: 5004,
        source_ppid: Some(5000),
        image_name: "cmd.exe".to_string(),
        command_line: "cmd.exe /c run.bat".to_string(),
        lineage_path: vec!["explorer.exe".to_string(), "launcher.exe".to_string(), "cmd.exe".to_string()],
        tree_depth: 3,
        evidence: dummy_ptr.clone(),
    };
    let p_b3 = ProcessObservation {
        report_id: "rep_b".to_string(),
        source_pid: 5008,
        source_ppid: Some(5004),
        image_name: "worker.exe".to_string(),
        command_line: "worker.exe --task run".to_string(),
        lineage_path: vec!["explorer.exe".to_string(), "launcher.exe".to_string(), "cmd.exe".to_string(), "worker.exe".to_string()],
        tree_depth: 4,
        evidence: dummy_ptr.clone(),
    };

    let norm_a_r1 = NormalizedReport {
        report_id: "rep_a".to_string(),
        sandbox_name: "CAPE".to_string(),
        schema_format: "cape".to_string(),
        schema_provenance_type: "DOC".to_string(),
        sample_sha256: "hash".to_string(),
        duration_seconds: Some(60),
        processes: vec![p_a1, p_a2, p_a3, p_a4],
        dropped_files: Vec::new(),
        network_events: Vec::new(),
        limitations: Vec::new(),
        parser_warnings: Vec::new(),
        unsupported_fields: Vec::new(),
    };
    let norm_b_r1 = NormalizedReport {
        report_id: "rep_b".to_string(),
        sandbox_name: "Falcon".to_string(),
        schema_format: "falcon".to_string(),
        schema_provenance_type: "DOC".to_string(),
        sample_sha256: "hash".to_string(),
        duration_seconds: Some(60),
        processes: vec![p_b1, p_b2, p_b3],
        dropped_files: Vec::new(),
        network_events: Vec::new(),
        limitations: Vec::new(),
        parser_warnings: Vec::new(),
        unsupported_fields: Vec::new(),
    };

    let res_r1 = EvidenceComparator::new(&norm_a_r1, &norm_b_r1).reconcile();

    // --- Run 2: Completely reassigned PIDs & shuffled order ---
    let p_a1_r2 = ProcessObservation {
        report_id: "rep_a".to_string(),
        source_pid: 9901,
        source_ppid: None,
        image_name: "launcher.exe".to_string(),
        command_line: "launcher.exe --start".to_string(),
        lineage_path: vec!["explorer.exe".to_string(), "launcher.exe".to_string()],
        tree_depth: 2,
        evidence: dummy_ptr.clone(),
    };
    let p_a2_r2 = ProcessObservation {
        report_id: "rep_a".to_string(),
        source_pid: 9902,
        source_ppid: Some(9901),
        image_name: "cmd.exe".to_string(),
        command_line: "cmd.exe /c run.bat".to_string(),
        lineage_path: vec!["explorer.exe".to_string(), "launcher.exe".to_string(), "cmd.exe".to_string()],
        tree_depth: 3,
        evidence: dummy_ptr.clone(),
    };
    let p_a3_r2 = ProcessObservation {
        report_id: "rep_a".to_string(),
        source_pid: 9903,
        source_ppid: Some(9902),
        image_name: "worker.exe".to_string(),
        command_line: "worker.exe --task run".to_string(),
        lineage_path: vec!["explorer.exe".to_string(), "launcher.exe".to_string(), "cmd.exe".to_string(), "worker.exe".to_string()],
        tree_depth: 4,
        evidence: dummy_ptr.clone(),
    };
    let p_a4_r2 = ProcessObservation {
        report_id: "rep_a".to_string(),
        source_pid: 9904,
        source_ppid: Some(9902),
        image_name: "worker.exe".to_string(),
        command_line: "worker.exe --task run".to_string(),
        lineage_path: vec!["explorer.exe".to_string(), "launcher.exe".to_string(), "cmd.exe".to_string(), "worker.exe".to_string()],
        tree_depth: 4,
        evidence: dummy_ptr.clone(),
    };

    let p_b1_r2 = ProcessObservation {
        report_id: "rep_b".to_string(),
        source_pid: 7701,
        source_ppid: None,
        image_name: "launcher.exe".to_string(),
        command_line: "launcher.exe --start".to_string(),
        lineage_path: vec!["explorer.exe".to_string(), "launcher.exe".to_string()],
        tree_depth: 2,
        evidence: dummy_ptr.clone(),
    };
    let p_b2_r2 = ProcessObservation {
        report_id: "rep_b".to_string(),
        source_pid: 7702,
        source_ppid: Some(7701),
        image_name: "cmd.exe".to_string(),
        command_line: "cmd.exe /c run.bat".to_string(),
        lineage_path: vec!["explorer.exe".to_string(), "launcher.exe".to_string(), "cmd.exe".to_string()],
        tree_depth: 3,
        evidence: dummy_ptr.clone(),
    };
    let p_b3_r2 = ProcessObservation {
        report_id: "rep_b".to_string(),
        source_pid: 7703,
        source_ppid: Some(7702),
        image_name: "worker.exe".to_string(),
        command_line: "worker.exe --task run".to_string(),
        lineage_path: vec!["explorer.exe".to_string(), "launcher.exe".to_string(), "cmd.exe".to_string(), "worker.exe".to_string()],
        tree_depth: 4,
        evidence: dummy_ptr.clone(),
    };

    // Shuffled input order
    let norm_a_r2 = NormalizedReport {
        report_id: "rep_a".to_string(),
        sandbox_name: "CAPE".to_string(),
        schema_format: "cape".to_string(),
        schema_provenance_type: "DOC".to_string(),
        sample_sha256: "hash".to_string(),
        duration_seconds: Some(60),
        processes: vec![p_a3_r2, p_a1_r2, p_a4_r2, p_a2_r2],
        dropped_files: Vec::new(),
        network_events: Vec::new(),
        limitations: Vec::new(),
        parser_warnings: Vec::new(),
        unsupported_fields: Vec::new(),
    };
    let norm_b_r2 = NormalizedReport {
        report_id: "rep_b".to_string(),
        sandbox_name: "Falcon".to_string(),
        schema_format: "falcon".to_string(),
        schema_provenance_type: "DOC".to_string(),
        sample_sha256: "hash".to_string(),
        duration_seconds: Some(60),
        processes: vec![p_b2_r2, p_b3_r2, p_b1_r2],
        dropped_files: Vec::new(),
        network_events: Vec::new(),
        limitations: Vec::new(),
        parser_warnings: Vec::new(),
        unsupported_fields: Vec::new(),
    };

    let res_r2 = EvidenceComparator::new(&norm_a_r2, &norm_b_r2).reconcile();

    // Verify stability of anchors: launcher and cmd must be MATCHED in both
    for (res, _lbl) in [(&res_r1, "Run 1"), (&res_r2, "Run 2")] {
        let launcher = res.reconciled_processes.iter().find(|p| p.image_name == "launcher.exe" && p.observation_presence == ObservationPresence::OBSERVED_IN_BOTH).unwrap();
        assert_eq!(launcher.confidence, ProcessMatchConfidence::MATCHED);

        let cmd = res.reconciled_processes.iter().find(|p| p.image_name == "cmd.exe" && p.observation_presence == ObservationPresence::OBSERVED_IN_BOTH).unwrap();
        assert_eq!(cmd.confidence, ProcessMatchConfidence::MATCHED);

        // Ambiguous worker must remain POSSIBLE_MATCH
        let worker_matched = res.reconciled_processes.iter().find(|p| p.image_name == "worker.exe" && p.observation_presence == ObservationPresence::OBSERVED_IN_BOTH).unwrap();
        assert_eq!(worker_matched.confidence, ProcessMatchConfidence::POSSIBLE_MATCH);
        assert_eq!(worker_matched.causal_explanation, CausalExplanation::UNEXPLAINED);
    }
}

#[test]
fn test_network_conflicting_metadata_divergent_endpoint_attributes_parity() {
    let dummy_ptr_a = EvidencePointer::available("rep_a", "/net/0", "TCP", serde_json::json!({"sport": 50000}));
    let dummy_ptr_b = EvidencePointer::available("rep_b", "/net/0", "TCP", serde_json::json!({"sport": 50001}));

    let net_a = NetworkObservation {
        report_id: "rep_a".to_string(),
        protocol: "TCP".to_string(),
        destination: "198.51.100.25".to_string(),
        port: Some(443),
        evidence: dummy_ptr_a,
    };
    let net_b = NetworkObservation {
        report_id: "rep_b".to_string(),
        protocol: "TCP".to_string(),
        destination: "198.51.100.25".to_string(),
        port: Some(443),
        evidence: dummy_ptr_b,
    };

    let norm_a = NormalizedReport {
        report_id: "rep_a".to_string(),
        sandbox_name: "CAPE".to_string(),
        schema_format: "cape".to_string(),
        schema_provenance_type: "DOC".to_string(),
        sample_sha256: "hash1".to_string(),
        duration_seconds: Some(60),
        processes: Vec::new(),
        dropped_files: Vec::new(),
        network_events: vec![net_a],
        limitations: Vec::new(),
        parser_warnings: Vec::new(),
        unsupported_fields: Vec::new(),
    };
    let norm_b = NormalizedReport {
        report_id: "rep_b".to_string(),
        sandbox_name: "Falcon".to_string(),
        schema_format: "falcon".to_string(),
        schema_provenance_type: "DOC".to_string(),
        sample_sha256: "hash1".to_string(),
        duration_seconds: Some(60),
        processes: Vec::new(),
        dropped_files: Vec::new(),
        network_events: vec![net_b],
        limitations: Vec::new(),
        parser_warnings: Vec::new(),
        unsupported_fields: Vec::new(),
    };

    let res = EvidenceComparator::new(&norm_a, &norm_b).reconcile();
    assert_eq!(res.reconciled_network.len(), 1);
    let item = &res.reconciled_network[0];
    assert_eq!(item.observation_presence, ObservationPresence::OBSERVED_IN_BOTH);
    assert_eq!(item.cross_report_correlation, "DIVERGENT_ENDPOINT_ATTRIBUTES");
    assert_eq!(item.causal_status, "DIVERGENT_ENDPOINT_ATTRIBUTES");
    assert_eq!(item.causal_explanation, CausalExplanation::UNEXPLAINED);
    assert!(item.epistemic_interpretation.contains("conflicting attributes"));
}

#[test]
fn test_falcon_duplicate_pids_and_conflicting_parents_parity() {
    use sandbox_comparator::parsers::falcon::parse_falcon_report;

    let raw_falcon = serde_json::json!({
        "submission_info": {
            "analyzer": "Falcon Test",
            "schema": "falcon_hybrid_synthetic_v3",
            "sample_metadata": {"sha256": "a".repeat(64)}
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
                            "ppid": 9999,
                            "name": "child1.exe",
                            "cmdline": "child1.exe",
                            "children": []
                        },
                        {
                            "pid": 1000,
                            "ppid": 1000,
                            "name": "reused.exe",
                            "cmdline": "reused.exe",
                            "children": []
                        }
                    ]
                }
            ]
        }
    });

    let norm = parse_falcon_report(&raw_falcon, "falcon_test");
    assert!(
        norm.parser_warnings.iter().any(|w| w.contains("Duplicate PID 1000 detected in Falcon process tree")),
        "Expected duplicate PID warning, got: {:?}", norm.parser_warnings
    );
    assert!(
        norm.parser_warnings.iter().any(|w| w.contains("Process PID 2000 declared ppid=9999 but is nested under PID 1000")),
        "Expected conflicting PPID warning, got: {:?}", norm.parser_warnings
    );
}

#[test]
fn test_observation_accounting_invariants_parity() {
    let dummy_ptr = EvidencePointer::available("rep", "/ptr", "event", serde_json::json!({}));

    let p_a1 = ProcessObservation { report_id: "rep_a".to_string(), source_pid: 100, source_ppid: None, image_name: "proc1.exe".to_string(), command_line: "proc1.exe".to_string(), lineage_path: vec!["proc1.exe".to_string()], tree_depth: 1, evidence: dummy_ptr.clone() };
    let p_a2 = ProcessObservation { report_id: "rep_a".to_string(), source_pid: 200, source_ppid: Some(100), image_name: "proc2.exe".to_string(), command_line: "proc2.exe".to_string(), lineage_path: vec!["proc1.exe".to_string(), "proc2.exe".to_string()], tree_depth: 2, evidence: dummy_ptr.clone() };
    let p_a3 = ProcessObservation { report_id: "rep_a".to_string(), source_pid: 300, source_ppid: Some(100), image_name: "proc3.exe".to_string(), command_line: "proc3.exe".to_string(), lineage_path: vec!["proc1.exe".to_string(), "proc3.exe".to_string()], tree_depth: 2, evidence: dummy_ptr.clone() };

    let p_b1 = ProcessObservation { report_id: "rep_b".to_string(), source_pid: 500, source_ppid: None, image_name: "proc1.exe".to_string(), command_line: "proc1.exe".to_string(), lineage_path: vec!["proc1.exe".to_string()], tree_depth: 1, evidence: dummy_ptr.clone() };
    let p_b2 = ProcessObservation { report_id: "rep_b".to_string(), source_pid: 600, source_ppid: Some(500), image_name: "proc4.exe".to_string(), command_line: "proc4.exe".to_string(), lineage_path: vec!["proc1.exe".to_string(), "proc4.exe".to_string()], tree_depth: 2, evidence: dummy_ptr.clone() };

    let f_a1 = DroppedFileObservation { report_id: "rep_a".to_string(), sha256: "1".repeat(64), file_path: "C:\\f1.dll".to_string(), file_name: "f1.dll".to_string(), file_size: 100, file_type: "PE".to_string(), evidence: dummy_ptr.clone(), is_malformed_hash: false };
    let f_a2 = DroppedFileObservation { report_id: "rep_a".to_string(), sha256: "2".repeat(64), file_path: "C:\\f2.dll".to_string(), file_name: "f2.dll".to_string(), file_size: 200, file_type: "PE".to_string(), evidence: dummy_ptr.clone(), is_malformed_hash: false };
    let f_b1 = DroppedFileObservation { report_id: "rep_b".to_string(), sha256: "1".repeat(64), file_path: "C:\\f1.dll".to_string(), file_name: "f1.dll".to_string(), file_size: 100, file_type: "PE".to_string(), evidence: dummy_ptr.clone(), is_malformed_hash: false };

    let n_a1 = NetworkObservation { report_id: "rep_a".to_string(), protocol: "TCP".to_string(), destination: "1.1.1.1".to_string(), port: Some(80), evidence: dummy_ptr.clone() };
    let n_a2 = NetworkObservation { report_id: "rep_a".to_string(), protocol: "TCP".to_string(), destination: "2.2.2.2".to_string(), port: Some(443), evidence: dummy_ptr.clone() };
    let n_b1 = NetworkObservation { report_id: "rep_b".to_string(), protocol: "TCP".to_string(), destination: "1.1.1.1".to_string(), port: Some(80), evidence: dummy_ptr.clone() };

    let norm_a = NormalizedReport {
        report_id: "rep_a".to_string(),
        sandbox_name: "A".to_string(),
        schema_format: "cape".to_string(),
        schema_provenance_type: "DOC".to_string(),
        sample_sha256: "h".repeat(64),
        duration_seconds: Some(60),
        processes: vec![p_a1, p_a2, p_a3],
        dropped_files: vec![f_a1, f_a2],
        network_events: vec![n_a1, n_a2],
        limitations: Vec::new(),
        parser_warnings: Vec::new(),
        unsupported_fields: Vec::new(),
    };
    let norm_b = NormalizedReport {
        report_id: "rep_b".to_string(),
        sandbox_name: "B".to_string(),
        schema_format: "falcon".to_string(),
        schema_provenance_type: "DOC".to_string(),
        sample_sha256: "h".repeat(64),
        duration_seconds: Some(60),
        processes: vec![p_b1, p_b2],
        dropped_files: vec![f_b1],
        network_events: vec![n_b1],
        limitations: Vec::new(),
        parser_warnings: Vec::new(),
        unsupported_fields: Vec::new(),
    };

    let res = EvidenceComparator::new(&norm_a, &norm_b).reconcile();

    // Process accounting
    let matched_p = res.reconciled_processes.iter().filter(|p| p.observation_presence == ObservationPresence::OBSERVED_IN_BOTH).count();
    let only_a_p = res.reconciled_processes.iter().filter(|p| p.observation_presence == ObservationPresence::OBSERVED_ONLY_IN_A).count();
    let only_b_p = res.reconciled_processes.iter().filter(|p| p.observation_presence == ObservationPresence::OBSERVED_ONLY_IN_B).count();
    assert_eq!(matched_p + only_a_p, norm_a.processes.len(), "Process accounting violated for Report A");
    assert_eq!(matched_p + only_b_p, norm_b.processes.len(), "Process accounting violated for Report B");

    // File accounting
    let matched_f = res.reconciled_files.iter().filter(|f| f.observation_presence == ObservationPresence::OBSERVED_IN_BOTH).count();
    let only_a_f = res.reconciled_files.iter().filter(|f| f.observation_presence == ObservationPresence::OBSERVED_ONLY_IN_A).count();
    let only_b_f = res.reconciled_files.iter().filter(|f| f.observation_presence == ObservationPresence::OBSERVED_ONLY_IN_B).count();
    assert_eq!(matched_f + only_a_f, norm_a.dropped_files.len(), "File accounting violated for Report A");
    assert_eq!(matched_f + only_b_f, norm_b.dropped_files.len(), "File accounting violated for Report B");

    // Network accounting
    let matched_n = res.reconciled_network.iter().filter(|n| n.observation_presence == ObservationPresence::OBSERVED_IN_BOTH).count();
    let only_a_n = res.reconciled_network.iter().filter(|n| n.observation_presence == ObservationPresence::OBSERVED_ONLY_IN_A).count();
    let only_b_n = res.reconciled_network.iter().filter(|n| n.observation_presence == ObservationPresence::OBSERVED_ONLY_IN_B).count();
    assert_eq!(matched_n + only_a_n, norm_a.network_events.len(), "Network accounting violated for Report A");
    assert_eq!(matched_n + only_b_n, norm_b.network_events.len(), "Network accounting violated for Report B");
}
