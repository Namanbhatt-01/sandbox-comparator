use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObservationPresence {
    OBSERVED_IN_BOTH,
    OBSERVED_ONLY_IN_A,
    OBSERVED_ONLY_IN_B,
    NOT_OBSERVED_IN_EITHER,
}

impl ObservationPresence {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::OBSERVED_IN_BOTH => "OBSERVED_IN_BOTH",
            Self::OBSERVED_ONLY_IN_A => "OBSERVED_ONLY_IN_A",
            Self::OBSERVED_ONLY_IN_B => "OBSERVED_ONLY_IN_B",
            Self::NOT_OBSERVED_IN_EITHER => "NOT_OBSERVED_IN_EITHER",
        }
    }
}

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CausalExplanation {
    CORROBORATED_EXECUTION,
    POLICY_DECISION_RECORDED,
    POTENTIAL_ENVIRONMENT_LIMITATION,
    UNEXPLAINED,
}

impl CausalExplanation {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::CORROBORATED_EXECUTION => "CORROBORATED_EXECUTION",
            Self::POLICY_DECISION_RECORDED => "POLICY_DECISION_RECORDED",
            Self::POTENTIAL_ENVIRONMENT_LIMITATION => "POTENTIAL_ENVIRONMENT_LIMITATION",
            Self::UNEXPLAINED => "UNEXPLAINED",
        }
    }
}

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProcessMatchConfidence {
    MATCHED,
    POSSIBLE_MATCH,
    UNRESOLVED,
}

impl ProcessMatchConfidence {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::MATCHED => "MATCHED",
            Self::POSSIBLE_MATCH => "POSSIBLE_MATCH",
            Self::UNRESOLVED => "UNRESOLVED",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidencePointer {
    pub report_id: String,
    pub json_pointer: String,
    pub event_summary: String,
    pub raw_snippet: serde_json::Value,
    pub is_available: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub missing_reason: Option<String>,
}

impl EvidencePointer {
    pub fn available(report_id: &str, pointer: &str, summary: &str, snippet: serde_json::Value) -> Self {
        Self {
            report_id: report_id.to_string(),
            json_pointer: pointer.to_string(),
            event_summary: summary.to_string(),
            raw_snippet: snippet,
            is_available: true,
            missing_reason: None,
        }
    }

    pub fn missing(report_id: &str, summary: &str, reason: &str) -> Self {
        Self {
            report_id: report_id.to_string(),
            json_pointer: String::new(),
            event_summary: summary.to_string(),
            raw_snippet: serde_json::json!({}),
            is_available: false,
            missing_reason: Some(reason.to_string()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessObservation {
    pub report_id: String,
    pub source_pid: u32,
    pub source_ppid: Option<u32>,
    pub image_name: String,
    pub command_line: String,
    pub lineage_path: Vec<String>,
    pub tree_depth: usize,
    pub evidence: EvidencePointer,
}

impl ProcessObservation {
    pub fn identity_signature(&self) -> String {
        let lineage_str = self.lineage_path.join(" -> ");
        let norm_cmd = self.command_line.split_whitespace().collect::<Vec<_>>().join(" ");
        format!("{} :: {}", lineage_str, norm_cmd)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DroppedFileObservation {
    pub report_id: String,
    pub sha256: String,
    pub file_path: String,
    pub file_name: String,
    pub file_size: u64,
    pub file_type: String,
    pub evidence: EvidencePointer,
    pub is_malformed_hash: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkObservation {
    pub report_id: String,
    pub protocol: String,
    pub destination: String,
    pub port: Option<u16>,
    pub evidence: EvidencePointer,
}

impl NetworkObservation {
    pub fn connection_key(&self) -> String {
        if let Some(p) = self.port {
            format!("{}://{}:{}", self.protocol.to_uppercase(), self.destination, p)
        } else {
            format!("{}://{}", self.protocol.to_uppercase(), self.destination)
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectionLimitation {
    pub report_id: String,
    pub code: String,
    pub description: String,
    pub category: String, // TIMEOUT, EGRESS_POLICY, RUNTIME_WARNING, etc.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_pattern: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<EvidencePointer>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NormalizedReport {
    pub report_id: String,
    pub sandbox_name: String,
    pub schema_format: String,
    pub schema_provenance_type: String,
    pub sample_sha256: String,
    pub duration_seconds: Option<u64>,
    pub processes: Vec<ProcessObservation>,
    pub dropped_files: Vec<DroppedFileObservation>,
    pub network_events: Vec<NetworkObservation>,
    pub limitations: Vec<CollectionLimitation>,
    pub parser_warnings: Vec<String>,
    pub unsupported_fields: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconciledFileItem {
    pub sha256: String,
    pub observation_presence: ObservationPresence,
    pub causal_explanation: CausalExplanation,
    pub filenames_by_report: BTreeMap<String, String>,
    pub file_paths_by_report: BTreeMap<String, String>,
    pub evidence_links: BTreeMap<String, EvidencePointer>,
    pub epistemic_interpretation: String,
    pub is_malformed_hash: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessAlternativeCandidate {
    pub report_b_pid: u32,
    pub image: String,
    pub score: f64,
    pub rationale: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconciledProcessItem {
    pub identity_signature: String,
    pub image_name: String,
    pub lineage_path: Vec<String>,
    pub observation_presence: ObservationPresence,
    pub confidence: ProcessMatchConfidence,
    pub heuristic_similarity_score: f64,
    pub matching_rationale: String,
    pub causal_explanation: CausalExplanation,
    pub epistemic_interpretation: String,
    pub pids_by_report: BTreeMap<String, u32>,
    pub commands_by_report: BTreeMap<String, String>,
    pub evidence_links: BTreeMap<String, EvidencePointer>,
    pub alternative_candidates: Vec<ProcessAlternativeCandidate>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconciledNetworkItem {
    pub connection_key: String,
    pub observation_presence: ObservationPresence,
    pub observation_type: String,
    pub connection_state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_decision: Option<String>,
    pub cross_report_correlation: String,
    pub causal_status: String,
    pub causal_explanation: CausalExplanation,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_decision_record: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_decision_evidence: Option<EvidencePointer>,
    pub observed_in_reports: Vec<String>,
    pub unobserved_in_reports: Vec<String>,
    pub evidence_links: BTreeMap<String, EvidencePointer>,
    pub epistemic_interpretation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComparisonReport {
    pub sample_sha256: String,
    pub report_a_id: String,
    pub report_b_id: String,
    pub reconciled_files: Vec<ReconciledFileItem>,
    pub reconciled_processes: Vec<ReconciledProcessItem>,
    pub reconciled_network: Vec<ReconciledNetworkItem>,
    pub collection_limitations: BTreeMap<String, Vec<CollectionLimitation>>,
    pub epistemic_uncertainty_notes: Vec<String>,
    pub provenance_metadata: BTreeMap<String, serde_json::Value>,
}

