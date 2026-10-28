"""
Data models for Evidence-Aware Sandbox Report Comparison (Milestone 3).
Disentangles observation presence, causal explanation, evidence pointers,
and epistemic interpretations into separate, non-collapsed dimensions.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class ObservationPresence(str, Enum):
    OBSERVED_IN_BOTH = "OBSERVED_IN_BOTH"
    OBSERVED_ONLY_IN_A = "OBSERVED_ONLY_IN_A"
    OBSERVED_ONLY_IN_B = "OBSERVED_ONLY_IN_B"
    NOT_OBSERVED_IN_EITHER = "NOT_OBSERVED_IN_EITHER"


class CausalExplanation(str, Enum):
    CORROBORATED_EXECUTION = "CORROBORATED_EXECUTION"              # Both reports observed; no omission to explain
    POLICY_DECISION_RECORDED = "POLICY_DECISION_RECORDED"          # Recorded firewall/hook rule intercepted traffic
    POTENTIAL_ENVIRONMENT_LIMITATION = "POTENTIAL_ENVIRONMENT_LIMITATION"  # Timeout/early exit may explain omission
    UNEXPLAINED = "UNEXPLAINED"                                    # No recorded limitation accounts for discrepancy


class ProcessMatchConfidence(str, Enum):
    MATCHED = "MATCHED"                 # High heuristic score (>= 0.80), clear separation from alternatives
    POSSIBLE_MATCH = "POSSIBLE_MATCH"   # Moderate heuristic score (0.50 <= s < 0.80) or competing candidates
    UNRESOLVED = "UNRESOLVED"           # Low heuristic score (< 0.50) or contradictory ancestry


@dataclass
class EvidencePointer:
    report_id: str
    json_pointer: str  # RFC 6901 JSON Pointer (e.g. '/behavior/dropped/0')
    event_summary: str
    raw_snippet: Dict[str, Any]
    is_available: bool = True
    missing_reason: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "report_id": self.report_id,
            "json_pointer": self.json_pointer,
            "event_summary": self.event_summary,
            "is_available": self.is_available,
            "missing_reason": self.missing_reason,
            "raw_snippet": self.raw_snippet
        }


@dataclass
class ProcessObservation:
    report_id: str
    source_pid: int
    source_ppid: Optional[int]
    image_name: str
    command_line: str
    lineage_path: List[str]
    tree_depth: int
    evidence: EvidencePointer

    @property
    def identity_signature(self) -> str:
        lineage_str = " -> ".join(self.lineage_path)
        norm_cmd = " ".join(self.command_line.strip().split())
        return f"{lineage_str} :: {norm_cmd}"


@dataclass
class DroppedFileObservation:
    report_id: str
    sha256: str
    file_path: str
    file_name: str
    file_size: int
    file_type: str
    evidence: EvidencePointer
    is_malformed_hash: bool = False


@dataclass
class NetworkObservation:
    report_id: str
    protocol: str
    destination: str
    port: Optional[int]
    evidence: EvidencePointer

    @property
    def connection_key(self) -> str:
        if self.port:
            return f"{self.protocol.upper()}://{self.destination}:{self.port}"
        return f"{self.protocol.upper()}://{self.destination}"


@dataclass
class CollectionLimitation:
    report_id: str
    code: str
    description: str
    category: str  # TIMEOUT, EGRESS_POLICY, ANTI_EVASION, CRASH
    target_pattern: Optional[str] = None
    evidence: Optional[EvidencePointer] = None


@dataclass
class NormalizedReport:
    report_id: str
    sandbox_name: str
    schema_format: str
    schema_provenance_type: str  # 'DOCUMENTED_VENDOR_FORMAT' or 'SYNTHETIC_APPROXIMATION'
    sample_sha256: str
    duration_seconds: Optional[int]
    processes: List[ProcessObservation] = field(default_factory=list)
    dropped_files: List[DroppedFileObservation] = field(default_factory=list)
    network_events: List[NetworkObservation] = field(default_factory=list)
    limitations: List[CollectionLimitation] = field(default_factory=list)
    parser_warnings: List[str] = field(default_factory=list)
    unsupported_fields: List[str] = field(default_factory=list)


@dataclass
class ReconciledFileItem:
    sha256: str
    observation_presence: ObservationPresence
    causal_explanation: CausalExplanation
    filenames_by_report: Dict[str, str]
    file_paths_by_report: Dict[str, str]
    evidence_links: Dict[str, EvidencePointer]
    epistemic_interpretation: str
    is_malformed_hash: bool = False


@dataclass
class ReconciledProcessItem:
    identity_signature: str
    image_name: str
    lineage_path: List[str]
    observation_presence: ObservationPresence
    confidence: ProcessMatchConfidence
    heuristic_similarity_score: float  # Explicitly labeled heuristic similarity, NOT probability
    matching_rationale: str
    causal_explanation: CausalExplanation
    epistemic_interpretation: str
    pids_by_report: Dict[str, int]
    commands_by_report: Dict[str, str]
    evidence_links: Dict[str, EvidencePointer]
    alternative_candidates: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class ReconciledNetworkItem:
    connection_key: str
    observation_presence: ObservationPresence
    observation_type: str                  # e.g. 'TELEMETRY_LOGGED_SOCKET_RECORD'
    connection_state: str                  # 'ATTEMPTED', 'ESTABLISHED', 'BLOCKED', 'SOCKET_RECORD_LOGGED', 'UNKNOWN'
    policy_decision: Optional[str]         # Explicit policy record or warning text
    cross_report_correlation: str          # 'DIRECT_IDENTIFIER_MATCH', 'CONTEXTUAL_SIMILARITY_ONLY', 'UNLINKED'
    causal_status: str                     # 'CONFIRMED', 'CORROBORATED_SOCKET', 'PLAUSIBLE_HYPOTHESIS', 'UNKNOWN'
    causal_explanation: CausalExplanation
    policy_decision_record: Optional[str]
    policy_decision_evidence: Optional[EvidencePointer]
    observed_in_reports: List[str]
    unobserved_in_reports: List[str]
    evidence_links: Dict[str, EvidencePointer]
    epistemic_interpretation: str


@dataclass
class ComparisonReport:
    sample_sha256: str
    report_a_id: str
    report_b_id: str
    reconciled_files: List[ReconciledFileItem]
    reconciled_processes: List[ReconciledProcessItem]
    reconciled_network: List[ReconciledNetworkItem]
    collection_limitations: Dict[str, List[CollectionLimitation]]
    epistemic_uncertainty_notes: List[str]
    provenance_metadata: Dict[str, Any] = field(default_factory=dict)
