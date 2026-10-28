"""
Reconciliation and Diff Engine for Sandbox Telemetry (Milestone 3 Disentangled).
Enforces:
1. Disentangled dimensions: Observation Presence vs Causal Explanation vs Epistemic Interpretation.
2. Calibrated Heuristic Process Matching with LOLBin argument gating and ancestry penalties.
3. Cryptographic hash-based file matching with malformed hash handling.
4. Strict RFC 6901 JSON Pointer provenance linking.
"""

import re
from typing import Dict, List, Optional, Set, Tuple
from .models import (
    CausalExplanation,
    ComparisonReport,
    DroppedFileObservation,
    EvidencePointer,
    NetworkObservation,
    NormalizedReport,
    ObservationPresence,
    ProcessMatchConfidence,
    ProcessObservation,
    ReconciledFileItem,
    ReconciledNetworkItem,
    ReconciledProcessItem,
)


def tokenize_cmdline(cmd: str) -> Set[str]:
    """Tokenize commandline arguments, ignoring paths and casing."""
    raw_tokens = re.split(r'[\s"\'=,;]+', cmd.lower())
    clean_tokens = set()
    for t in raw_tokens:
        if not t:
            continue
        if "\\" in t or "/" in t:
            t = t.replace("\\", "/").split("/")[-1]
        clean_tokens.add(t)
    return clean_tokens


def get_arg_tokens(img_name: str, cmdline: str) -> Set[str]:
    """Extract argument tokens excluding the binary image name itself."""
    tokens = tokenize_cmdline(cmdline)
    base = img_name.lower().replace(".exe", "")
    return {t for t in tokens if t != img_name.lower() and t != base}


class EvidenceComparator:
    def __init__(self, report_a: NormalizedReport, report_b: NormalizedReport):
        self.report_a = report_a
        self.report_b = report_b

    def reconcile(self) -> ComparisonReport:
        reconciled_files = self._reconcile_files()
        reconciled_processes = self._reconcile_processes()
        reconciled_network = self._reconcile_network()

        notes = [
            "Epistemic Principle: Telemetry absence does NOT confirm behavioral non-occurrence.",
            f"Report A ({self.report_a.sandbox_name}) duration: {self.report_a.duration_seconds}s. Provenance: {self.report_a.schema_provenance_type}.",
            f"Report B ({self.report_b.sandbox_name}) duration: {self.report_b.duration_seconds}s. Provenance: {self.report_b.schema_provenance_type}.",
            "All process match scores are heuristic similarity metrics, NOT calibrated confidence probabilities.",
            "All evidence addresses formatted as RFC 6901 JSON Pointers (/path/to/token).",
        ]
        for lim in self.report_b.limitations:
            notes.append(f"Report B Limitation [{lim.code}] ({lim.category}): {lim.description}")
        for lim in self.report_a.limitations:
            notes.append(f"Report A Limitation [{lim.code}] ({lim.category}): {lim.description}")

        return ComparisonReport(
            sample_sha256=self.report_a.sample_sha256 or self.report_b.sample_sha256,
            report_a_id=self.report_a.report_id,
            report_b_id=self.report_b.report_id,
            reconciled_files=reconciled_files,
            reconciled_processes=reconciled_processes,
            reconciled_network=reconciled_network,
            collection_limitations={
                self.report_a.report_id: self.report_a.limitations,
                self.report_b.report_id: self.report_b.limitations,
            },
            epistemic_uncertainty_notes=notes,
            provenance_metadata={
                self.report_a.report_id: {
                    "sandbox": self.report_a.sandbox_name,
                    "schema": self.report_a.schema_format,
                    "provenance_type": self.report_a.schema_provenance_type,
                    "parser_warnings": self.report_a.parser_warnings
                },
                self.report_b.report_id: {
                    "sandbox": self.report_b.sandbox_name,
                    "schema": self.report_b.schema_format,
                    "provenance_type": self.report_b.schema_provenance_type,
                    "parser_warnings": self.report_b.parser_warnings
                }
            }
        )

    def _reconcile_files(self) -> List[ReconciledFileItem]:
        results: List[ReconciledFileItem] = []
        files_a: Dict[str, DroppedFileObservation] = {f.sha256: f for f in self.report_a.dropped_files}
        files_b: Dict[str, DroppedFileObservation] = {f.sha256: f for f in self.report_b.dropped_files}

        all_hashes = sorted(list(set(files_a.keys()) | set(files_b.keys())))

        for h in all_hashes:
            fa = files_a.get(h)
            fb = files_b.get(h)

            filenames: Dict[str, str] = {}
            filepaths: Dict[str, str] = {}
            evidence_links: Dict[str, EvidencePointer] = {}
            is_malformed = (fa.is_malformed_hash if fa else False) or (fb.is_malformed_hash if fb else False)

            if fa and fb:
                obs_presence = ObservationPresence.OBSERVED_IN_BOTH
                causal = CausalExplanation.CORROBORATED_EXECUTION
                filenames[self.report_a.report_id] = fa.file_name
                filenames[self.report_b.report_id] = fb.file_name
                filepaths[self.report_a.report_id] = fa.file_path
                filepaths[self.report_b.report_id] = fb.file_path
                evidence_links[self.report_a.report_id] = fa.evidence
                evidence_links[self.report_b.report_id] = fb.evidence

                if fa.file_name != fb.file_name:
                    interpretation = (
                        f"Matched by SHA-256 hash across naming discrepancies. "
                        f"Report A recorded '{fa.file_name}'; Report B recorded '{fb.file_name}'."
                    )
                else:
                    interpretation = f"Corroborated by SHA-256 hash and identical filename '{fa.file_name}'."

            elif fa and not fb:
                obs_presence = ObservationPresence.OBSERVED_ONLY_IN_A
                causal = self._evaluate_file_causality(self.report_b)
                filenames[self.report_a.report_id] = fa.file_name
                filepaths[self.report_a.report_id] = fa.file_path
                evidence_links[self.report_a.report_id] = fa.evidence
                evidence_links[self.report_b.report_id] = EvidencePointer(
                    report_id=self.report_b.report_id,
                    json_pointer="",
                    event_summary=f"SHA-256 {h[:12]}... unrecorded in Report B",
                    raw_snippet={},
                    is_available=False,
                    missing_reason=f"File hash {h} not found in {self.report_b.report_id} created_files telemetry"
                )
                interpretation = (
                    f"Observed only in Report A ('{fa.file_name}'). "
                    f"Report B telemetry does not record this file; this does not establish non-occurrence."
                )

            else:
                assert fb is not None
                obs_presence = ObservationPresence.OBSERVED_ONLY_IN_B
                causal = self._evaluate_file_causality(self.report_a)
                filenames[self.report_b.report_id] = fb.file_name
                filepaths[self.report_b.report_id] = fb.file_path
                evidence_links[self.report_b.report_id] = fb.evidence
                evidence_links[self.report_a.report_id] = EvidencePointer(
                    report_id=self.report_a.report_id,
                    json_pointer="",
                    event_summary=f"SHA-256 {h[:12]}... unrecorded in Report A",
                    raw_snippet={},
                    is_available=False,
                    missing_reason=f"File hash {h} not found in {self.report_a.report_id} dropped telemetry"
                )
                interpretation = (
                    f"Observed only in Report B ('{fb.file_name}'). "
                    f"Report A telemetry does not record this file; this does not establish non-occurrence."
                )

            results.append(
                ReconciledFileItem(
                    sha256=h,
                    observation_presence=obs_presence,
                    causal_explanation=causal,
                    filenames_by_report=filenames,
                    file_paths_by_report=filepaths,
                    evidence_links=evidence_links,
                    epistemic_interpretation=interpretation,
                    is_malformed_hash=is_malformed
                )
            )

        return results

    def _score_process_pair(self, p_a: ProcessObservation, p_b: ProcessObservation) -> Tuple[float, str]:
        """
        Calibrated heuristic similarity scorer (0.0 to 1.0).
        Incorporate LOLBin argument gating and disjoint ancestry penalties.
        """
        img_a = p_a.image_name.lower()
        img_b = p_b.image_name.lower()
        args_a = get_arg_tokens(img_a, p_a.command_line)
        args_b = get_arg_tokens(img_b, p_b.command_line)

        lolbins = {"powershell.exe", "cmd.exe", "svchost.exe", "rundll32.exe", "mshta.exe", "cscript.exe", "wscript.exe", "regsvr32.exe"}
        is_lolbin = (img_a in lolbins or img_b in lolbins)

        # Ancestry similarity (Jaccard)
        anc_a = set(s.lower() for s in p_a.lineage_path[:-1])
        anc_b = set(s.lower() for s in p_b.lineage_path[:-1])
        if anc_a or anc_b:
            anc_union = anc_a | anc_b
            anc_intersect = anc_a & anc_b
            anc_sim = len(anc_intersect) / len(anc_union) if anc_union else 0.0
        else:
            anc_sim = 1.0  # Both root processes

        # Argument similarity (Jaccard)
        if args_a and args_b:
            arg_intersect = args_a & args_b
            arg_union = args_a | args_b
            arg_jaccard = len(arg_intersect) / len(arg_union) if arg_union else 0.0
        elif not args_a and not args_b:
            arg_jaccard = 1.0
        else:
            arg_jaccard = 0.0

        # Disjoint ancestry penalty (e.g. explorer.exe vs excel.exe parentage)
        if (anc_a or anc_b) and anc_sim == 0.0:
            return 0.15, f"Disjoint ancestry tree: {anc_a} vs {anc_b}"

        # LOLBin divergent arguments penalty
        if is_lolbin and (args_a or args_b) and arg_jaccard < 0.20:
            return 0.25, f"LOLBin ({img_a}) with divergent commandline arguments (Jaccard {arg_jaccard:.2f})"

        score = 0.0
        reasons = []

        if img_a == img_b:
            score += 0.35
            reasons.append(f"Image match ('{p_a.image_name}')")
        elif len(p_a.lineage_path) >= 2 and len(p_b.lineage_path) >= 2:
            if "powershell" in p_a.lineage_path[-2].lower() and "powershell" in p_b.lineage_path[-2].lower():
                score += 0.30
                reasons.append("Spawned payload role under powershell.exe")

        score += 0.35 * arg_jaccard
        if arg_jaccard > 0.3:
            reasons.append(f"Argument Jaccard ({arg_jaccard:.2f})")

        score += 0.20 * anc_sim
        if anc_sim > 0.3:
            reasons.append(f"Ancestry lineage overlap ({anc_sim:.2f})")

        depth_delta = abs(p_a.tree_depth - p_b.tree_depth)
        if depth_delta == 0:
            score += 0.10
            reasons.append("Identical tree depth")
        elif depth_delta == 1:
            score += 0.05
            reasons.append("Adjacent tree depth (delta=1)")

        final_score = min(round(score, 3), 1.0)
        return final_score, "; ".join(reasons)

    def _reconcile_processes(self) -> List[ReconciledProcessItem]:
        results: List[ReconciledProcessItem] = []
        procs_a = self.report_a.processes
        procs_b = self.report_b.processes

        matched_b_indices: Set[int] = set()

        for p_a in procs_a:
            candidates: List[Tuple[int, float, str]] = []
            for idx_b, p_b in enumerate(procs_b):
                if idx_b in matched_b_indices:
                    continue
                score, rationale = self._score_process_pair(p_a, p_b)
                if score >= 0.45:
                    candidates.append((idx_b, score, rationale))

            candidates.sort(key=lambda x: x[1], reverse=True)

            evidence_links: Dict[str, EvidencePointer] = {self.report_a.report_id: p_a.evidence}
            pids: Dict[str, int] = {self.report_a.report_id: p_a.source_pid}
            commands: Dict[str, str] = {self.report_a.report_id: p_a.command_line}
            alternatives: List[Dict[str, Any]] = []

            if candidates:
                best_idx_b, best_score, best_rationale = candidates[0]
                is_ambiguous = False

                if len(candidates) > 1 and (best_score - candidates[1][1]) < 0.15:
                    is_ambiguous = True
                    for c_idx, c_score, c_rat in candidates[1:]:
                        alternatives.append({
                            "report_b_pid": procs_b[c_idx].source_pid,
                            "image": procs_b[c_idx].image_name,
                            "score": c_score,
                            "rationale": c_rat
                        })

                if best_score >= 0.80 and not is_ambiguous:
                    confidence = ProcessMatchConfidence.MATCHED
                    matched_b_indices.add(best_idx_b)
                    p_b = procs_b[best_idx_b]
                    evidence_links[self.report_b.report_id] = p_b.evidence
                    pids[self.report_b.report_id] = p_b.source_pid
                    commands[self.report_b.report_id] = p_b.command_line
                    obs_presence = ObservationPresence.OBSERVED_IN_BOTH
                    causal = CausalExplanation.CORROBORATED_EXECUTION
                    interpretation = f"Corroborated across runs (PID A={p_a.source_pid}, PID B={p_b.source_pid})."
                else:
                    confidence = ProcessMatchConfidence.POSSIBLE_MATCH
                    matched_b_indices.add(best_idx_b)
                    p_b = procs_b[best_idx_b]
                    evidence_links[self.report_b.report_id] = p_b.evidence
                    pids[self.report_b.report_id] = p_b.source_pid
                    commands[self.report_b.report_id] = p_b.command_line
                    obs_presence = ObservationPresence.OBSERVED_IN_BOTH
                    causal = CausalExplanation.CORROBORATED_EXECUTION
                    interpretation = "Plausible candidate alignment with potential ambiguity across candidate nodes."
            else:
                confidence = ProcessMatchConfidence.UNRESOLVED
                obs_presence = ObservationPresence.OBSERVED_ONLY_IN_A
                causal = self._evaluate_file_causality(self.report_b)
                evidence_links[self.report_b.report_id] = EvidencePointer(
                    report_id=self.report_b.report_id,
                    json_pointer="",
                    event_summary=f"Process '{p_a.image_name}' unrecorded in Report B",
                    raw_snippet={},
                    is_available=False,
                    missing_reason=f"No matching execution node in {self.report_b.report_id}"
                )
                best_score = 0.0
                best_rationale = "No plausible process candidate identified"
                interpretation = f"Observed only in Report A. Report B does not establish whether '{p_a.image_name}' executed."

            results.append(
                ReconciledProcessItem(
                    identity_signature=p_a.identity_signature,
                    image_name=p_a.image_name,
                    lineage_path=p_a.lineage_path,
                    observation_presence=obs_presence,
                    confidence=confidence,
                    heuristic_similarity_score=best_score,
                    matching_rationale=best_rationale,
                    causal_explanation=causal,
                    epistemic_interpretation=interpretation,
                    pids_by_report=pids,
                    commands_by_report=commands,
                    evidence_links=evidence_links,
                    alternative_candidates=alternatives
                )
            )

        # Handle leftover processes in Report B
        for idx_b, p_b in enumerate(procs_b):
            if idx_b in matched_b_indices:
                continue
            causal = self._evaluate_file_causality(self.report_a)
            evidence_links = {
                self.report_b.report_id: p_b.evidence,
                self.report_a.report_id: EvidencePointer(
                    report_id=self.report_a.report_id,
                    json_pointer="",
                    event_summary=f"Process '{p_b.image_name}' unrecorded in Report A",
                    raw_snippet={},
                    is_available=False,
                    missing_reason=f"No matching execution node in Report A"
                )
            }
            results.append(
                ReconciledProcessItem(
                    identity_signature=p_b.identity_signature,
                    image_name=p_b.image_name,
                    lineage_path=p_b.lineage_path,
                    observation_presence=ObservationPresence.OBSERVED_ONLY_IN_B,
                    confidence=ProcessMatchConfidence.UNRESOLVED,
                    heuristic_similarity_score=0.0,
                    matching_rationale="Unpaired execution node in Report B",
                    causal_explanation=causal,
                    epistemic_interpretation=f"Observed only in Report B (PID {p_b.source_pid}).",
                    pids_by_report={self.report_b.report_id: p_b.source_pid},
                    commands_by_report={self.report_b.report_id: p_b.command_line},
                    evidence_links=evidence_links
                )
            )

        return results

    def _reconcile_network(self) -> List[ReconciledNetworkItem]:
        results: List[ReconciledNetworkItem] = []
        net_a: Dict[str, NetworkObservation] = {n.connection_key: n for n in self.report_a.network_events}
        net_b: Dict[str, NetworkObservation] = {n.connection_key: n for n in self.report_b.network_events}

        all_keys = sorted(list(set(net_a.keys()) | set(net_b.keys())))

        for key in all_keys:
            na = net_a.get(key)
            nb = net_b.get(key)

            evidence_links: Dict[str, EvidencePointer] = {}
            observed_in: List[str] = []
            unobserved_in: List[str] = []
            policy_rec: Optional[str] = None
            policy_ptr: Optional[EvidencePointer] = None
            cross_corr = "UNLINKED"
            causal_stat = "UNKNOWN"
            conn_state = "UNKNOWN"

            if na and nb:
                obs_presence = ObservationPresence.OBSERVED_IN_BOTH
                causal = CausalExplanation.CORROBORATED_EXECUTION
                cross_corr = "DIRECT_IDENTIFIER_MATCH"
                causal_stat = "CONFIRMED"
                conn_state = "ESTABLISHED"
                observed_in.extend([self.report_a.report_id, self.report_b.report_id])
                evidence_links[self.report_a.report_id] = na.evidence
                evidence_links[self.report_b.report_id] = nb.evidence
                interpretation = f"Socket observation '{key}' corroborated across both reports."

            elif na and not nb:
                obs_presence = ObservationPresence.OBSERVED_ONLY_IN_A
                observed_in.append(self.report_a.report_id)
                unobserved_in.append(self.report_b.report_id)
                evidence_links[self.report_a.report_id] = na.evidence

                causal, policy_rec, policy_ptr, interpretation, cross_corr, causal_stat, conn_state = (
                    self._evaluate_network_causality(na, self.report_b)
                )

                evidence_links[self.report_b.report_id] = EvidencePointer(
                    report_id=self.report_b.report_id,
                    json_pointer="",
                    event_summary=f"Connection {key} unrecorded in Report B",
                    raw_snippet={},
                    is_available=False,
                    missing_reason=policy_rec or interpretation
                )

            else:
                assert nb is not None
                obs_presence = ObservationPresence.OBSERVED_ONLY_IN_B
                observed_in.append(self.report_b.report_id)
                unobserved_in.append(self.report_a.report_id)
                evidence_links[self.report_b.report_id] = nb.evidence

                causal, policy_rec, policy_ptr, interpretation, cross_corr, causal_stat, conn_state = (
                    self._evaluate_network_causality(nb, self.report_a)
                )

                evidence_links[self.report_a.report_id] = EvidencePointer(
                    report_id=self.report_a.report_id,
                    json_pointer="",
                    event_summary=f"Connection {key} unrecorded in Report A",
                    raw_snippet={},
                    is_available=False,
                    missing_reason=policy_rec or interpretation
                )

            results.append(
                ReconciledNetworkItem(
                    connection_key=key,
                    observation_presence=obs_presence,
                    observation_type="TELEMETRY_LOGGED_SOCKET_RECORD",
                    connection_state=conn_state,
                    policy_decision=policy_rec,
                    cross_report_correlation=cross_corr,
                    causal_status=causal_stat,
                    causal_explanation=causal,
                    policy_decision_record=policy_rec,
                    policy_decision_evidence=policy_ptr,
                    observed_in_reports=observed_in,
                    unobserved_in_reports=unobserved_in,
                    evidence_links=evidence_links,
                    epistemic_interpretation=interpretation
                )
            )

        return results

    def _evaluate_network_causality(
        self, event: NetworkObservation, target_report: NormalizedReport
    ) -> Tuple[CausalExplanation, Optional[str], Optional[EvidencePointer], str, str, str, str]:
        """
        Disentangles:
        - Observation type: Telemetry logged socket record.
        - Connection state: Attempted, Blocked, Established, or Unknown.
        - Policy decision: Explicit policy text.
        - Cross-report correlation: Direct identifier vs Contextual similarity only vs Unlinked.
        - Causal status: Confirmed vs Plausible hypothesis vs Unknown.
        """
        # Targeted policy match
        for lim in target_report.limitations:
            if lim.category == "EGRESS_POLICY" and lim.target_pattern and event.port:
                if f"port:{event.port}" in lim.target_pattern or str(event.port) in lim.description:
                    policy_text = f"{target_report.sandbox_name} [{lim.code}]: {lim.description}"
                    interpretation = (
                        f"TCP observation present in Report A; {target_report.sandbox_name} contains a general egress-policy "
                        f"warning mentioning port {event.port}; relationship between the records is not established."
                    )
                    return (
                        CausalExplanation.POLICY_DECISION_RECORDED,
                        policy_text,
                        lim.evidence,
                        interpretation,
                        "CONTEXTUAL_SIMILARITY_ONLY",
                        "PLAUSIBLE_HYPOTHESIS",
                        "UNKNOWN"  # Telemetry logs destination port, but does not record whether TCP handshake completed
                    )

        # General timeout match
        for lim in target_report.limitations:
            if lim.category == "TIMEOUT":
                interpretation = (
                    f"TCP observation present in source report; absent from {target_report.sandbox_name} which timed out at "
                    f"{target_report.duration_seconds}s. Relationship between timeout and omission is plausible but not confirmed."
                )
                return (
                    CausalExplanation.POTENTIAL_ENVIRONMENT_LIMITATION,
                    None,
                    lim.evidence,
                    interpretation,
                    "CONTEXTUAL_SIMILARITY_ONLY",
                    "PLAUSIBLE_HYPOTHESIS",
                    "UNKNOWN"
                )

        # Unexplained omission
        interpretation = (
            f"Observed in active run; absent from {target_report.sandbox_name} telemetry. "
            f"No sandbox warning correlates with omission; causes remain unverified."
        )
        return CausalExplanation.UNEXPLAINED, None, None, interpretation, "UNLINKED", "UNKNOWN", "UNKNOWN"

    def _evaluate_file_causality(self, target_report: NormalizedReport) -> CausalExplanation:
        for lim in target_report.limitations:
            if lim.category == "TIMEOUT":
                return CausalExplanation.POTENTIAL_ENVIRONMENT_LIMITATION
        return CausalExplanation.UNEXPLAINED
