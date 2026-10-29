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
    CollectionLimitation,
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
from .timing_benchmark import ExecutionBenchmark


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

        hash_a = (self.report_a.sample_sha256 or "").lower().strip()
        hash_b = (self.report_b.sample_sha256 or "").lower().strip()
        is_cross_sample = bool(hash_a and hash_b and hash_a != hash_b)

        lims_a = list(self.report_a.limitations)
        lims_b = list(self.report_b.limitations)

        if is_cross_sample:
            mismatch_lim = CollectionLimitation(
                report_id="COMPARATOR_CORE",
                code="SAMPLE_HASH_MISMATCH",
                description=(
                    f"Input reports analyze different sample SHA-256 hashes "
                    f"(Report A: '{hash_a}' vs Report B: '{hash_b}'). "
                    f"Behavioral alignment reflects cross-sample heuristics, NOT same-sample execution reproducibility."
                ),
                category="INPUT_DIVERGENCE"
            )
            lims_a.append(mismatch_lim)
            lims_b.append(mismatch_lim)
            notes.insert(
                0,
                f"WARNING: Cross-sample comparison. Report A sample SHA-256 ('{hash_a}') does not match Report B ('{hash_b}'). Behavioral similarities indicate heuristic overlap, not identical binary provenance."
            )
            sample_sha256 = f"CROSS_SAMPLE: {hash_a[:12]}... != {hash_b[:12]}..."
        else:
            sample_sha256 = hash_a or hash_b

        for lim in lims_b:
            notes.append(f"Report B Limitation [{lim.code}] ({lim.category}): {lim.description}")
        for lim in lims_a:
            notes.append(f"Report A Limitation [{lim.code}] ({lim.category}): {lim.description}")

        return ComparisonReport(
            sample_sha256=sample_sha256,
            report_a_id=self.report_a.report_id,
            report_b_id=self.report_b.report_id,
            reconciled_files=reconciled_files,
            reconciled_processes=reconciled_processes,
            reconciled_network=reconciled_network,
            collection_limitations={
                self.report_a.report_id: lims_a,
                self.report_b.report_id: lims_b,
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

    @staticmethod
    def _is_valid_sha256(h: Optional[str]) -> bool:
        if not h or not isinstance(h, str):
            return False
        h_clean = h.strip()
        return len(h_clean) == 64 and all(c in "0123456789abcdefABCDEF" for c in h_clean)

    def _reconcile_files(self) -> List[ReconciledFileItem]:
        results: List[ReconciledFileItem] = []
        files_a_by_hash: Dict[str, List[DroppedFileObservation]] = {}
        unhashed_a: List[DroppedFileObservation] = []
        for f in self.report_a.dropped_files:
            if self._is_valid_sha256(f.sha256) and not f.is_malformed_hash:
                files_a_by_hash.setdefault(f.sha256.lower().strip(), []).append(f)
            else:
                unhashed_a.append(f)

        files_b_by_hash: Dict[str, List[DroppedFileObservation]] = {}
        unhashed_b: List[DroppedFileObservation] = []
        for f in self.report_b.dropped_files:
            if self._is_valid_sha256(f.sha256) and not f.is_malformed_hash:
                files_b_by_hash.setdefault(f.sha256.lower().strip(), []).append(f)
            else:
                unhashed_b.append(f)

        # 1. Reconcile cryptographically valid hashes
        all_hashes = sorted(list(set(files_a_by_hash.keys()) | set(files_b_by_hash.keys())))

        for h in all_hashes:
            list_a = sorted(files_a_by_hash.get(h, []), key=lambda x: (x.file_path or "", x.file_name or ""))
            list_b = sorted(files_b_by_hash.get(h, []), key=lambda x: (x.file_path or "", x.file_name or ""))

            matched_pairs: List[Tuple[Optional[DroppedFileObservation], Optional[DroppedFileObservation]]] = []
            used_b_indices: Set[int] = set()

            for fa in list_a:
                best_b_idx = None
                # First try exact path match
                for b_idx, fb in enumerate(list_b):
                    if b_idx in used_b_indices:
                        continue
                    if fa.file_path and fb.file_path and fa.file_path.strip().lower() == fb.file_path.strip().lower():
                        best_b_idx = b_idx
                        break
                # Next try exact filename match
                if best_b_idx is None:
                    for b_idx, fb in enumerate(list_b):
                        if b_idx in used_b_indices:
                            continue
                        if fa.file_name and fb.file_name and fa.file_name.strip().lower() == fb.file_name.strip().lower():
                            best_b_idx = b_idx
                            break
                # Next take first available with same hash
                if best_b_idx is None:
                    for b_idx, fb in enumerate(list_b):
                        if b_idx not in used_b_indices:
                            best_b_idx = b_idx
                            break

                if best_b_idx is not None:
                    used_b_indices.add(best_b_idx)
                    matched_pairs.append((fa, list_b[best_b_idx]))
                else:
                    matched_pairs.append((fa, None))

            for b_idx, fb in enumerate(list_b):
                if b_idx not in used_b_indices:
                    matched_pairs.append((None, fb))

            for fa, fb in matched_pairs:
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

                    if fa.file_name != fb.file_name or (fa.file_path and fb.file_path and fa.file_path.strip().lower() != fb.file_path.strip().lower()):
                        interpretation = (
                            f"Identical binary payload (SHA-256: {h}) corroborated across runs, but filesystem paths or names diverge "
                            f"(Report A: '{fa.file_path or fa.file_name}'; Report B: '{fb.file_path or fb.file_name}'). "
                            f"Confirms content identity rather than identical filesystem deployment instance."
                        )
                    else:
                        interpretation = f"Corroborated by SHA-256 hash and identical path '{fa.file_path or fa.file_name}'."

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

        # 2. Reconcile unhashed or malformed-hash files (never group by empty hash!)
        used_unhashed_b: Set[int] = set()
        for fa in unhashed_a:
            best_b_idx = None
            for b_idx, fb in enumerate(unhashed_b):
                if b_idx in used_unhashed_b:
                    continue
                if fa.file_path and fb.file_path and fa.file_path.strip().lower() == fb.file_path.strip().lower():
                    best_b_idx = b_idx
                    break

            if best_b_idx is not None:
                used_unhashed_b.add(best_b_idx)
                fb = unhashed_b[best_b_idx]
                results.append(
                    ReconciledFileItem(
                        sha256=fa.sha256 or fb.sha256 or "UNAVAILABLE_MISSING_HASH",
                        observation_presence=ObservationPresence.OBSERVED_IN_BOTH,
                        causal_explanation=CausalExplanation.UNEXPLAINED,
                        filenames_by_report={self.report_a.report_id: fa.file_name, self.report_b.report_id: fb.file_name},
                        file_paths_by_report={self.report_a.report_id: fa.file_path, self.report_b.report_id: fb.file_path},
                        evidence_links={self.report_a.report_id: fa.evidence, self.report_b.report_id: fb.evidence},
                        epistemic_interpretation=(
                            f"Files share matching path '{fa.file_path}' across runs, but lack verified cryptographic SHA-256 hashes "
                            f"(Report A: '{fa.sha256 or 'none'}', Report B: '{fb.sha256 or 'none'}'). "
                            f"Content identity cannot be verified; payload corroboration remains unestablished."
                        ),
                        is_malformed_hash=True
                    )
                )
            else:
                results.append(
                    ReconciledFileItem(
                        sha256=fa.sha256 or "UNAVAILABLE_MISSING_HASH",
                        observation_presence=ObservationPresence.OBSERVED_ONLY_IN_A,
                        causal_explanation=self._evaluate_file_causality(self.report_b),
                        filenames_by_report={self.report_a.report_id: fa.file_name},
                        file_paths_by_report={self.report_a.report_id: fa.file_path},
                        evidence_links={
                            self.report_a.report_id: fa.evidence,
                            self.report_b.report_id: EvidencePointer(
                                report_id=self.report_b.report_id,
                                json_pointer="",
                                event_summary=f"Unhashed file '{fa.file_name}' unrecorded in Report B",
                                raw_snippet={},
                                is_available=False,
                                missing_reason="File unrecorded or lacks valid hash in Report B"
                            )
                        },
                        epistemic_interpretation=(
                            f"Observed only in Report A ('{fa.file_name}'). "
                            f"File lacks a verified SHA-256 hash (recorded: '{fa.sha256 or 'none'}'); "
                            f"cannot correlate content across environments without cryptographic hash."
                        ),
                        is_malformed_hash=True
                    )
                )

        for b_idx, fb in enumerate(unhashed_b):
            if b_idx not in used_unhashed_b:
                results.append(
                    ReconciledFileItem(
                        sha256=fb.sha256 or "UNAVAILABLE_MISSING_HASH",
                        observation_presence=ObservationPresence.OBSERVED_ONLY_IN_B,
                        causal_explanation=self._evaluate_file_causality(self.report_a),
                        filenames_by_report={self.report_b.report_id: fb.file_name},
                        file_paths_by_report={self.report_b.report_id: fb.file_path},
                        evidence_links={
                            self.report_b.report_id: fb.evidence,
                            self.report_a.report_id: EvidencePointer(
                                report_id=self.report_a.report_id,
                                json_pointer="",
                                event_summary=f"Unhashed file '{fb.file_name}' unrecorded in Report A",
                                raw_snippet={},
                                is_available=False,
                                missing_reason="File unrecorded or lacks valid hash in Report A"
                            )
                        },
                        epistemic_interpretation=(
                            f"Observed only in Report B ('{fb.file_name}'). "
                            f"File lacks a verified SHA-256 hash (recorded: '{fb.sha256 or 'none'}'); "
                            f"cannot correlate content across environments without cryptographic hash."
                        ),
                        is_malformed_hash=True
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
        def get_ancestors(proc: ProcessObservation) -> Set[str]:
            if not proc.lineage_path:
                return set()
            if proc.lineage_path[-1].lower() == proc.image_name.lower():
                return set(s.lower() for s in proc.lineage_path[:-1])
            return set(s.lower() for s in proc.lineage_path)

        anc_a = get_ancestors(p_a)
        anc_b = get_ancestors(p_b)
        if anc_a and anc_b:
            anc_union = anc_a | anc_b
            anc_intersect = anc_a & anc_b
            anc_sim = len(anc_intersect) / len(anc_union) if anc_union else 0.0
        else:
            anc_sim = 0.0

        # Argument similarity (Jaccard)
        if args_a and args_b:
            arg_intersect = args_a & args_b
            arg_union = args_a | args_b
            arg_jaccard = len(arg_intersect) / len(arg_union) if arg_union else 0.0
        else:
            arg_jaccard = 0.0

        # Disjoint ancestry penalty (only when BOTH processes have recorded ancestry and they actively conflict)
        if (anc_a and anc_b) and anc_sim == 0.0:
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

        # Step 1: Compute all pairwise similarity scores
        candidates_by_a: Dict[int, List[Tuple[int, float, str]]] = {i: [] for i in range(len(procs_a))}
        candidates_by_b: Dict[int, List[Tuple[int, float, str]]] = {j: [] for j in range(len(procs_b))}
        all_candidate_pairs: List[Tuple[float, int, int, str]] = []

        for idx_a, p_a in enumerate(procs_a):
            for idx_b, p_b in enumerate(procs_b):
                score, rationale = self._score_process_pair(p_a, p_b)
                if score >= 0.45:
                    candidates_by_a[idx_a].append((idx_b, score, rationale))
                    candidates_by_b[idx_b].append((idx_a, score, rationale))
                    all_candidate_pairs.append((score, idx_a, idx_b, rationale))

        for idx_a in candidates_by_a:
            candidates_by_a[idx_a].sort(key=lambda x: x[1], reverse=True)
        for idx_b in candidates_by_b:
            candidates_by_b[idx_b].sort(key=lambda x: x[1], reverse=True)

        # Step 2: Greedy score-sorted bipartite matching with anchor preservation (highest scores matched first)
        # Deterministic tie-breaking on intrinsic attributes ensures order independence
        all_candidate_pairs.sort(
            key=lambda x: (
                -x[0],
                procs_a[x[1]].image_name.lower(),
                procs_b[x[2]].image_name.lower(),
                procs_a[x[1]].command_line or "",
                procs_b[x[2]].command_line or "",
                "/".join(procs_a[x[1]].lineage_path),
                "/".join(procs_b[x[2]].lineage_path),
                procs_a[x[1]].source_pid,
                procs_b[x[2]].source_pid
            )
        )
        matched_a_to_b: Dict[int, Tuple[int, float, str]] = {}
        matched_b_indices: Set[int] = set()

        for score, idx_a, idx_b, rationale in all_candidate_pairs:
            if idx_a not in matched_a_to_b and idx_b not in matched_b_indices:
                matched_a_to_b[idx_a] = (idx_b, score, rationale)
                matched_b_indices.add(idx_b)

        # Step 3: Emit reconciled items for processes in A
        for idx_a, p_a in enumerate(procs_a):
            evidence_links: Dict[str, EvidencePointer] = {self.report_a.report_id: p_a.evidence}
            pids: Dict[str, int] = {self.report_a.report_id: p_a.source_pid}
            commands: Dict[str, str] = {self.report_a.report_id: p_a.command_line}
            alternatives: List[Dict[str, Any]] = []

            if idx_a in matched_a_to_b:
                best_idx_b, best_score, best_rationale = matched_a_to_b[idx_a]
                p_b = procs_b[best_idx_b]
                evidence_links[self.report_b.report_id] = p_b.evidence
                pids[self.report_b.report_id] = p_b.source_pid
                commands[self.report_b.report_id] = p_b.command_line

                is_ambiguous = False
                a_cands = candidates_by_a.get(idx_a, [])
                alt_cands = [c for c in a_cands if c[0] != best_idx_b]
                for c_idx, c_score, c_rat in alt_cands:
                    if abs(best_score - c_score) < 0.15:
                        is_ambiguous = True
                    alternatives.append({
                        "report_b_pid": procs_b[c_idx].source_pid,
                        "image": procs_b[c_idx].image_name,
                        "score": c_score,
                        "rationale": c_rat,
                        "claimed_by_other": c_idx in matched_b_indices and c_idx != best_idx_b
                    })

                # Check reverse competition (another node in A competing for the same node in B)
                b_cands = candidates_by_b.get(best_idx_b, [])
                for other_a_idx, other_score, _ in b_cands:
                    if other_a_idx != idx_a and abs(best_score - other_score) < 0.15:
                        is_ambiguous = True

                if best_score >= 0.80 and not is_ambiguous:
                    confidence = ProcessMatchConfidence.MATCHED
                    obs_presence = ObservationPresence.OBSERVED_IN_BOTH
                    causal = CausalExplanation.CORROBORATED_EXECUTION
                    interpretation = f"Corroborated across runs (PID A={p_a.source_pid}, PID B={p_b.source_pid})."
                else:
                    confidence = ProcessMatchConfidence.POSSIBLE_MATCH
                    obs_presence = ObservationPresence.OBSERVED_IN_BOTH
                    causal = CausalExplanation.UNEXPLAINED
                    interpretation = (
                        f"Plausible candidate alignment (PID A={p_a.source_pid}, PID B={p_b.source_pid}) "
                        f"with score {best_score:.2f}, but ambiguity across candidate nodes prevents definitive corroboration."
                    )
            else:
                confidence = ProcessMatchConfidence.UNRESOLVED
                obs_presence = ObservationPresence.OBSERVED_ONLY_IN_A
                causal = self._evaluate_process_causality(self.report_b)
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

        # Step 4: Handle leftover processes in Report B
        for idx_b, p_b in enumerate(procs_b):
            if idx_b in matched_b_indices:
                continue
            causal = self._evaluate_process_causality(self.report_a)
            evidence_links = {
                self.report_b.report_id: p_b.evidence,
                self.report_a.report_id: EvidencePointer(
                    report_id=self.report_a.report_id,
                    json_pointer="",
                    event_summary=f"Process '{p_b.image_name}' unrecorded in Report A",
                    raw_snippet={},
                    is_available=False,
                    missing_reason="No matching execution node in Report A"
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
                    evidence_links=evidence_links,
                    alternative_candidates=[]
                )
            )

        return results

    def _score_network_pair(self, na: NetworkObservation, nb: NetworkObservation) -> Tuple[float, bool]:
        """
        Calculates similarity between two network observations sharing a connection_key.
        Returns (score, has_discriminators).
        Evaluates source port, PID, timestamp, and HTTP/DNS attributes from raw_snippet.
        """
        snip_a = na.evidence.raw_snippet if na.evidence and isinstance(na.evidence.raw_snippet, dict) else {}
        snip_b = nb.evidence.raw_snippet if nb.evidence and isinstance(nb.evidence.raw_snippet, dict) else {}

        score = 0.0
        has_discriminators = False

        # Source port matching
        sport_a = snip_a.get("sport") or snip_a.get("src_port")
        sport_b = snip_b.get("sport") or snip_b.get("src_port")
        if sport_a is not None and sport_b is not None:
            has_discriminators = True
            if sport_a == sport_b:
                score += 0.40
            else:
                score -= 0.30

        # PID matching
        pid_a = snip_a.get("pid") or snip_a.get("source_pid")
        pid_b = snip_b.get("pid") or snip_b.get("source_pid")
        if pid_a is not None and pid_b is not None:
            has_discriminators = True
            if pid_a == pid_b:
                score += 0.30
            else:
                score -= 0.10

        # Timestamp proximity (within 2 seconds)
        time_a = snip_a.get("time") or snip_a.get("timestamp")
        time_b = snip_b.get("time") or snip_b.get("timestamp")
        if time_a is not None and time_b is not None:
            try:
                diff = abs(float(time_a) - float(time_b))
                has_discriminators = True
                if diff <= 2.0:
                    score += 0.30
                elif diff <= 10.0:
                    score += 0.15
            except (ValueError, TypeError):
                pass

        # Method / URI matching (for HTTP)
        method_a = snip_a.get("method")
        method_b = snip_b.get("method")
        if method_a and method_b:
            has_discriminators = True
            if str(method_a).upper() == str(method_b).upper():
                score += 0.20

        return max(score, 0.0), has_discriminators

    def _reconcile_network(self) -> List[ReconciledNetworkItem]:
        results: List[ReconciledNetworkItem] = []
        net_a_by_key: Dict[str, List[NetworkObservation]] = {}
        for n in self.report_a.network_events:
            net_a_by_key.setdefault(n.connection_key, []).append(n)

        net_b_by_key: Dict[str, List[NetworkObservation]] = {}
        for n in self.report_b.network_events:
            net_b_by_key.setdefault(n.connection_key, []).append(n)

        all_keys = sorted(list(set(net_a_by_key.keys()) | set(net_b_by_key.keys())))

        for key in all_keys:
            list_a = net_a_by_key.get(key, [])
            list_b = net_b_by_key.get(key, [])

            pairs: List[Tuple[NetworkObservation, NetworkObservation, str, bool]] = []
            unmatched_a: List[NetworkObservation] = []
            unmatched_b: List[NetworkObservation] = []

            if len(list_a) == 1 and len(list_b) == 1:
                score, has_disc = self._score_network_pair(list_a[0], list_b[0])
                if has_disc and score > 0.0:
                    pairs.append((list_a[0], list_b[0], "DIRECT_IDENTIFIER_MATCH", True))
                elif has_disc:
                    pairs.append((list_a[0], list_b[0], "DIVERGENT_ENDPOINT_ATTRIBUTES", False))
                else:
                    pairs.append((list_a[0], list_b[0], "SINGLETON_ENDPOINT_OVERLAP", False))
            elif len(list_a) > 0 and len(list_b) > 0:
                # Pairwise matching among repeated connections using discriminating attributes
                candidate_pairs = []
                for i_a, na in enumerate(list_a):
                    for i_b, nb in enumerate(list_b):
                        score, has_disc = self._score_network_pair(na, nb)
                        if has_disc and score > 0.0:
                            candidate_pairs.append((score, has_disc, i_a, i_b))

                # Sort candidates by score descending
                candidate_pairs.sort(key=lambda x: x[0], reverse=True)

                used_a: Set[int] = set()
                used_b: Set[int] = set()
                for score, has_disc, i_a, i_b in candidate_pairs:
                    if i_a in used_a or i_b in used_b:
                        continue
                    used_a.add(i_a)
                    used_b.add(i_b)
                    pairs.append((list_a[i_a], list_b[i_b], "DIRECT_IDENTIFIER_MATCH", True))

                rem_a = [list_a[i] for i in range(len(list_a)) if i not in used_a]
                rem_b = [list_b[i] for i in range(len(list_b)) if i not in used_b]

                if rem_a and rem_b:
                    cluster_links = {
                        self.report_a.report_id: rem_a[0].evidence,
                        self.report_b.report_id: rem_b[0].evidence
                    }
                    results.append(
                        ReconciledNetworkItem(
                            connection_key=key,
                            observation_presence=ObservationPresence.OBSERVED_IN_BOTH,
                            observation_type="TELEMETRY_LOGGED_SOCKET_RECORD",
                            connection_state="SOCKET_RECORD_LOGGED",
                            policy_decision=None,
                            cross_report_correlation="AGGREGATE_ENDPOINT_CLUSTER",
                            causal_status="AGGREGATE_ENDPOINT_CORROBORATION",
                            causal_explanation=CausalExplanation.UNEXPLAINED,
                            policy_decision_record=None,
                            policy_decision_evidence=None,
                            observed_in_reports=[self.report_a.report_id, self.report_b.report_id],
                            unobserved_in_reports=[],
                            evidence_links=cluster_links,
                            epistemic_interpretation=(
                                f"Endpoint '{key}' logged multiple socket records ({len(rem_a)} in {self.report_a.report_id}, "
                                f"{len(rem_b)} in {self.report_b.report_id}) lacking distinct source ports or timestamps. "
                                f"Records are grouped into a single aggregate destination cluster rather than arbitrary one-to-one stream pairings."
                            )
                        )
                    )
                elif rem_a:
                    unmatched_a = rem_a
                elif rem_b:
                    unmatched_b = rem_b
            else:
                unmatched_a = list(list_a)
                unmatched_b = list(list_b)

            for na, nb, cross_corr, has_disc in pairs:
                evidence_links: Dict[str, EvidencePointer] = {
                    self.report_a.report_id: na.evidence,
                    self.report_b.report_id: nb.evidence
                }
                conn_state = "SOCKET_RECORD_LOGGED"
                if cross_corr == "DIRECT_IDENTIFIER_MATCH":
                    obs_presence = ObservationPresence.OBSERVED_IN_BOTH
                    causal = CausalExplanation.CORROBORATED_EXECUTION
                    causal_stat = "CORROBORATED_SOCKET"
                    interpretation = (
                        f"Socket observation '{key}' corroborated across both reports with matching connection attributes. "
                        f"Telemetry confirms both environments logged socket activity; does not establish "
                        f"full application-layer handshake completion or identical payload transmission without packet-level capture."
                    )
                elif cross_corr == "DIVERGENT_ENDPOINT_ATTRIBUTES":
                    obs_presence = ObservationPresence.OBSERVED_IN_BOTH
                    causal = CausalExplanation.UNEXPLAINED
                    causal_stat = "DIVERGENT_ENDPOINT_ATTRIBUTES"
                    interpretation = (
                        f"Endpoint '{key}' logged once in each report, but distinguishing attributes conflict "
                        f"(e.g., source port or protocol). Treated as endpoint-level overlap with conflicting attributes "
                        f"rather than a corroborated socket stream."
                    )
                elif cross_corr == "SINGLETON_ENDPOINT_OVERLAP":
                    obs_presence = ObservationPresence.OBSERVED_IN_BOTH
                    causal = CausalExplanation.UNEXPLAINED
                    causal_stat = "ENDPOINT_MATCH"
                    interpretation = (
                        f"Endpoint '{key}' logged once in each report, but records lack distinguishing attributes "
                        f"(e.g., ephemeral source port, PID, or timestamp) to confirm an identical socket session. "
                        f"Treat as endpoint overlap rather than a verified stream-level match."
                    )
                else:
                    obs_presence = ObservationPresence.OBSERVED_IN_BOTH
                    causal = CausalExplanation.UNEXPLAINED
                    causal_stat = "AGGREGATE_ENDPOINT_CORROBORATION"
                    interpretation = (
                        f"Endpoint '{key}' logged multiple socket records ({len(list_a)} in {self.report_a.report_id}, "
                        f"{len(list_b)} in {self.report_b.report_id}). Specific stream-to-stream bijection is unestablished "
                        f"due to lack of distinct source ports or timestamps; aggregate traffic to destination is corroborated."
                    )

                results.append(
                    ReconciledNetworkItem(
                        connection_key=key,
                        observation_presence=obs_presence,
                        observation_type="TELEMETRY_LOGGED_SOCKET_RECORD",
                        connection_state=conn_state,
                        policy_decision=None,
                        cross_report_correlation=cross_corr,
                        causal_status=causal_stat,
                        causal_explanation=causal,
                        policy_decision_record=None,
                        policy_decision_evidence=None,
                        observed_in_reports=[self.report_a.report_id, self.report_b.report_id],
                        unobserved_in_reports=[],
                        evidence_links=evidence_links,
                        epistemic_interpretation=interpretation
                    )
                )

            for na in unmatched_a:
                evidence_links = {self.report_a.report_id: na.evidence}
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
                results.append(
                    ReconciledNetworkItem(
                        connection_key=key,
                        observation_presence=ObservationPresence.OBSERVED_ONLY_IN_A,
                        observation_type="TELEMETRY_LOGGED_SOCKET_RECORD",
                        connection_state=conn_state,
                        policy_decision=policy_rec,
                        cross_report_correlation=cross_corr,
                        causal_status=causal_stat,
                        causal_explanation=causal,
                        policy_decision_record=policy_rec,
                        policy_decision_evidence=policy_ptr,
                        observed_in_reports=[self.report_a.report_id],
                        unobserved_in_reports=[self.report_b.report_id],
                        evidence_links=evidence_links,
                        epistemic_interpretation=interpretation
                    )
                )

            for nb in unmatched_b:
                evidence_links = {self.report_b.report_id: nb.evidence}
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
                        observation_presence=ObservationPresence.OBSERVED_ONLY_IN_B,
                        observation_type="TELEMETRY_LOGGED_SOCKET_RECORD",
                        connection_state=conn_state,
                        policy_decision=policy_rec,
                        cross_report_correlation=cross_corr,
                        causal_status=causal_stat,
                        causal_explanation=causal,
                        policy_decision_record=policy_rec,
                        policy_decision_evidence=policy_ptr,
                        observed_in_reports=[self.report_b.report_id],
                        unobserved_in_reports=[self.report_a.report_id],
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
                        f"TCP observation present in {event.report_id}; {target_report.sandbox_name} contains a general egress-policy "
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

    def _evaluate_process_causality(self, target_report: NormalizedReport) -> CausalExplanation:
        """
        Evaluates whether an unobserved process execution can be attributed to documented
        sandbox environment limitations (e.g. TIMEOUT, ANTI_EVASION, CRASH).
        """
        for lim in target_report.limitations:
            if lim.category in ("TIMEOUT", "ANTI_EVASION", "CRASH"):
                return CausalExplanation.POTENTIAL_ENVIRONMENT_LIMITATION
        return CausalExplanation.UNEXPLAINED

    def _evaluate_file_causality(self, target_report: NormalizedReport) -> CausalExplanation:
        """
        Evaluates whether an unrecorded dropped file can be attributed to documented
        filesystem or sandbox capture limitations (e.g. TIMEOUT, DISK_QUOTA, DROP_LIMIT).
        """
        for lim in target_report.limitations:
            if lim.category in ("TIMEOUT", "DISK_QUOTA", "DROP_LIMIT"):
                return CausalExplanation.POTENTIAL_ENVIRONMENT_LIMITATION
        return CausalExplanation.UNEXPLAINED
