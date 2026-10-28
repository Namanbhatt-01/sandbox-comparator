use crate::models::{
    CausalExplanation, ComparisonReport, DroppedFileObservation, EvidencePointer,
    NetworkObservation, NormalizedReport, ObservationPresence, ProcessAlternativeCandidate,
    ProcessMatchConfidence, ProcessObservation, ReconciledFileItem, ReconciledNetworkItem,
    ReconciledProcessItem,
};
use crate::provenance::truncate_utf8;
use std::collections::{BTreeMap, HashSet};

pub fn tokenize_cmdline(cmd: &str) -> HashSet<String> {
    let mut tokens = HashSet::new();
    let delimiters = [' ', '\t', '\n', '\r', '"', '\'', '=', ',', ';'];
    for part in cmd.split(&delimiters[..]) {
        let trimmed = part.trim();
        if trimmed.is_empty() {
            continue;
        }
        let lower = trimmed.to_ascii_lowercase();
        let base = lower.replace('\\', "/");
        let filename = base.rsplit('/').next().unwrap_or(&base);
        tokens.insert(filename.to_string());
    }
    tokens
}

pub fn get_arg_tokens(img_name: &str, cmdline: &str) -> HashSet<String> {
    let tokens = tokenize_cmdline(cmdline);
    let img_lower = img_name.to_ascii_lowercase();
    let img_base = img_lower.replace(".exe", "");
    tokens
        .into_iter()
        .filter(|t| t != &img_lower && t != &img_base)
        .collect()
}

pub struct EvidenceComparator<'a> {
    pub report_a: &'a NormalizedReport,
    pub report_b: &'a NormalizedReport,
}

impl<'a> EvidenceComparator<'a> {
    pub fn new(report_a: &'a NormalizedReport, report_b: &'a NormalizedReport) -> Self {
        Self { report_a, report_b }
    }

    pub fn reconcile(&self) -> ComparisonReport {
        let reconciled_files = self.reconcile_files();
        let reconciled_processes = self.reconcile_processes();
        let reconciled_network = self.reconcile_network();

        let mut notes = vec![
            "Epistemic Principle: Telemetry absence does NOT confirm behavioral non-occurrence.".to_string(),
            format!(
                "Report A ({}) duration: {}s. Provenance: {}.",
                self.report_a.sandbox_name,
                self.report_a.duration_seconds.unwrap_or(0),
                self.report_a.schema_provenance_type
            ),
            format!(
                "Report B ({}) duration: {}s. Provenance: {}.",
                self.report_b.sandbox_name,
                self.report_b.duration_seconds.unwrap_or(0),
                self.report_b.schema_provenance_type
            ),
            "All process match scores are heuristic similarity metrics, NOT calibrated confidence probabilities.".to_string(),
            "All evidence addresses formatted as RFC 6901 JSON Pointers (/path/to/token).".to_string(),
        ];

        for lim in &self.report_b.limitations {
            notes.push(format!(
                "Report B Limitation [{}] ({}): {}",
                lim.code, lim.category, lim.description
            ));
        }
        for lim in &self.report_a.limitations {
            notes.push(format!(
                "Report A Limitation [{}] ({}): {}",
                lim.code, lim.category, lim.description
            ));
        }

        let mut limitations = BTreeMap::new();
        limitations.insert(self.report_a.report_id.clone(), self.report_a.limitations.clone());
        limitations.insert(self.report_b.report_id.clone(), self.report_b.limitations.clone());

        let mut provenance_metadata = BTreeMap::new();
        provenance_metadata.insert(
            self.report_a.report_id.clone(),
            serde_json::json!({
                "sandbox": self.report_a.sandbox_name,
                "schema": self.report_a.schema_format,
                "provenance_type": self.report_a.schema_provenance_type,
                "parser_warnings": self.report_a.parser_warnings
            }),
        );
        provenance_metadata.insert(
            self.report_b.report_id.clone(),
            serde_json::json!({
                "sandbox": self.report_b.sandbox_name,
                "schema": self.report_b.schema_format,
                "provenance_type": self.report_b.schema_provenance_type,
                "parser_warnings": self.report_b.parser_warnings
            }),
        );

        let sample_sha256 = if !self.report_a.sample_sha256.is_empty() {
            self.report_a.sample_sha256.clone()
        } else {
            self.report_b.sample_sha256.clone()
        };

        ComparisonReport {
            sample_sha256,
            report_a_id: self.report_a.report_id.clone(),
            report_b_id: self.report_b.report_id.clone(),
            reconciled_files,
            reconciled_processes,
            reconciled_network,
            collection_limitations: limitations,
            epistemic_uncertainty_notes: notes,
            provenance_metadata,
        }
    }

    fn reconcile_files(&self) -> Vec<ReconciledFileItem> {
        let mut results = Vec::new();

        fn is_valid_sha256(h: &str) -> bool {
            h.len() == 64 && h.chars().all(|c| c.is_ascii_hexdigit())
        }

        let mut files_a_by_hash: BTreeMap<String, Vec<&DroppedFileObservation>> = BTreeMap::new();
        let mut unhashed_a: Vec<&DroppedFileObservation> = Vec::new();
        for f in &self.report_a.dropped_files {
            if is_valid_sha256(&f.sha256) && !f.is_malformed_hash {
                files_a_by_hash.entry(f.sha256.to_ascii_lowercase()).or_default().push(f);
            } else {
                unhashed_a.push(f);
            }
        }

        let mut files_b_by_hash: BTreeMap<String, Vec<&DroppedFileObservation>> = BTreeMap::new();
        let mut unhashed_b: Vec<&DroppedFileObservation> = Vec::new();
        for f in &self.report_b.dropped_files {
            if is_valid_sha256(&f.sha256) && !f.is_malformed_hash {
                files_b_by_hash.entry(f.sha256.to_ascii_lowercase()).or_default().push(f);
            } else {
                unhashed_b.push(f);
            }
        }

        let mut all_hashes: HashSet<String> = HashSet::new();
        for h in files_a_by_hash.keys() {
            all_hashes.insert(h.clone());
        }
        for h in files_b_by_hash.keys() {
            all_hashes.insert(h.clone());
        }
        let mut sorted_hashes: Vec<String> = all_hashes.into_iter().collect();
        sorted_hashes.sort();

        for h in sorted_hashes {
            let mut list_a = files_a_by_hash.get(&h).cloned().unwrap_or_default();
            let mut list_b = files_b_by_hash.get(&h).cloned().unwrap_or_default();
            list_a.sort_by(|x, y| x.file_path.cmp(&y.file_path).then_with(|| x.file_name.cmp(&y.file_name)));
            list_b.sort_by(|x, y| x.file_path.cmp(&y.file_path).then_with(|| x.file_name.cmp(&y.file_name)));

            let mut matched_pairs: Vec<(Option<&DroppedFileObservation>, Option<&DroppedFileObservation>)> =
                Vec::new();
            let mut used_b_indices: HashSet<usize> = HashSet::new();

            for fa in &list_a {
                let mut best_b_idx = None;
                // 1. Exact path match
                for (b_idx, fb) in list_b.iter().enumerate() {
                    if used_b_indices.contains(&b_idx) {
                        continue;
                    }
                    if !fa.file_path.is_empty()
                        && !fb.file_path.is_empty()
                        && fa.file_path.trim().eq_ignore_ascii_case(fb.file_path.trim())
                    {
                        best_b_idx = Some(b_idx);
                        break;
                    }
                }
                // 2. Exact filename match
                if best_b_idx.is_none() {
                    for (b_idx, fb) in list_b.iter().enumerate() {
                        if used_b_indices.contains(&b_idx) {
                            continue;
                        }
                        if !fa.file_name.is_empty()
                            && !fb.file_name.is_empty()
                            && fa.file_name.trim().eq_ignore_ascii_case(fb.file_name.trim())
                        {
                            best_b_idx = Some(b_idx);
                            break;
                        }
                    }
                }
                // 3. First available
                if best_b_idx.is_none() {
                    for (b_idx, _) in list_b.iter().enumerate() {
                        if !used_b_indices.contains(&b_idx) {
                            best_b_idx = Some(b_idx);
                            break;
                        }
                    }
                }

                if let Some(b_idx) = best_b_idx {
                    used_b_indices.insert(b_idx);
                    matched_pairs.push((Some(fa), Some(list_b[b_idx])));
                } else {
                    matched_pairs.push((Some(fa), None));
                }
            }

            for (b_idx, fb) in list_b.iter().enumerate() {
                if !used_b_indices.contains(&b_idx) {
                    matched_pairs.push((None, Some(fb)));
                }
            }

            for (opt_a, opt_b) in matched_pairs {
                let mut filenames = BTreeMap::new();
                let mut filepaths = BTreeMap::new();
                let mut evidence_links = BTreeMap::new();
                let is_malformed = opt_a.is_some_and(|f| f.is_malformed_hash)
                    || opt_b.is_some_and(|f| f.is_malformed_hash);

                let (obs_presence, causal, interpretation) = match (opt_a, opt_b) {
                    (Some(fa), Some(fb)) => {
                        filenames.insert(self.report_a.report_id.clone(), fa.file_name.clone());
                        filenames.insert(self.report_b.report_id.clone(), fb.file_name.clone());
                        filepaths.insert(self.report_a.report_id.clone(), fa.file_path.clone());
                        filepaths.insert(self.report_b.report_id.clone(), fb.file_path.clone());
                        evidence_links.insert(self.report_a.report_id.clone(), fa.evidence.clone());
                        evidence_links.insert(self.report_b.report_id.clone(), fb.evidence.clone());

                        let interp = if fa.file_name != fb.file_name
                            || (!fa.file_path.is_empty()
                                && !fb.file_path.is_empty()
                                && !fa.file_path.trim().eq_ignore_ascii_case(fb.file_path.trim()))
                        {
                            format!(
                                "Identical binary payload (SHA-256: {}) corroborated across runs, but filesystem paths or names diverge (Report A: '{}'; Report B: '{}'). Confirms content identity rather than identical filesystem deployment instance.",
                                h, fa.file_path, fb.file_path
                            )
                        } else {
                            format!(
                                "Corroborated by SHA-256 hash and identical path '{}'.",
                                if !fa.file_path.is_empty() { &fa.file_path } else { &fa.file_name }
                            )
                        };

                        (
                            ObservationPresence::OBSERVED_IN_BOTH,
                            CausalExplanation::CORROBORATED_EXECUTION,
                            interp,
                        )
                    }
                    (Some(fa), None) => {
                        let causal = self.evaluate_file_causality(self.report_b);
                        filenames.insert(self.report_a.report_id.clone(), fa.file_name.clone());
                        filepaths.insert(self.report_a.report_id.clone(), fa.file_path.clone());
                        evidence_links.insert(self.report_a.report_id.clone(), fa.evidence.clone());

                        let hash_pref = truncate_utf8(&h, 12);
                        evidence_links.insert(
                            self.report_b.report_id.clone(),
                            EvidencePointer::missing(
                                &self.report_b.report_id,
                                &format!("SHA-256 {}... unrecorded in Report B", hash_pref),
                                &format!("File hash {} not found in {} created_files telemetry", h, self.report_b.report_id),
                            ),
                        );

                        let interp = format!(
                            "Observed only in Report A ('{}'). Report B telemetry does not record this file; this does not establish non-occurrence.",
                            fa.file_name
                        );

                        (ObservationPresence::OBSERVED_ONLY_IN_A, causal, interp)
                    }
                    (None, Some(fb)) => {
                        let causal = self.evaluate_file_causality(self.report_a);
                        filenames.insert(self.report_b.report_id.clone(), fb.file_name.clone());
                        filepaths.insert(self.report_b.report_id.clone(), fb.file_path.clone());
                        evidence_links.insert(self.report_b.report_id.clone(), fb.evidence.clone());

                        let hash_pref = truncate_utf8(&h, 12);
                        evidence_links.insert(
                            self.report_a.report_id.clone(),
                            EvidencePointer::missing(
                                &self.report_a.report_id,
                                &format!("SHA-256 {}... unrecorded in Report A", hash_pref),
                                &format!("File hash {} not found in {} dropped telemetry", h, self.report_a.report_id),
                            ),
                        );

                        let interp = format!(
                            "Observed only in Report B ('{}'). Report A telemetry does not record this file; this does not establish non-occurrence.",
                            fb.file_name
                        );

                        (ObservationPresence::OBSERVED_ONLY_IN_B, causal, interp)
                    }
                    (None, None) => unreachable!(),
                };

                results.push(ReconciledFileItem {
                    sha256: h.clone(),
                    observation_presence: obs_presence,
                    causal_explanation: causal,
                    filenames_by_report: filenames,
                    file_paths_by_report: filepaths,
                    evidence_links,
                    epistemic_interpretation: interpretation,
                    is_malformed_hash: is_malformed,
                });
            }
        }

        // Reconcile unhashed or malformed-hash files (never group by empty hash!)
        let mut used_unhashed_b: HashSet<usize> = HashSet::new();
        for fa in unhashed_a {
            let mut best_b_idx = None;
            for (b_idx, fb) in unhashed_b.iter().enumerate() {
                if used_unhashed_b.contains(&b_idx) {
                    continue;
                }
                if !fa.file_path.is_empty()
                    && !fb.file_path.is_empty()
                    && fa.file_path.trim().eq_ignore_ascii_case(fb.file_path.trim())
                {
                    best_b_idx = Some(b_idx);
                    break;
                }
            }

            if let Some(b_idx) = best_b_idx {
                used_unhashed_b.insert(b_idx);
                let fb = unhashed_b[b_idx];
                let mut filenames = BTreeMap::new();
                let mut filepaths = BTreeMap::new();
                let mut evidence_links = BTreeMap::new();

                filenames.insert(self.report_a.report_id.clone(), fa.file_name.clone());
                filenames.insert(self.report_b.report_id.clone(), fb.file_name.clone());
                filepaths.insert(self.report_a.report_id.clone(), fa.file_path.clone());
                filepaths.insert(self.report_b.report_id.clone(), fb.file_path.clone());
                evidence_links.insert(self.report_a.report_id.clone(), fa.evidence.clone());
                evidence_links.insert(self.report_b.report_id.clone(), fb.evidence.clone());

                results.push(ReconciledFileItem {
                    sha256: if !fa.sha256.is_empty() { fa.sha256.clone() } else if !fb.sha256.is_empty() { fb.sha256.clone() } else { "UNAVAILABLE_MISSING_HASH".to_string() },
                    observation_presence: ObservationPresence::OBSERVED_IN_BOTH,
                    causal_explanation: CausalExplanation::UNEXPLAINED,
                    filenames_by_report: filenames,
                    file_paths_by_report: filepaths,
                    evidence_links,
                    epistemic_interpretation: format!(
                        "Files share matching path '{}' across runs, but lack verified cryptographic SHA-256 hashes (Report A: '{}', Report B: '{}'). Content identity cannot be verified; payload corroboration remains unestablished.",
                        fa.file_path,
                        if fa.sha256.is_empty() { "none" } else { &fa.sha256 },
                        if fb.sha256.is_empty() { "none" } else { &fb.sha256 }
                    ),
                    is_malformed_hash: true,
                });
            } else {
                let mut filenames = BTreeMap::new();
                let mut filepaths = BTreeMap::new();
                let mut evidence_links = BTreeMap::new();

                filenames.insert(self.report_a.report_id.clone(), fa.file_name.clone());
                filepaths.insert(self.report_a.report_id.clone(), fa.file_path.clone());
                evidence_links.insert(self.report_a.report_id.clone(), fa.evidence.clone());
                evidence_links.insert(
                    self.report_b.report_id.clone(),
                    EvidencePointer::missing(
                        &self.report_b.report_id,
                        &format!("Unhashed file '{}' unrecorded in Report B", fa.file_name),
                        "File unrecorded or lacks valid hash in Report B",
                    ),
                );

                results.push(ReconciledFileItem {
                    sha256: if !fa.sha256.is_empty() { fa.sha256.clone() } else { "UNAVAILABLE_MISSING_HASH".to_string() },
                    observation_presence: ObservationPresence::OBSERVED_ONLY_IN_A,
                    causal_explanation: self.evaluate_file_causality(self.report_b),
                    filenames_by_report: filenames,
                    file_paths_by_report: filepaths,
                    evidence_links,
                    epistemic_interpretation: format!(
                        "Observed only in Report A ('{}'). File lacks a verified SHA-256 hash (recorded: '{}'); cannot correlate content across environments without cryptographic hash.",
                        fa.file_name,
                        if fa.sha256.is_empty() { "none" } else { &fa.sha256 }
                    ),
                    is_malformed_hash: true,
                });
            }
        }

        for (b_idx, fb) in unhashed_b.iter().enumerate() {
            if !used_unhashed_b.contains(&b_idx) {
                let mut filenames = BTreeMap::new();
                let mut filepaths = BTreeMap::new();
                let mut evidence_links = BTreeMap::new();

                filenames.insert(self.report_b.report_id.clone(), fb.file_name.clone());
                filepaths.insert(self.report_b.report_id.clone(), fb.file_path.clone());
                evidence_links.insert(self.report_b.report_id.clone(), fb.evidence.clone());
                evidence_links.insert(
                    self.report_a.report_id.clone(),
                    EvidencePointer::missing(
                        &self.report_a.report_id,
                        &format!("Unhashed file '{}' unrecorded in Report A", fb.file_name),
                        "File unrecorded or lacks valid hash in Report A",
                    ),
                );

                results.push(ReconciledFileItem {
                    sha256: if !fb.sha256.is_empty() { fb.sha256.clone() } else { "UNAVAILABLE_MISSING_HASH".to_string() },
                    observation_presence: ObservationPresence::OBSERVED_ONLY_IN_B,
                    causal_explanation: self.evaluate_file_causality(self.report_a),
                    filenames_by_report: filenames,
                    file_paths_by_report: filepaths,
                    evidence_links,
                    epistemic_interpretation: format!(
                        "Observed only in Report B ('{}'). File lacks a verified SHA-256 hash (recorded: '{}'); cannot correlate content across environments without cryptographic hash.",
                        fb.file_name,
                        if fb.sha256.is_empty() { "none" } else { &fb.sha256 }
                    ),
                    is_malformed_hash: true,
                });
            }
        }

        results
    }

    fn score_process_pair(
        &self,
        p_a: &ProcessObservation,
        p_b: &ProcessObservation,
    ) -> (f64, String) {
        let img_a = p_a.image_name.to_ascii_lowercase();
        let img_b = p_b.image_name.to_ascii_lowercase();
        let args_a = get_arg_tokens(&p_a.image_name, &p_a.command_line);
        let args_b = get_arg_tokens(&p_b.image_name, &p_b.command_line);

        let lolbins = [
            "powershell.exe",
            "cmd.exe",
            "svchost.exe",
            "rundll32.exe",
            "mshta.exe",
            "cscript.exe",
            "wscript.exe",
            "regsvr32.exe",
        ];
        let is_lolbin = lolbins.contains(&img_a.as_str()) || lolbins.contains(&img_b.as_str());

        // Ancestry similarity (Jaccard)
        let get_ancestors = |p: &ProcessObservation| -> HashSet<String> {
            if p.lineage_path.is_empty() {
                return HashSet::new();
            }
            if p.lineage_path.last().map(|s| s.to_ascii_lowercase()) == Some(p.image_name.to_ascii_lowercase()) {
                p.lineage_path[..p.lineage_path.len() - 1]
                    .iter()
                    .map(|s| s.to_ascii_lowercase())
                    .collect()
            } else {
                p.lineage_path
                    .iter()
                    .map(|s| s.to_ascii_lowercase())
                    .collect()
            }
        };

        let anc_a = get_ancestors(p_a);
        let anc_b = get_ancestors(p_b);

        let anc_sim = if !anc_a.is_empty() && !anc_b.is_empty() {
            let intersect = anc_a.intersection(&anc_b).count();
            let union = anc_a.union(&anc_b).count();
            if union > 0 {
                intersect as f64 / union as f64
            } else {
                0.0
            }
        } else {
            0.0
        };

        // Argument similarity (Jaccard)
        let arg_jaccard = if !args_a.is_empty() && !args_b.is_empty() {
            let intersect = args_a.intersection(&args_b).count();
            let union = args_a.union(&args_b).count();
            if union > 0 {
                intersect as f64 / union as f64
            } else {
                0.0
            }
        } else {
            0.0
        };

        // Disjoint ancestry penalty
        if (!anc_a.is_empty() || !anc_b.is_empty()) && anc_sim == 0.0 {
            return (0.15, format!("Disjoint ancestry tree: {:?} vs {:?}", anc_a, anc_b));
        }

        // LOLBin divergent arguments penalty
        if is_lolbin && (!args_a.is_empty() || !args_b.is_empty()) && arg_jaccard < 0.20 {
            return (
                0.25,
                format!(
                    "LOLBin ({}) with divergent commandline arguments (Jaccard {:.2})",
                    img_a, arg_jaccard
                ),
            );
        }

        let mut score: f64 = 0.0;
        let mut reasons = Vec::new();

        if img_a == img_b {
            score += 0.35;
            reasons.push(format!("Image match ('{}')", p_a.image_name));
        } else if p_a.lineage_path.len() >= 2 && p_b.lineage_path.len() >= 2 {
            let parent_a = &p_a.lineage_path[p_a.lineage_path.len() - 2].to_ascii_lowercase();
            let parent_b = &p_b.lineage_path[p_b.lineage_path.len() - 2].to_ascii_lowercase();
            if parent_a.contains("powershell") && parent_b.contains("powershell") {
                score += 0.30;
                reasons.push("Spawned payload role under powershell.exe".to_string());
            }
        }

        score += 0.35 * arg_jaccard;
        if arg_jaccard > 0.3 {
            reasons.push(format!("Argument Jaccard ({:.2})", arg_jaccard));
        }

        score += 0.20 * anc_sim;
        if anc_sim > 0.3 {
            reasons.push(format!("Ancestry lineage overlap ({:.2})", anc_sim));
        }

        let depth_delta = (p_a.tree_depth as isize - p_b.tree_depth as isize).abs();
        if depth_delta == 0 {
            score += 0.10;
            reasons.push("Identical tree depth".to_string());
        } else if depth_delta == 1 {
            score += 0.05;
            reasons.push("Adjacent tree depth (delta=1)".to_string());
        }

        let final_score = ((score * 1000.0).round() / 1000.0).min(1.0);
        (final_score, reasons.join("; "))
    }

    fn reconcile_processes(&self) -> Vec<ReconciledProcessItem> {
        let mut results = Vec::new();
        let procs_a = &self.report_a.processes;
        let procs_b = &self.report_b.processes;

        // Step 1: Pairwise scoring
        let mut candidates_by_a: Vec<Vec<(usize, f64, String)>> = vec![Vec::new(); procs_a.len()];
        let mut all_candidate_pairs: Vec<(f64, usize, usize, String)> = Vec::new();

        for (idx_a, p_a) in procs_a.iter().enumerate() {
            for (idx_b, p_b) in procs_b.iter().enumerate() {
                let (score, rationale) = self.score_process_pair(p_a, p_b);
                if score >= 0.45 {
                    candidates_by_a[idx_a].push((idx_b, score, rationale.clone()));
                    all_candidate_pairs.push((score, idx_a, idx_b, rationale));
                }
            }
        }

        for list in &mut candidates_by_a {
            list.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        }

        // Step 2: Greedy score-sorted bipartite matching with anchor preservation (highest scores matched first)
        // Deterministic tie-breaking on intrinsic attributes ensures order independence
        all_candidate_pairs.sort_by(|a, b| {
            b.0.partial_cmp(&a.0)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| procs_a[a.1].image_name.to_ascii_lowercase().cmp(&procs_b[b.1].image_name.to_ascii_lowercase()))
                .then_with(|| procs_b[a.2].image_name.to_ascii_lowercase().cmp(&procs_b[b.2].image_name.to_ascii_lowercase()))
                .then_with(|| procs_a[a.1].command_line.cmp(&procs_b[b.1].command_line))
                .then_with(|| procs_b[a.2].command_line.cmp(&procs_b[b.2].command_line))
                .then_with(|| procs_a[a.1].lineage_path.join("/").cmp(&procs_b[b.1].lineage_path.join("/")))
                .then_with(|| procs_b[a.2].lineage_path.join("/").cmp(&procs_b[b.2].lineage_path.join("/")))
                .then_with(|| procs_a[a.1].source_pid.cmp(&procs_a[b.1].source_pid))
                .then_with(|| procs_b[a.2].source_pid.cmp(&procs_b[b.2].source_pid))
        });

        let mut matched_a_to_b: BTreeMap<usize, (usize, f64, String)> = BTreeMap::new();
        let mut matched_b_indices: HashSet<usize> = HashSet::new();

        for (score, idx_a, idx_b, rationale) in all_candidate_pairs {
            if !matched_a_to_b.contains_key(&idx_a) && !matched_b_indices.contains(&idx_b) {
                matched_a_to_b.insert(idx_a, (idx_b, score, rationale));
                matched_b_indices.insert(idx_b);
            }
        }

        // Step 3: Reconciled items for processes in A
        for (idx_a, p_a) in procs_a.iter().enumerate() {
            let mut evidence_links = BTreeMap::new();
            evidence_links.insert(self.report_a.report_id.clone(), p_a.evidence.clone());

            let mut pids = BTreeMap::new();
            pids.insert(self.report_a.report_id.clone(), p_a.source_pid);

            let mut commands = BTreeMap::new();
            commands.insert(self.report_a.report_id.clone(), p_a.command_line.clone());

            let mut alternatives = Vec::new();

            let (obs_presence, confidence, score, rationale, causal, interpretation) =
                if let Some(&(best_idx_b, best_score, ref best_rat)) = matched_a_to_b.get(&idx_a) {
                    let p_b = &procs_b[best_idx_b];
                    evidence_links.insert(self.report_b.report_id.clone(), p_b.evidence.clone());
                    pids.insert(self.report_b.report_id.clone(), p_b.source_pid);
                    commands.insert(self.report_b.report_id.clone(), p_b.command_line.clone());

                    let mut is_ambiguous = false;
                    for &(c_idx, c_score, ref c_rat) in candidates_by_a[idx_a].iter() {
                        if c_idx == best_idx_b {
                            continue;
                        }
                        if (best_score - c_score).abs() < 0.15 {
                            is_ambiguous = true;
                        }
                        alternatives.push(ProcessAlternativeCandidate {
                            report_b_pid: procs_b[c_idx].source_pid,
                            image: procs_b[c_idx].image_name.clone(),
                            score: c_score,
                            rationale: c_rat.clone(),
                        });
                    }

                    if best_score >= 0.80 && !is_ambiguous {
                        (
                            ObservationPresence::OBSERVED_IN_BOTH,
                            ProcessMatchConfidence::MATCHED,
                            best_score,
                            best_rat.clone(),
                            CausalExplanation::CORROBORATED_EXECUTION,
                            format!(
                                "Corroborated across runs (PID A={}, PID B={}).",
                                p_a.source_pid, p_b.source_pid
                            ),
                        )
                    } else {
                        (
                            ObservationPresence::OBSERVED_IN_BOTH,
                            ProcessMatchConfidence::POSSIBLE_MATCH,
                            best_score,
                            best_rat.clone(),
                            CausalExplanation::UNEXPLAINED,
                            format!(
                                "Plausible candidate alignment (PID A={}, PID B={}) with score {:.2}, but ambiguity across candidate nodes prevents definitive corroboration.",
                                p_a.source_pid, p_b.source_pid, best_score
                            ),
                        )
                    }
                } else {
                    let causal = self.evaluate_process_causality(self.report_b);
                    evidence_links.insert(
                        self.report_b.report_id.clone(),
                        EvidencePointer::missing(
                            &self.report_b.report_id,
                            &format!("Process '{}' unrecorded in Report B", p_a.image_name),
                            &format!("No matching execution node in {}", self.report_b.report_id),
                        ),
                    );

                    (
                        ObservationPresence::OBSERVED_ONLY_IN_A,
                        ProcessMatchConfidence::UNRESOLVED,
                        0.0,
                        "No plausible process candidate identified".to_string(),
                        causal,
                        format!(
                            "Observed only in Report A. Report B does not establish whether '{}' executed.",
                            p_a.image_name
                        ),
                    )
                };

            results.push(ReconciledProcessItem {
                identity_signature: p_a.identity_signature(),
                image_name: p_a.image_name.clone(),
                lineage_path: p_a.lineage_path.clone(),
                observation_presence: obs_presence,
                confidence,
                heuristic_similarity_score: score,
                matching_rationale: rationale,
                causal_explanation: causal,
                epistemic_interpretation: interpretation,
                pids_by_report: pids,
                commands_by_report: commands,
                evidence_links,
                alternative_candidates: alternatives,
            });
        }

        // Step 4: Leftovers in Report B
        for (idx_b, p_b) in procs_b.iter().enumerate() {
            if matched_b_indices.contains(&idx_b) {
                continue;
            }
            let causal = self.evaluate_process_causality(self.report_a);
            let mut evidence_links = BTreeMap::new();
            evidence_links.insert(self.report_b.report_id.clone(), p_b.evidence.clone());
            evidence_links.insert(
                self.report_a.report_id.clone(),
                EvidencePointer::missing(
                    &self.report_a.report_id,
                    &format!("Process '{}' unrecorded in Report A", p_b.image_name),
                    "No matching execution node in Report A",
                ),
            );

            let mut pids = BTreeMap::new();
            pids.insert(self.report_b.report_id.clone(), p_b.source_pid);

            let mut commands = BTreeMap::new();
            commands.insert(self.report_b.report_id.clone(), p_b.command_line.clone());

            results.push(ReconciledProcessItem {
                identity_signature: p_b.identity_signature(),
                image_name: p_b.image_name.clone(),
                lineage_path: p_b.lineage_path.clone(),
                observation_presence: ObservationPresence::OBSERVED_ONLY_IN_B,
                confidence: ProcessMatchConfidence::UNRESOLVED,
                heuristic_similarity_score: 0.0,
                matching_rationale: "Unpaired execution node in Report B".to_string(),
                causal_explanation: causal,
                epistemic_interpretation: format!("Observed only in Report B (PID {}).", p_b.source_pid),
                pids_by_report: pids,
                commands_by_report: commands,
                evidence_links,
                alternative_candidates: Vec::new(),
            });
        }

        results
    }

    fn score_network_pair(&self, na: &NetworkObservation, nb: &NetworkObservation) -> (f64, bool) {
        let snip_a = &na.evidence.raw_snippet;
        let snip_b = &nb.evidence.raw_snippet;

        let mut score: f64 = 0.0;
        let mut has_disc = false;

        let get_sport = |v: &serde_json::Value| {
            v.get("sport").or_else(|| v.get("src_port")).and_then(|x| x.as_i64())
        };
        let get_pid = |v: &serde_json::Value| {
            v.get("pid").or_else(|| v.get("source_pid")).and_then(|x| x.as_i64())
        };
        let get_time = |v: &serde_json::Value| {
            v.get("time").or_else(|| v.get("timestamp")).and_then(|x| x.as_f64())
        };

        if let (Some(sa), Some(sb)) = (get_sport(snip_a), get_sport(snip_b)) {
            has_disc = true;
            if sa == sb {
                score += 0.40;
            } else {
                score -= 0.30;
            }
        }

        if let (Some(pa), Some(pb)) = (get_pid(snip_a), get_pid(snip_b)) {
            has_disc = true;
            if pa == pb {
                score += 0.30;
            } else {
                score -= 0.10;
            }
        }

        if let (Some(ta), Some(tb)) = (get_time(snip_a), get_time(snip_b)) {
            has_disc = true;
            let diff = (ta - tb).abs();
            if diff <= 2.0 {
                score += 0.30;
            } else if diff <= 10.0 {
                score += 0.15;
            }
        }

        if let (Some(ma), Some(mb)) = (
            snip_a.get("method").and_then(|x| x.as_str()),
            snip_b.get("method").and_then(|x| x.as_str()),
        ) {
            has_disc = true;
            if ma.eq_ignore_ascii_case(mb) {
                score += 0.20;
            }
        }

        (score.max(0.0), has_disc)
    }

    fn reconcile_network(&self) -> Vec<ReconciledNetworkItem> {
        let mut results = Vec::new();

        let mut net_a_by_key: BTreeMap<String, Vec<&NetworkObservation>> = BTreeMap::new();
        for n in &self.report_a.network_events {
            net_a_by_key.entry(n.connection_key()).or_default().push(n);
        }

        let mut net_b_by_key: BTreeMap<String, Vec<&NetworkObservation>> = BTreeMap::new();
        for n in &self.report_b.network_events {
            net_b_by_key.entry(n.connection_key()).or_default().push(n);
        }

        let mut all_keys: HashSet<String> = HashSet::new();
        for k in net_a_by_key.keys() {
            all_keys.insert(k.clone());
        }
        for k in net_b_by_key.keys() {
            all_keys.insert(k.clone());
        }
        let mut sorted_keys: Vec<String> = all_keys.into_iter().collect();
        sorted_keys.sort();

        for key in sorted_keys {
            let list_a = net_a_by_key.get(&key).cloned().unwrap_or_default();
            let list_b = net_b_by_key.get(&key).cloned().unwrap_or_default();

            let mut pairs = Vec::new();
            let mut unmatched_a = Vec::new();
            let mut unmatched_b = Vec::new();

            if list_a.len() == 1 && list_b.len() == 1 {
                pairs.push((list_a[0], list_b[0], "DIRECT_IDENTIFIER_MATCH".to_string(), true));
            } else if !list_a.is_empty() && !list_b.is_empty() {
                let mut candidates = Vec::new();
                for (i_a, na) in list_a.iter().enumerate() {
                    for (i_b, nb) in list_b.iter().enumerate() {
                        let (score, has_disc) = self.score_network_pair(na, nb);
                        candidates.push((score, has_disc, i_a, i_b));
                    }
                }

                candidates.sort_by(|x, y| y.0.partial_cmp(&x.0).unwrap_or(std::cmp::Ordering::Equal));

                let mut used_a = HashSet::new();
                let mut used_b = HashSet::new();
                for (score, has_disc, i_a, i_b) in candidates {
                    if used_a.contains(&i_a) || used_b.contains(&i_b) {
                        continue;
                    }
                    used_a.insert(i_a);
                    used_b.insert(i_b);
                    let corr = if has_disc && score > 0.0 {
                        "DIRECT_IDENTIFIER_MATCH".to_string()
                    } else {
                        "AGGREGATE_ENDPOINT_CORROBORATION".to_string()
                    };
                    pairs.push((list_a[i_a], list_b[i_b], corr, has_disc));
                }

                for (i_a, na) in list_a.iter().enumerate() {
                    if !used_a.contains(&i_a) {
                        unmatched_a.push(*na);
                    }
                }
                for (i_b, nb) in list_b.iter().enumerate() {
                    if !used_b.contains(&i_b) {
                        unmatched_b.push(*nb);
                    }
                }
            } else {
                unmatched_a.extend(list_a);
                unmatched_b.extend(list_b);
            }

            for (na, nb, cross_corr, _) in pairs {
                let mut evidence_links = BTreeMap::new();
                evidence_links.insert(self.report_a.report_id.clone(), na.evidence.clone());
                evidence_links.insert(self.report_b.report_id.clone(), nb.evidence.clone());

                let interp = if cross_corr == "DIRECT_IDENTIFIER_MATCH" {
                    format!(
                        "Socket observation '{}' corroborated across both reports with matching connection attributes. Telemetry confirms both environments logged socket activity; does not establish full application-layer handshake completion or identical payload transmission without packet-level capture.",
                        key
                    )
                } else {
                    format!(
                        "Endpoint '{}' logged multiple socket records ({} in {}, {} in {}). Specific stream-to-stream bijection is unestablished due to lack of distinct source ports or timestamps; aggregate traffic to destination is corroborated.",
                        key,
                        net_a_by_key.get(&key).map(|v| v.len()).unwrap_or(0),
                        self.report_a.report_id,
                        net_b_by_key.get(&key).map(|v| v.len()).unwrap_or(0),
                        self.report_b.report_id
                    )
                };

                let (causal, causal_stat) = if cross_corr == "DIRECT_IDENTIFIER_MATCH" {
                    (CausalExplanation::CORROBORATED_EXECUTION, "CORROBORATED_SOCKET".to_string())
                } else {
                    (CausalExplanation::UNEXPLAINED, "AGGREGATE_ENDPOINT_CORROBORATION".to_string())
                };

                results.push(ReconciledNetworkItem {
                    connection_key: key.clone(),
                    observation_presence: ObservationPresence::OBSERVED_IN_BOTH,
                    observation_type: "TELEMETRY_LOGGED_SOCKET_RECORD".to_string(),
                    connection_state: "SOCKET_RECORD_LOGGED".to_string(),
                    policy_decision: None,
                    cross_report_correlation: cross_corr,
                    causal_status: causal_stat,
                    causal_explanation: causal,
                    policy_decision_record: None,
                    policy_decision_evidence: None,
                    epistemic_interpretation: interp,
                    observed_in_reports: vec![self.report_a.report_id.clone(), self.report_b.report_id.clone()],
                    unobserved_in_reports: Vec::new(),
                    evidence_links,
                });
            }

            for na in unmatched_a {
                let mut evidence_links = BTreeMap::new();
                evidence_links.insert(self.report_a.report_id.clone(), na.evidence.clone());

                let (causal, pol_rec, pol_ptr, interp, x_corr, c_stat, c_state) =
                    self.evaluate_network_causality(na, self.report_b);

                evidence_links.insert(
                    self.report_b.report_id.clone(),
                    EvidencePointer::missing(
                        &self.report_b.report_id,
                        &format!("Connection {} unrecorded in Report B", key),
                        pol_rec.as_deref().unwrap_or(&interp),
                    ),
                );

                results.push(ReconciledNetworkItem {
                    connection_key: key.clone(),
                    observation_presence: ObservationPresence::OBSERVED_ONLY_IN_A,
                    observation_type: "TELEMETRY_LOGGED_SOCKET_RECORD".to_string(),
                    connection_state: c_state,
                    policy_decision: pol_rec.clone(),
                    cross_report_correlation: x_corr,
                    causal_status: c_stat,
                    causal_explanation: causal,
                    policy_decision_record: pol_rec,
                    policy_decision_evidence: pol_ptr,
                    epistemic_interpretation: interp,
                    observed_in_reports: vec![self.report_a.report_id.clone()],
                    unobserved_in_reports: vec![self.report_b.report_id.clone()],
                    evidence_links,
                });
            }

            for nb in unmatched_b {
                let mut evidence_links = BTreeMap::new();
                evidence_links.insert(self.report_b.report_id.clone(), nb.evidence.clone());

                let (causal, pol_rec, pol_ptr, interp, x_corr, c_stat, c_state) =
                    self.evaluate_network_causality(nb, self.report_a);

                evidence_links.insert(
                    self.report_a.report_id.clone(),
                    EvidencePointer::missing(
                        &self.report_a.report_id,
                        &format!("Connection {} unrecorded in Report A", key),
                        pol_rec.as_deref().unwrap_or(&interp),
                    ),
                );

                results.push(ReconciledNetworkItem {
                    connection_key: key.clone(),
                    observation_presence: ObservationPresence::OBSERVED_ONLY_IN_B,
                    observation_type: "TELEMETRY_LOGGED_SOCKET_RECORD".to_string(),
                    connection_state: c_state,
                    policy_decision: pol_rec.clone(),
                    cross_report_correlation: x_corr,
                    causal_status: c_stat,
                    causal_explanation: causal,
                    policy_decision_record: pol_rec,
                    policy_decision_evidence: pol_ptr,
                    epistemic_interpretation: interp,
                    observed_in_reports: vec![self.report_b.report_id.clone()],
                    unobserved_in_reports: vec![self.report_a.report_id.clone()],
                    evidence_links,
                });
            }
        }

        results
    }

    fn evaluate_network_causality(
        &self,
        event: &NetworkObservation,
        target_report: &NormalizedReport,
    ) -> (
        CausalExplanation,
        Option<String>,
        Option<EvidencePointer>,
        String,
        String,
        String,
        String,
    ) {
        // Targeted egress policy check
        for lim in &target_report.limitations {
            if lim.category == "EGRESS_POLICY" {
                if let Some(port) = event.port {
                    let port_str = port.to_string();
                    let pattern_match = lim
                        .target_pattern
                        .as_deref()
                        .is_some_and(|pat| pat.contains(&format!("port:{}", port)));
                    let desc_match = lim.description.contains(&port_str);

                    if pattern_match || desc_match {
                        let policy_text =
                            format!("{} [{}]: {}", target_report.sandbox_name, lim.code, lim.description);
                        let interpretation = format!(
                            "TCP observation present in {}; {} contains a general egress-policy warning mentioning port {}; relationship between the records is not established.",
                            event.report_id, target_report.sandbox_name, port
                        );
                        return (
                            CausalExplanation::POLICY_DECISION_RECORDED,
                            Some(policy_text),
                            lim.evidence.clone(),
                            interpretation,
                            "CONTEXTUAL_SIMILARITY_ONLY".to_string(),
                            "PLAUSIBLE_HYPOTHESIS".to_string(),
                            "UNKNOWN".to_string(),
                        );
                    }
                }
            }
        }

        // General timeout check
        for lim in &target_report.limitations {
            if lim.category == "TIMEOUT" {
                let interpretation = format!(
                    "TCP observation present in source report; absent from {} which timed out at {}s. Relationship between timeout and omission is plausible but not confirmed.",
                    target_report.sandbox_name,
                    target_report.duration_seconds.unwrap_or(0)
                );
                return (
                    CausalExplanation::POTENTIAL_ENVIRONMENT_LIMITATION,
                    None,
                    lim.evidence.clone(),
                    interpretation,
                    "CONTEXTUAL_SIMILARITY_ONLY".to_string(),
                    "PLAUSIBLE_HYPOTHESIS".to_string(),
                    "UNKNOWN".to_string(),
                );
            }
        }

        let interpretation = format!(
            "Observed in active run; absent from {} telemetry. No sandbox warning correlates with omission; causes remain unverified.",
            target_report.sandbox_name
        );
        (
            CausalExplanation::UNEXPLAINED,
            None,
            None,
            interpretation,
            "UNLINKED".to_string(),
            "UNKNOWN".to_string(),
            "UNKNOWN".to_string(),
        )
    }

    fn evaluate_process_causality(&self, target_report: &NormalizedReport) -> CausalExplanation {
        for lim in &target_report.limitations {
            if lim.category == "TIMEOUT" || lim.category == "ANTI_EVASION" || lim.category == "CRASH" {
                return CausalExplanation::POTENTIAL_ENVIRONMENT_LIMITATION;
            }
        }
        CausalExplanation::UNEXPLAINED
    }

    fn evaluate_file_causality(&self, target_report: &NormalizedReport) -> CausalExplanation {
        for lim in &target_report.limitations {
            if lim.category == "TIMEOUT" || lim.category == "DISK_QUOTA" || lim.category == "DROP_LIMIT" {
                return CausalExplanation::POTENTIAL_ENVIRONMENT_LIMITATION;
            }
        }
        CausalExplanation::UNEXPLAINED
    }
}

