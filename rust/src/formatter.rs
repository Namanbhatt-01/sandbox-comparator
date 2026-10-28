use crate::models::ComparisonReport;
use crate::provenance::truncate_utf8;

pub fn format_markdown_report(comparison: &ComparisonReport) -> String {
    let mut lines = Vec::new();
    lines.push("# Evidence-Aware Sandbox Comparison Report".to_string());
    lines.push(format!("**Target Sample SHA-256**: `{}`\n", comparison.sample_sha256));

    let meta_a = comparison.provenance_metadata.get(&comparison.report_a_id);
    let meta_b = comparison.provenance_metadata.get(&comparison.report_b_id);

    let sandbox_a = meta_a
        .and_then(|m| m.get("sandbox"))
        .and_then(|v| v.as_str())
        .unwrap_or("CAPE Sandbox");
    let prov_a = meta_a
        .and_then(|m| m.get("provenance_type"))
        .and_then(|v| v.as_str())
        .unwrap_or("DOCUMENTED_VENDOR_FORMAT");

    let sandbox_b = meta_b
        .and_then(|m| m.get("sandbox"))
        .and_then(|v| v.as_str())
        .unwrap_or("Falcon Sandbox Cloud Engine");
    let prov_b = meta_b
        .and_then(|m| m.get("provenance_type"))
        .and_then(|v| v.as_str())
        .unwrap_or("SYNTHETIC_APPROXIMATION");

    lines.push(format!(
        "- **Report A**: `{}` ({}) — Provenance: `{}`",
        comparison.report_a_id, sandbox_a, prov_a
    ));
    lines.push(format!(
        "- **Report B**: `{}` ({}) — Provenance: `{}`\n",
        comparison.report_b_id, sandbox_b, prov_b
    ));

    // 1. Files
    lines.push("## 1. Dropped Files Reconciliation (Disentangled Presence & Explanation)".to_string());
    lines.push(
        "| SHA-256 | Observation Presence | Causal Explanation | Filename in A | Filename in B | RFC 6901 Evidence Pointers |".to_string(),
    );
    lines.push("| :--- | :--- | :--- | :--- | :--- | :--- |".to_string());

    for f in &comparison.reconciled_files {
        let name_a = f
            .filenames_by_report
            .get(&comparison.report_a_id)
            .map(|s| s.as_str())
            .unwrap_or("*(not recorded)*");
        let name_b = f
            .filenames_by_report
            .get(&comparison.report_b_id)
            .map(|s| s.as_str())
            .unwrap_or("*(not recorded)*");

        let ptr_a = f.evidence_links.get(&comparison.report_a_id);
        let ptr_b = f.evidence_links.get(&comparison.report_b_id);

        let mut ptrs = Vec::new();
        if let Some(pa) = ptr_a {
            if pa.is_available {
                ptrs.push(format!("A: `{}`", pa.json_pointer));
            }
        }
        if let Some(pb) = ptr_b {
            if pb.is_available {
                ptrs.push(format!("B: `{}`", pb.json_pointer));
            }
        }

        let malformed_flag = if f.is_malformed_hash { " [MALFORMED HASH]" } else { "" };
        let hash_prefix = truncate_utf8(&f.sha256, 12);

        lines.push(format!(
            "| `{}`...{} | `{}` | `{}` | `{}` | `{}` | {} |",
            hash_prefix,
            malformed_flag,
            f.observation_presence.as_str(),
            f.causal_explanation.as_str(),
            name_a,
            name_b,
            ptrs.join(", ")
        ));
    }

    lines.push("\n**File Epistemic Interpretations**:".to_string());
    for f in &comparison.reconciled_files {
        let hash_prefix = truncate_utf8(&f.sha256, 16);
        lines.push(format!("- **`{}...`**: {}", hash_prefix, f.epistemic_interpretation));
    }

    // 2. Processes
    lines.push("\n## 2. Process Tree Reconciliation (Calibrated Heuristic Scoring)".to_string());
    lines.push(
        "| Semantic Process Node | Confidence | Heuristic Score | Presence | Lineage Depth | PID in A | PID in B | RFC 6901 Pointer |".to_string(),
    );
    lines.push("| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |".to_string());

    for p in &comparison.reconciled_processes {
        let pid_a = p
            .pids_by_report
            .get(&comparison.report_a_id)
            .map(|id| id.to_string())
            .unwrap_or_else(|| "N/A".to_string());
        let pid_b = p
            .pids_by_report
            .get(&comparison.report_b_id)
            .map(|id| id.to_string())
            .unwrap_or_else(|| "N/A".to_string());

        let ptr_a = p.evidence_links.get(&comparison.report_a_id);
        let ptr_b = p.evidence_links.get(&comparison.report_b_id);

        let mut ptrs = Vec::new();
        if let Some(pa) = ptr_a {
            if pa.is_available {
                ptrs.push(format!("A: `{}`", pa.json_pointer));
            }
        }
        if let Some(pb) = ptr_b {
            if pb.is_available {
                ptrs.push(format!("B: `{}`", pb.json_pointer));
            }
        }

        lines.push(format!(
            "| `{}` | `{}` | {:.2} | `{}` | {} | `{}` | `{}` | {} |",
            p.image_name,
            p.confidence.as_str(),
            p.heuristic_similarity_score,
            p.observation_presence.as_str(),
            p.lineage_path.len(),
            pid_a,
            pid_b,
            ptrs.join(", ")
        ));
    }

    lines.push("\n**Process Lineage Detail & Heuristic Rationale**:".to_string());
    for p in &comparison.reconciled_processes {
        lines.push(format!(
            "- `{}`: {} | *Interpretation*: {}",
            p.image_name, p.matching_rationale, p.epistemic_interpretation
        ));
    }

    // 3. Network
    lines.push("\n## 3. Network Reconciliation (Disentangled Presence & Policy Decisions)".to_string());
    lines.push(
        "| Connection Key | Observation Type | State | Presence | Causal Status | Policy Record / Context |".to_string(),
    );
    lines.push("| :--- | :--- | :--- | :--- | :--- | :--- |".to_string());

    for n in &comparison.reconciled_network {
        let policy_str = n
            .policy_decision_record
            .as_deref()
            .unwrap_or("*(None recorded)*");

        lines.push(format!(
            "| `{}` | `{}` | `{}` | `{}` | `{}` | {} |",
            n.connection_key,
            n.observation_type,
            n.connection_state,
            n.observation_presence.as_str(),
            n.causal_status,
            policy_str
        ));
    }

    lines.push("\n**Network Epistemic Interpretations**:".to_string());
    for n in &comparison.reconciled_network {
        lines.push(format!(
            "- **`{}`** ({}): {}",
            n.connection_key, n.cross_report_correlation, n.epistemic_interpretation
        ));
    }

    // 4. Limitations
    lines.push("\n## 4. Collection Limitations & Schema Coverage".to_string());
    let lims_a = comparison.collection_limitations.get(&comparison.report_a_id);
    lines.push(format!("### Limitations recorded by `{}`:", comparison.report_a_id));
    if let Some(la) = lims_a {
        if la.is_empty() {
            lines.push("- *(No collection warnings recorded)*".to_string());
        } else {
            for l in la {
                lines.push(format!("- **[{}]** ({}): {}", l.code, l.category, l.description));
            }
        }
    } else {
        lines.push("- *(No collection warnings recorded)*".to_string());
    }

    let lims_b = comparison.collection_limitations.get(&comparison.report_b_id);
    lines.push(format!("### Limitations recorded by `{}`:", comparison.report_b_id));
    if let Some(lb) = lims_b {
        if lb.is_empty() {
            lines.push("- *(No collection warnings recorded)*".to_string());
        } else {
            for l in lb {
                lines.push(format!("- **[{}]** ({}): {}", l.code, l.category, l.description));
            }
        }
    } else {
        lines.push("- *(No collection warnings recorded)*".to_string());
    }

    lines.join("\n")
}

