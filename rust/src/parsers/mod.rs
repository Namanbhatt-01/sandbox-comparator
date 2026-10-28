pub mod cape;
pub mod falcon;

use crate::models::NormalizedReport;
use serde_json::Value;

pub fn detect_schema(raw: &Value) -> &'static str {
    let empty_obj = serde_json::Map::new();
    let root = raw.as_object().unwrap_or(&empty_obj);

    // Falcon-like signatures
    if root.contains_key("submission_info") {
        return "falcon";
    }
    if let Some(exec) = root.get("execution").and_then(|v| v.as_object()) {
        if exec.contains_key("process_tree") {
            return "falcon";
        }
    }

    // CAPE / Cuckoo signatures
    if root.contains_key("info") || root.contains_key("report_metadata") {
        return "cape";
    }
    if root.contains_key("behavior") || root.contains_key("target") || root.contains_key("dropped") {
        return "cape";
    }

    "unknown"
}

pub fn parse_auto_report(raw: &Value, report_id: &str) -> NormalizedReport {
    let schema = detect_schema(raw);
    if schema == "falcon" {
        falcon::parse_falcon_report(raw, report_id)
    } else {
        let mut norm = cape::parse_cape_report(raw, report_id);
        if schema == "unknown" {
            norm.parser_warnings.push(
                "Schema could not be conclusively identified; defaulted to CAPE/Cuckoo defensive parser."
                    .to_string(),
            );
        }
        norm
    }
}

