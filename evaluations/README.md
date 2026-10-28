# Practitioner Evaluation & Clinical Pilot Protocol (Protocol v5.1)

This directory houses the formal scientific methodology, participant interview protocols, pilot packets, rehearsal findings, and empirical evidence capture records for the **Evidence-Aware Sandbox Comparator**.

---

## Directory Inventory

| Document | Purpose |
| :--- | :--- |
| [**`PILOT_PACKET.md`**](PILOT_PACKET.md) | **Authoritative Protocol v5.1**: Complete pre-pilot briefing, scenario specifications, cryptographic ledger, scoring rubrics, and data redaction rules. |
| [**`INTERVIEW_PROTOCOL.md`**](INTERVIEW_PROTOCOL.md) | **Standardized Semi-Structured Interview Guide**: Neutral 3-step Phase 4 interview protocol preventing conversational leading and demand characteristics. |
| [**`PILOT_EXECUTION_KIT.md`**](PILOT_EXECUTION_KIT.md) | **Facilitator Runbook**: Step-by-step operational checklist for session setup, terminal timing prompts, and real-time observation capture. |
| [**`RECRUITMENT_TRACKER.md`**](RECRUITMENT_TRACKER.md) | **Practitioner Cohort Tracker**: Anonymized tracking of $N=5\text{ to }8$ senior malware analysts across commercial SOCs, CSIRTs, and threat intelligence pods. |
| [**`REHEARSAL_FINDINGS_AND_LOCK_RECORD.md`**](REHEARSAL_FINDINGS_AND_LOCK_RECORD.md) | **Pre-Pilot Rehearsal Record**: Documentation of dry-runs (R1/R2), identified failure modes, and formal version-lock decisions for Protocol v5.1. |
| [**`RESULT_REPORT.md`**](RESULT_REPORT.md) | **Evaluation Findings & Gate Sign-Off**: Verification records across Gate 1 (Baseline Integrity), Gate 2 (Protocol Integrity), and Gate 3 (Empirical Calibration). |
| [**`MILESTONE_2_PLAN.md`**](MILESTONE_2_PLAN.md) | **Milestone Execution Architecture**: High-level execution roadmap, timeline, and audit milestones. |
| [**`evidence_capture/`**](evidence_capture/) | **Participant Evidence Sheets**: Standardized evaluation templates and completed evidence capture records (`P1` through `P8`). |

---

## Study Design Summary

- **Study Type**: Counterbalanced within-subjects randomized block crossover design ($N=5\text{ to }8$).
- **Conditions**: Condition A (Baseline unstructured manual JSON diffing) vs. Condition B (Evidence-Aware Sandbox Comparator).
- **Primary Metrics**:
  1. Analytical task completion time (seconds).
  2. Uncorroborated claim rate (UCR).
  3. Ground-truth discrepancy detection accuracy.
  4. Provenance auditability score (RFC 6901 verification speed).
