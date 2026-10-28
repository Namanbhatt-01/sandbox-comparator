# Practitioner Interview Protocol: Evidence-Aware Malware Comparison Validation (Milestone 5)

## 1. Study Objective & Core Principles
**Target Audience**: 5 to 8 senior cybersecurity practitioners who regularly analyze malware or reconcile sandbox reports (DFIR incident responders, reverse engineers, SOC Tier 3 escalation leads, threat intelligence researchers).

**Primary Research Objective**:
Measure whether cross-sandbox and cross-run telemetry reconciliation is an acute, high-frequency manual bottleneck that justifies dedicated tooling, or whether existing workflows (manual multi-tab inspection, single-vendor EDR telemetry, custom scripts) are already "good enough."

**Key Rules of Engagement**:
1. **Anchor in Recent Reality**: Never ask speculative or hypothetical questions (*"Would you like a tool that does X?"*). Anchor the interview in their **most recent real comparison** (*"Walk me through the last time you analyzed a sample in more than one sandbox or across multiple runs"*).
2. **Workflow-First Sequencing**: Ask about the analyst's existing workflow and friction first. Show the prototype only in Phase 4 after capturing their baseline reality.
3. **No Steering or Feature Promotion**: Do not lead with claimed benefits or attempt to persuade. Treat *"our current manual workflow is good enough"* as a completely valid, valuable research finding.
4. **Confidentiality by Design**: Never ask participants to disclose confidential client names, internal IP addresses, or sensitive malware specifics. Request sanitized, generic descriptions of the workflow, telemetry types, and decision steps.
5. **Safe Data Protocol**: Any discussion of testing organizational reports must adhere strictly to the Data Handling & Redaction Protocol (Section 7 of `PILOT_PACKET.md`).

---

## 2. Participant Screening & Profiling (5–8 Candidates)

| Target Profile ID | Target Role | Primary Workflow | Qualifying Experience Required |
| :--- | :--- | :--- | :--- |
| **P1** | Senior DFIR Consultant | Incident containment & malware triage | Ran a multi-stage sample through 2+ sandboxes in the last 30 days |
| **P2** | Threat Intelligence Analyst | Campaign attribution & IOC extraction | Compares repeated runs across configurations/versions |
| **P3** | SOC Tier 3 / Detection Engineer | Detection rule authoring (Sigma/YARA) | Validates execution artifacts against sandboxed samples |
| **P4** | Dedicated Malware Reverse Engineer | Behavioral verification & unpacking | Dissects evasion techniques and hook-drop anomalies |
| **P5** | MDR Operations Lead | High-throughput alert escalation | Reviews multi-sandbox telemetry attached to alerts |
| **P6** | Enterprise Incident Commander | Post-mortem root cause analysis | Reconciles discrepancies between internal and external intel |

### Screening Questions:
1. *"In the last 30 days, have you analyzed a suspicious file or binary where you had to consult more than one sandbox report or run the sample more than once?"* **(Must be Yes)**
2. *"Which specific tools or platforms did you use?"* *(Expected: CAPE, Any.Run, Joe Sandbox, Falcon Sandbox, VirusTotal Enterprise, Hatching Triage)*
3. *"Did you encounter conflicting or missing observations between runs?"* **(Must cite a concrete, sanitized example)**

*Cohort Transparency Note*: If 5–8 senior analysts cannot be recruited within the evaluation window, recruit a clearly labelled exploratory cohort (e.g. generalist security analysts) and explicitly document the cohort limitations rather than silently diluting qualification standards.

---

## 3. Structured Retrospective Interview Script (45 Minutes)

### Phase 1: Grounding in the Most Recent Real Incident (10 mins)
*Goal: Elicit concrete factual history, not idealized opinions.*

- *"Think back to the most recent suspicious file where you looked at multiple sandbox runs or reports. Without disclosing confidential client names or sensitive specifics, what was the nature of the sample, and why did you submit it to more than one environment?"*
- *"Which specific sandboxes or tools did you inspect?"*
- *"What specific question were you trying to answer? (e.g., Did it drop a secondary payload? What network destinations did it contact? What persistence keys did it write?)"*

### Phase 2: Workflow Reconstruction & Friction Mapping (15 mins)
*Goal: Reconstruct step-by-step how the analyst performed the comparison manually.*

- *"When you had Report A and Report B in front of you, how did you actually compare them? (e.g., two browser windows side-by-side, copying hashes into a text editor, using `jq`/Python, or relying on memory)?"*
- *"Did you encounter a dropped file with different names in the two reports? How did you verify whether it was the same payload or a different binary?"*
- *"Did the process tree differ between runs? How did you correlate which child process executed which command when process IDs (PIDs) changed?"*
- *"Did one report show network traffic or persistence that the other report omitted? How did you investigate why it was missing?"*
  - *Probe*: *"What explanations, if any, did you investigate for the difference between the reports? What evidence did you find for each?"*
  - *Follow-up (Neutral, only if unprompted)*: *"Did environment constraints, execution timeouts, or sandbox policy warnings play any role in your assessment?"*
- *"Approximately how many minutes did you spend cross-checking these reports before you felt confident writing your report or alert ticket?"*

### Phase 3: Testing Against Current State-of-the-Art Tools (10 mins)
*Goal: Understand the strengths and limitations of existing tools without disparaging them.*

- *"If you used VirusTotal or a multi-engine console in this investigation, what did its merged summary provide, and what did you still need to inspect elsewhere?"*
  - *Probe*: *"Did you click into individual sandbox tabs (e.g., CAPE vs Falcon vs Zenbox)? What specific data were you cross-referencing between them?"*
- *"Do you use any automated diff tools, scripts, or spreadsheets for this today? Where do they break when comparing different sandbox schemas?"*

### Phase 4: Prototype Walkthrough & Reality Check (10 mins)
*Goal: Present the evidence-aware reconciliation output, strictly preserving the boundary between unaided analyst comprehension and prompted guided insights.*

#### Methodological Phase Separation:
- **Phase 4A (Unaided Inspection — Prior to Walkthrough)**:
  - Capture initial reaction, spontaneous interpretation, unprompted hash discovery, and unaided confusion before any feature explanations.
  - *"Here is the output from our prototype comparator running on a multi-stage sample analyzed in two environments. Take a minute to review it. What does this diff tell you, and what conclusions would you draw from it?"*
  - *(Evaluator Rule: Explicitly record whether insights were reached unaided, from the output alone, or only after subsequent explanation. Do NOT count a correct conclusion reached after guided explanation as evidence that the prototype independently improved analytical accuracy).*

- **Phase 4B (Guided Walkthrough — Comprehension & Usability Observation)**:
  - Walk through key reconciliation boundaries and observe comprehension, confusion, evidence verification, and usability:
    - *"Notice that `update_payload.exe` and `staged_runner.bin` are matched by reported SHA-256 metadata with explicit source-resolvable RFC 6901 JSON pointers (`/behavior/dropped/0` vs `/execution/created_files/0`)."*
    - *"Notice the network reconciliation table: Report A contains a TCP observation for `203.0.113.88:8080`. Report B contains a general egress-policy warning mentioning port 8080. The output records: `connection_state = UNKNOWN`, `cross_report_correlation = CONTEXTUAL_SIMILARITY_ONLY`, and explicitly states: 'relationship between the records is not established; evidence does not establish whether a TCP handshake completed or whether destination was C2 infrastructure.' "*
    - *"Notice the process matcher scores node similarity using a multi-factor heuristic (image name, argument Jaccard, lineage depth) instead of relying on transient PIDs."*

- **Phase 4C (Task-Based Debrief & Reality Check — Post-Walkthrough)**:
  - Capture perceived usefulness, operational friction, ambiguities, and follow-up interest:
    - *"What, if anything, would you do differently after seeing this output?"*
    - *"Which conclusions can you support directly from the evidence shown?"*
    - *"What would you still need to verify in the raw reports?"*
    - *"What, if anything, was less useful or more confusing than your usual workflow?"*
    - *"Where does this output feel ambiguous or risk misleading you?"*
    - *"Is your current manual comparison process already good enough that adding a comparator CLI would feel like unnecessary overhead?"*

---

## 4. Tightened 5-Dimension Evaluation Gate

Each completed interview is scored across five objective dimensions:

| Dimension | Evaluation Criteria | Red Flag (Fail) | Green Flag (Pass) |
| :--- | :--- | :--- | :--- |
| **1. Frequency** | How often does cross-report discrepancy cause friction? | Less than once a month; single sandbox summary is sufficient. | Multiple times weekly; cross-checking is a recurring bottleneck. |
| **2. Cost** | Time spent manually comparing discordant reports. | < 5 minutes per sample; friction is negligible. | 20–45+ minutes per sample across tabs and raw logs. |
| **3. Alternatives** | Adequacy of current tools, scripts, or workarounds. | Existing portal summaries or internal scripts solve 90%+ of needs. | Spreadsheets/manual text diffs are fragile and fail across schemas. |
| **4. Technical Value** | Does the output improve correctness and prevent false leaps? | *"I don't care why an event is missing; if it's not logged, I ignore it."* | *"Crucial: distinguishing unrecorded from non-occurrence prevents bad Sigma rules."* |
| **5. Adoption Evidence** | Concrete willingness to participate in follow-up trial. | Polite verbal praise; declines follow-up or testing on real telemetry. | **Agrees to review 2–3 sanitized organizational reports under our safe data protocol.** *(Note: Evaluated as a concrete follow-up commitment—not as proof of purchasing intent, commercial adoption, or product-market fit).* |

### Overall Gate Decision Rules:
- **Advance Toward Specialized Workflow Tool**: $\ge 5$ of 8 practitioners pass Dimensions 1–4, AND at least **2 practitioners commit to reviewing sanitized organizational reports under the Data Handling Protocol**.
- **Package as Open-Source Library**: Practitioners confirm technical value and forensic accuracy, but state organizational procurement or budget constraints prevent adopting commercial point solutions.
- **Shelve Project**: $\ge 4$ practitioners conclude that VirusTotal's merged view or standard single-engine reports are already adequate for their operational decision-making.
