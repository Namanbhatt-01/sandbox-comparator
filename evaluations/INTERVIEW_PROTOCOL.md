# Practitioner Interview Protocol: Evidence-Aware Malware Comparison Validation (Milestone 5)

**Protocol Version**: v5.1 (Locked post-R1/R2 Calibration)  
**Technology Baseline**: Commit `dfec537434...` (Monorepo) / `fa12a78045...` (Standalone)  
**Session Time Budget**: Exactly 60 minutes  
**Target Main Cohort**: 5 to 8 senior cybersecurity practitioners (P1–P8)  

---

## 1. Study Objective & Core Principles

**Target Audience**: 5 to 8 senior cybersecurity practitioners who regularly analyze malware or reconcile sandbox reports (DFIR incident responders, reverse engineers, SOC Tier 3 escalation leads, threat intelligence researchers).

**Primary Research Objective**:  
Measure whether cross-sandbox and cross-run telemetry reconciliation is an acute, high-frequency manual bottleneck that justifies dedicated tooling, or whether existing workflows (manual multi-tab inspection, single-vendor EDR telemetry, custom scripts) are already "good enough."

**Key Rules of Engagement**:
1. **Anchor in Recent Reality**: Never ask speculative or hypothetical questions (*"Would you like a tool that does X?"*). Anchor the interview in their **most recent real comparison** (*"Walk me through the last time you analyzed a sample in more than one sandbox or across multiple runs"*).
2. **Workflow-First Sequencing**: Ask about the analyst's existing workflow and friction first. Administer experimental tasks before any feature explanation.
3. **No Steering or Feature Promotion**: Do not lead with claimed benefits or attempt to persuade. Treat *"our current manual workflow is good enough"* as a completely valid, valuable research finding.
4. **Confidentiality by Design**: Never ask participants to disclose confidential client names, internal IP addresses, or sensitive malware specifics. Request sanitized, generic descriptions of the workflow, telemetry types, and decision steps.
5. **Safe Data Protocol**: Any discussion of testing organizational reports must adhere strictly to the Data Handling & Redaction Protocol (Section 7 of `PILOT_PACKET.md`).

---

## 2. Participant Screening & Profiling (P1–P8)

Candidates are screened from the decoupled candidate pool (C01–C14) against five explicit inquiries. Only qualified and consented candidates are sequentially assigned to locked Study IDs P1–P8.

| Target Profile ID | Target Role | Primary Workflow | Qualifying Experience Required | Locked Crossover Allocation |
| :--- | :--- | :--- | :--- | :--- |
| **P1** | Senior DFIR Consultant | Incident containment & triage | Multi-stage sample in 2+ sandboxes in last 30 days | **Group B** (Task 1: SY-Baseline, Task 2: SX-Prototype) |
| **P2** | Threat Intelligence Analyst | Campaign attribution & IOC extraction | Compares repeated runs across configs/versions | **Group D** (Task 1: SY-Prototype, Task 2: SX-Baseline) |
| **P3** | SOC Tier 3 / Escalation Lead | High-throughput alert escalation | Validates execution artifacts against sandboxed samples | **Group A** (Task 1: SX-Baseline, Task 2: SY-Prototype) |
| **P4** | Dedicated Malware Reverse Engineer | Behavioral unpacking & verification | Dissects evasion techniques and hook anomalies | **Group C** (Task 1: SX-Prototype, Task 2: SY-Baseline) |
| **P5** | Enterprise Incident Commander | Post-mortem root cause analysis | Reconciles conflicting internal/external telemetry | **Group C** (Task 1: SX-Prototype, Task 2: SY-Baseline) |
| **P6** | Senior Detection Engineer | Detection rule authoring (Sigma/YARA) | Verifies process trees and socket omissions across runs | **Group A** (Task 1: SX-Baseline, Task 2: SY-Prototype) |
| **P7** | Lead Threat Hunter | Proactive adversary infrastructure tracking | Cross-checks multi-engine behavioral reports | **Group D** (Task 1: SY-Prototype, Task 2: SX-Baseline) |
| **P8** | Principal DFIR Consultant | Complex multi-stage dropper containment | Compares divergent guest-execution artifacts | **Group B** (Task 1: SY-Baseline, Task 2: SX-Prototype) |

### Authoritative 5-Question Screening Inquiries:
1. **Q1 (Recent Comparison)**: *"In the last 30 days, have you analyzed a suspicious file or binary where you had to consult more than one sandbox report or run the sample more than once?"* **(Must be Yes)**
2. **Q2 (Tools Actually Used)**: *"Which specific tools or platforms did you use?"* *(Expected: CAPE, Any.Run, Joe Sandbox, Falcon Sandbox, VirusTotal Enterprise, Hatching Triage)*
3. **Q3 (Concrete Discrepancy)**: *"Did you encounter conflicting or missing observations between runs?"* **(Must cite a concrete, sanitized example of file, process, or network divergence)**
4. **Q4 (Role & Experience)**: *"What is your current primary role and professional focus in security analysis?"* **(Must confirm DFIR, RE, Threat Intel, or Senior SOC/Detection role)**
5. **Q5 (Availability)**: *"Are you available for a 60-minute recorded/noted evaluation session with controlled task scenarios?"* **(Must confirm full 60-minute uninterrupted availability)**

*Cohort Transparency Note*: If 5–8 senior analysts cannot be recruited within the evaluation window, recruit a clearly labelled exploratory cohort (e.g. generalist security analysts) and explicitly document cohort limitations rather than silently diluting qualification standards.

---

## 3. Standardized 60-Minute Interview & Evaluation Script

```
+---------------------------------------------------------------------------------------------------+
| 60-MINUTE SESSION TIME BUDGET                                                                     |
+-------------------+-----------------+-------------------------------------------------------------+
| Time Window       | Duration        | Phase & Operational Activity                                |
+-------------------+-----------------+-------------------------------------------------------------+
| 00:00 – 00:05     | 5 minutes       | Phase 0: Welcome, Privacy Disclosure & Voluntary Consent    |
| 00:05 – 00:20     | 15 minutes      | Phases 1–3: Retrospective Grounding in Most Recent Workflow |
| 00:20 – 00:33     | 13 minutes      | Task 1 Execution (12 min / 720s cap + 1 min transition)     |
| 00:33 – 00:46     | 13 minutes      | Task 2 Execution (12 min / 720s cap + 1 min transition)     |
| 00:46 – 00:51     | 5 minutes       | Phase 4B: Guided Walkthrough & Provenance Inspection        |
| 00:51 – 01:00     | 9 minutes       | Phase 4C: Structured Debrief, Usability & Safe Trial Follow-up|
+-------------------+-----------------+-------------------------------------------------------------+
```

### Phase 0: Welcome, Privacy Disclosure & Voluntary Consent (5 mins)
- Explain exploratory research purpose (methodological inquiry into cross-report reconciliation, not a commercial product pitch).
- Reaffirm strict data boundaries: no client names, internal IPs, or confidential binaries needed.
- Obtain voluntary consent; explain anonymous Study ID coding (P1–P8).

### Phase 1: Grounding in the Most Recent Real Incident (5 mins)
*Goal: Elicit concrete factual history, not idealized opinions.*
- *"Think back to the most recent suspicious file where you looked at multiple sandbox runs or reports. Without disclosing confidential client names or sensitive specifics, what was the nature of the sample, and why did you submit it to more than one environment?"*
- *"Which specific sandboxes or tools did you inspect?"*
- *"What specific question were you trying to answer? (e.g., Did it drop a secondary payload? What network destinations did it contact? What persistence keys did it write?)"*

### Phase 2: Workflow Reconstruction & Friction Mapping (5 mins)
*Goal: Reconstruct step-by-step how the analyst performed the comparison manually.*
- *"When you had Report A and Report B in front of you, how did you actually compare them? (e.g., two browser windows side-by-side, copying hashes into a text editor, using `jq`/Python, or relying on memory)?"*
- *"Did you encounter a dropped file with different names in the two reports? How did you verify whether it was the same payload or a different binary?"*
- *"Did the process tree differ between runs? How did you correlate which child process executed which command when process IDs (PIDs) changed?"*
- *"Did one report show network traffic or persistence that the other report omitted? How did you investigate why it was missing?"*
  - *Probe*: *"What explanations, if any, did you investigate for the difference between the reports? What evidence did you find for each?"*
  - *Follow-up (Neutral, only if unprompted)*: *"Did environment constraints, execution timeouts, or sandbox policy warnings play any role in your assessment?"*
- *"Approximately how many minutes did you spend cross-checking these reports before you felt confident writing your report or alert ticket?"*

### Phase 3: Testing Against Current State-of-the-Art Tools (5 mins)
*Goal: Understand the strengths and limitations of existing tools without disparaging them.*
- *"If you used VirusTotal or a multi-engine console in this investigation, what did its merged summary provide, and what did you still need to inspect elsewhere?"*
  - *Probe*: *"Did you click into individual sandbox tabs (e.g., CAPE vs Falcon vs Zenbox)? What specific data were you cross-referencing between them?"*
- *"Do you use any automated diff tools, scripts, or spreadsheets for this today? Where do they break when comparing different sandbox schemas?"*

---

### Phase 4: Controlled Crossover Task Execution & Usability Reality Check (40 mins)

*Goal: Administer assigned crossover tasks and debrief, strictly preserving the boundary between unaided analyst comprehension and prompted guided insights.*

#### Task 1 Execution (13 mins: 12 min / 720s cap + 1 min transition)
1. **Scenario & Condition Allocation**: Look up the participant's assigned row from Section 2 (e.g., P1 $\to$ Scenario Y under Manual Reference Baseline; P3 $\to$ Scenario X under Manual Reference Baseline).
2. **Administration**:
   - Provide the assigned scenario briefing and fixtures (`PILOT_PACKET.md` Section 3).
   - If **Condition A (Manual Baseline)**: Provide raw JSON fixture files and standard text/CLI inspection tools (`jq`, VS Code, text editor).
   - If **Condition B (Prototype Comparator)**: Provide the comparator output (Markdown/CLI report).
3. **Execution Rules**:
   - Start 720-second countdown timer.
   - Maintain strict silence; do not coach, hint, or steer.
   - If the participant reaches 720s before finishing, stop immediately and record as **`720s (censored)`**.
4. **Evidence Capture**:
   - Record the 4 unblended metrics: Completion Status, Questions Attempted ($k/4$), Points Earned ($X/20$), Task Time ($T$ sec).
   - Log each analytical assertion in the claim ledger with its provenance decision (Supported vs Unsupported) and severity classification.

#### Task 2 Execution (13 mins: 12 min / 720s cap + 1 min transition)
1. **Scenario & Condition Allocation**: Administer the second assigned scenario under the alternate condition (e.g., P1 $\to$ Scenario X under Evidence-Aware Prototype).
2. **Administration & Rules**: Identical 720-second cap, zero coaching, and 4-metric capture.
3. **Methodological Separation Rule**:
   - For any insight or finding on Condition B, evaluators explicitly record whether it was reached **Unaided (Output-Only)** or required guidance.
   - Conclusions reached after explanation are **never** counted as evidence of independent prototype efficacy.

#### Phase 4B: Guided Walkthrough & Provenance Inspection (5 mins)
*Goal: Observe comprehension, confusion, evidence verification, and usability on key prototype capabilities.*
- Walk through key reconciliation boundaries:
  - *"Notice that `update_payload.exe` and `staged_runner.bin` are matched by reported SHA-256 metadata with explicit source-resolvable RFC 6901 JSON pointers (`/behavior/dropped/0` vs `/execution/created_files/0`)."*
  - *"Notice the network reconciliation table: Report A contains a TCP observation for `203.0.113.88:8080`. Report B contains a general egress-policy warning mentioning port 8080. The output records: `connection_state = SOCKET_RECORD_LOGGED`, `cross_report_correlation = CONTEXTUAL_SIMILARITY_ONLY`, and explicitly states: 'relationship between the records is not established; evidence does not establish whether a TCP handshake completed or whether destination was C2 infrastructure.' "*
  - *"Notice the process matcher scores node similarity using a multi-factor heuristic (image name, argument Jaccard, lineage depth) instead of relying on transient PIDs."*

#### Phase 4C: Structured Debrief & Reality Check (9 mins)
*Goal: Capture perceived usefulness, operational friction, ambiguities, and follow-up interest.*
- *"What, if anything, would you do differently after seeing this output?"*
- *"Which conclusions can you support directly from the evidence shown?"*
- *"What would you still need to verify in the raw reports?"*
- *"What, if anything, was less useful or more confusing than your usual workflow?"*
- *"Where does this output feel ambiguous or risk misleading you?"*
- *"Is your current manual comparison process already good enough that adding a comparator CLI would feel like unnecessary overhead?"*
- *"Subject to formal employer and data-owner authorization under our safe data protocol, would your team be willing to test this on 2–3 sanitized internal reports in a follow-up trial?"*

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

### Partial-Cohort Rule ($N < 8$):
If recruitment concludes with fewer than 8 practitioners ($N = 5, 6, \text{ or } 7$), the $\ge 5 \text{ of } 8$ threshold cannot be mathematically relaxed, proportionally scaled, or extrapolated. In that event, the milestone gate must be formally designated as:
$$\text{Gate Decision: } \mathbf{Not\ Fully\ Evaluable\ (Cohort\ Size\ } N < 8\mathbf{)}$$
Results must be transparently reported as exploratory calibration evidence without claiming to have passed the locked 8-participant gate.
