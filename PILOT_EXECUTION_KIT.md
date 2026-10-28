# Milestone 5 — Practitioner Pilot Execution Kit

**Protocol Version**: `v5.1` (Locked Baseline)  
**Technology Baseline**: `dfec53743414b3cc95f48b20f74e84ad1f885469` (`dfec537`)  
**Target Codebase**: [`sandbox_comparator/`](file:///Users/namanbhatt/cfp/sandbox_comparator)  
**Authoritative References**: [`PILOT_PACKET.md`](file:///Users/namanbhatt/cfp/sandbox_comparator/PILOT_PACKET.md), [`INTERVIEW_PROTOCOL.md`](file:///Users/namanbhatt/cfp/sandbox_comparator/INTERVIEW_PROTOCOL.md), [`REHEARSAL_FINDINGS_AND_LOCK_RECORD.md`](file:///Users/namanbhatt/cfp/sandbox_comparator/REHEARSAL_FINDINGS_AND_LOCK_RECORD.md)  

> [!IMPORTANT]
> **Purpose**: Execute practitioner recruitment, screening, and main-cohort pilot sessions without altering the frozen prototype or modifying the locked Protocol v5.1.  
> This kit is an operational companion to `PILOT_PACKET.md` and `INTERVIEW_PROTOCOL.md`. If any procedural conflict arises, the authoritative locked protocol in `PILOT_PACKET.md` takes precedence.

---

## 1. Recruitment Outreach Scripts

### Option A: LinkedIn / Direct Message (Personalized Outreach)
```text
Hi [Name] — I’m conducting a small practitioner study on how security analysts compare malware sandbox reports or repeated sandbox runs.

I’m looking to speak with people in DFIR, malware analysis/reverse engineering, threat intelligence, or senior SOC/detection roles who have performed this kind of comparison within the last 30 days.

The session takes about 60 minutes. We’ll discuss a recent workflow using only a sanitized, non-confidential description, then evaluate a controlled offline prototype using prepared fixtures. I’m interested in what helps, what does not, and whether existing tools already meet the need.

No client names, internal IPs, malware samples, or confidential organizational telemetry are required.

Would you be open to a short eligibility check to see whether your experience fits the study?

Thank you!
```

### Option B: Community / Slack / Discord Post (DFIR / Detection Engineering Groups)
```text
Seeking practitioner feedback: multi-sandbox malware triage workflow

I'm running a small exploratory study with experienced DFIR, malware-analysis, threat-intelligence, and senior detection practitioners. The study examines how analysts reconcile differences between sandbox reports or repeated runs.

Eligibility: You have compared multiple sandbox reports or repeated runs in the past 30 days and can describe one sanitized example of a discrepancy.

Format: Approximately 60 minutes; prepared controlled fixtures; no live malware, client data, or confidential organizational telemetry required. The goal is to learn from current workflows, including cases where existing tools are already good enough.

Please DM me if interested.
```

---

## 2. Participant Screening Script & Eligibility Gate

Administer these five screening inquiries to every candidate prior to scheduling a session:

1. **Recent Experience**:  
   *"In the last 30 days, have you compared reports from more than one sandbox or compared repeated runs of a suspicious file?"*  
   - [ ] **Yes** (Qualifying)  
   - [ ] **No** (Ineligible)  
   - *If Yes*: *"Briefly describe the context without disclosing confidential details."*
2. **Tools & Platforms Actually Used**:  
   *"Which specific sandbox platforms, threat portals, or analysis tools did you inspect?"*  
   - Acceptable: CAPE, Any.Run, Joe Sandbox, Falcon Sandbox, VirusTotal Enterprise, Hatching Triage, internal sandboxes, custom scripts.  
   - *(Rule: Record strictly what tools were genuinely used).*
3. **Concrete Discrepancy Citation**:  
   *"Did the reports differ or omit an observation (e.g. dropped payload name divergence, missing network connection, process lineage change)?"*  
   - [ ] **Yes** (Qualifying)  
   - [ ] **No** (Ineligible)  
   - *If Yes*: *"Provide a high-level, sanitized summary of what differed and how you resolved it manually."*
4. **Role & Operational Experience**:  
   *"What is your current role and approximate time working in incident response, detection engineering, or malware analysis?"*  
   - Target profiles: Senior DFIR, Threat Intel, Tier 3 SOC, Malware RE, Detection Engineering.
5. **Session Availability**:  
   *"Which dates or time windows over the next 10 business days work for a 60-minute remote session?"*

> [!CAUTION]
> **Eligibility Rule**: Include only candidates who answer "Yes" to Questions 1 and 3 and provide a verifiable, concrete sanitized discrepancy. If recruitment requires including a broader exploratory cohort (e.g., Tier 2 SOC analysts), document this explicitly in the cohort metadata; **never silently relax eligibility standards.**

---

## 3. Predefined Randomized Allocation Tracker (Locked Blocks)

Participants are assigned strictly in sequence according to the locked random block sequence (`RANDOM_SEED = 20261028`). No participant may be reassigned post-hoc based on perceived skill or preferred scenario:

| Block | Study ID | Assigned Group | Task 1 (First Session) | Task 2 (Second Session) |
| :--- | :--- | :--- | :--- | :--- |
| **Block 1** | **P1** | **Group B** | Scenario Y — Manual Baseline | Scenario X — Evidence-Aware Prototype |
| | **P2** | **Group D** | Scenario Y — Evidence-Aware Prototype | Scenario X — Manual Baseline |
| | **P3** | **Group A** | Scenario X — Manual Baseline | Scenario Y — Evidence-Aware Prototype |
| | **P4** | **Group C** | Scenario X — Evidence-Aware Prototype | Scenario Y — Manual Baseline |
| **Block 2** | **P5** | **Group C** | Scenario X — Evidence-Aware Prototype | Scenario Y — Manual Baseline |
| | **P6** | **Group A** | Scenario X — Manual Baseline | Scenario Y — Evidence-Aware Prototype |
| | **P7** | **Group D** | Scenario Y — Evidence-Aware Prototype | Scenario X — Manual Baseline |
| | **P8** | **Group B** | Scenario Y — Manual Baseline | Scenario X — Evidence-Aware Prototype |

*Partial-Block Rule*: If recruitment concludes with $N=5, 6, \text{ or } 7$, candidates are assigned strictly in order from Block 2 (`P5 -> Group C`, `P6 -> Group A`, `P7 -> Group D`). Report partial-block sizes transparently.

---

## 4. Session Schedule & Operational Checklist (60-Minute Standard)

To accommodate two 12-minute (720-second) task sessions with full methodological fidelity without cutting task limits or truncating retrospective inquiry, sessions are scheduled for **60 minutes**:

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
| 00:46 – 01:00     | 14 minutes      | Phase 4C: Structured Debrief, Usability & Safe Trial Follow-up|
+-------------------+-----------------+-------------------------------------------------------------+
```

### Phase 0: Before the Participant Joins
- [ ] Confirm assigned Study ID (`P1`–`P8`) and assigned Group from the locked table above.
- [ ] Verify repository commit (`dfec537`) and fixture SHA-256 hashes against the ledger in `PILOT_PACKET.md`.
- [ ] Prepare exact task materials, condition prompt instructions, timer (720s countdown), and answer template.
- [ ] Ensure **zero** live malware, client data, organizational telemetry, or proprietary scripts are present in the workspace.
- [ ] Have the consent disclosure, privacy statement, and note-taking sheet ready.

### Phases 1–3: Real-World Workflow Grounding (15 Minutes)
- [ ] Ground in recent reality: Ask about their most recent real workflow **before** introducing any prototype concepts.
- [ ] Enforce confidentiality: Explicitly remind participant not to disclose client names, internal IPs, or proprietary details.
- [ ] Reconstruct workflow: Record exact tools, manual comparison steps, copy-paste friction, and approximate elapsed effort.
- [ ] Inquire about workarounds: Ask how they handled conflicting or omitted observations and whether current tools are "good enough."

### Phase 4A/B: Controlled Task Execution (26 Minutes: Two 12-Min Tasks + Transitions)
- [ ] Administer Task 1 and Task 2 strictly according to the assigned sequence and conditions.
- [ ] Enforce unaided task boundary: Maintain silence during the 12-minute unaided problem solving.
- [ ] Track 4-metric task outcomes separately:
  1. Completion Status: `Completed within 720s` vs `Censored at 720s (Incomplete)`
  2. Questions Attempted: `k / 4`
  3. Points Earned: `X / 20`
  4. Task Time: `T sec` (or `720s censored`)
- [ ] Incomplete task rule: If time reaches 12 minutes, stop immediately, record as `720s (censored)`, and mark benchmark as **`Not Assessable (Incomplete Task)`**. Do not truncate or extrapolate.
- [ ] Methodological separation: Label each participant insight as **Unaided**, **Output-Only**, or **Prompted/Guided**.
- [ ] Record negative feedback: Actively solicit what was confusing, misleading, or inferior to their current workflow.

### Phase 4C: Structured Debrief & Reality Check (14 Minutes)
- [ ] Probe perceived utility: Ask what they would still need to verify in raw reports and what was less useful than existing workflows.
- [ ] Evaluate adoption blockers: Document daily pipeline friction, CLI preference, and organizational constraints.
- [ ] Formal data-handling inquiry: Inquire whether their team would review 2–3 sanitized internal reports under the safe storage and cryptographic erasure protocol.

### After the Session
- [ ] Store notes using the anonymized Study ID only; archive contact info in an encrypted, isolated roster.
- [ ] Conduct independent dual-reviewer scoring prior to consensus discussion.
- [ ] Separate supported claims from unsupported causal/attribution leaps (stratified UCR).
- [ ] Record follow-up interest strictly as a **trial commitment** under the data-handling protocol—not commercial purchase intent.
- [ ] Keep rehearsal records R1 and R2 permanently segregated from main-cohort analysis.

---

## 5. Five-Dimension Evaluation Gate & Standards

| Dimension | Evaluation Criteria | Red Flag (Fail) | Green Flag (Pass) |
| :--- | :--- | :--- | :--- |
| **1. Frequency** | How often does cross-report discrepancy cause operational friction? | Less than once a month; single sandbox summary is sufficient. | Multiple times weekly; cross-checking is a recurring bottleneck. |
| **2. Cost** | Time spent manually comparing discordant reports. | < 5 minutes per sample; friction is negligible. | 20–45+ minutes per sample across tabs and raw logs. |
| **3. Alternatives** | Adequacy of current tools, scripts, or workarounds. | Existing portal summaries or internal scripts solve 90%+ of needs. | Spreadsheets/manual text diffs are fragile and fail across schemas. |
| **4. Technical Value** | Does the output improve correctness and prevent false leaps? | *"I don't care why an event is missing; if it's not logged, I ignore it."* | *"Crucial: distinguishing unrecorded from non-occurrence prevents bad Sigma rules."* |
| **5. Adoption Evidence** | Concrete willingness to participate in follow-up trial. | Polite verbal praise; declines follow-up or testing on real telemetry. | **Agrees to review 2–3 sanitized organizational reports under our safe data protocol.** |

### Predeclared Milestone Gate Rules & Incomplete Cohort Handling:
1. **Advance Toward Specialized Workflow Tool**: $\ge 5$ of 8 practitioners pass Dimensions 1–4, AND at least **2 practitioners commit to reviewing sanitized organizational reports under the Data Handling Protocol**.
2. **Package as Open-Source Library**: Practitioners confirm technical value and forensic accuracy, but state organizational procurement or budget constraints prevent adopting commercial point solutions.
3. **Shelve Project**: $\ge 4$ practitioners conclude that VirusTotal's merged view or standard single-engine reports are already adequate for their operational decision-making.

> [!IMPORTANT]
> **Incomplete Cohort Rule ($N = 5, 6, \text{ or } 7$)**: The $\ge 5/8$ threshold is fixed to an 8-practitioner cohort. If recruitment concludes with fewer than 8 participants, the gate is reported strictly as **`Not Fully Evaluable (Incomplete Cohort: N/8 completed)`** against the 8-practitioner standard. Evaluators report descriptive proportions (e.g. $4/6$ or $5/7$ passed Dimensions 1–4) without adjusting the threshold post-hoc or claiming statistical power.

