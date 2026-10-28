# Practitioner Pilot Packet: Evidence-Aware Malware Comparison Workflow (Milestone 5)

This document is the standardized, reproducible pilot protocol for evaluating the evidence-aware sandbox comparator against a manual reference-report baseline across 5 to 8 practicing security analysts.

---

## 1. Experimental Design: Counterbalanced 2x2 Crossover

To prevent confounding tool efficacy with scenario difficulty or task order, the study uses a **counterbalanced 2x2 crossover design**. Both workflows are tested by every participant across two independently prepared, equivalent forensic scenarios.

### 4-Group Allocation Matrix

| Group | Task 1 (First Session) | Task 2 (Second Session) |
| :--- | :--- | :--- |
| **Group A** | Scenario X — Manual Reference Baseline | Scenario Y — Evidence-Aware Prototype |
| **Group B** | Scenario Y — Manual Reference Baseline | Scenario X — Evidence-Aware Prototype |
| **Group C** | Scenario X — Evidence-Aware Prototype | Scenario Y — Manual Reference Baseline |
| **Group D** | Scenario Y — Evidence-Aware Prototype | Scenario X — Manual Reference Baseline |

### Predefined Randomized Block Allocation & Partial-Block Rule:
Participants are allocated using **predefined randomized blocks of four** generated with fixed seed `RANDOM_SEED = 20261028`:

| Block | Participant ID | Assigned Group | Task 1 Session | Task 2 Session |
| :--- | :--- | :--- | :--- | :--- |
| **Block 1** | **P1** | **Group B** | Scenario Y — Baseline | Scenario X — Prototype |
| | **P2** | **Group D** | Scenario Y — Prototype | Scenario X — Baseline |
| | **P3** | **Group A** | Scenario X — Baseline | Scenario Y — Prototype |
| | **P4** | **Group C** | Scenario X — Prototype | Scenario Y — Baseline |
| **Block 2** | **P5** | **Group C** | Scenario X — Prototype | Scenario Y — Baseline |
| | **P6** | **Group A** | Scenario X — Baseline | Scenario Y — Prototype |
| | **P7** | **Group D** | Scenario Y — Prototype | Scenario X — Baseline |
| | **P8** | **Group B** | Scenario Y — Baseline | Scenario X — Prototype |

- **Partial-Block Handling**: If recruitment concludes with fewer than 8 participants (e.g. $N=5, 6, \text{ or } 7$), participants are assigned strictly in sequence from Block 2 (`P5 -> Group C`, `P6 -> Group A`, `P7 -> Group D`). Evaluators record the exact group allocation and report partial-block allocation transparently. Group assignments are locked prior to interview administration and cannot be altered post-hoc.
- **Rehearsal Exclusion**: Rehearsal participants (R1, R2) are strictly excluded from the study cohort and from Block 1/2 randomization.
- **Methodological Scope**: This is an exploratory, counterbalanced usability and task-performance pilot. It distributes order and scenario differences across participants, but does not claim large-sample statistical equivalence.

---

## 2. Experimental Conditions & Fair Baseline Standards

To ensure a fair, defensible comparison, both conditions receive **identical input evidence**:

| Dimension | Condition A: Manual Reference Baseline | Condition B: Evidence-Aware Prototype |
| :--- | :--- | :--- |
| **Input Data** | Local raw JSON reports (CAPE schema fixture and Falcon-like approximation) + VT behavior reference JSON. | Identical local raw JSON reports + VT behavior reference JSON. |
| **Interface / Tooling** | Text editors (VS Code / Sublime), terminal (`jq`, `grep`), or multi-window JSON inspection simulating typical manual triage. | Prototype CLI: `python3 cli.py --format markdown` (or `--format json`). |
| **Evidence Access** | Full access to all raw source files; manual copy-pasting of hashes and cross-referencing of process trees. | Automated cross-engine reconciliation table with source-resolvable RFC 6901 JSON pointers into the same source files. |
| **Scope & Fairness** | Condition A is explicitly framed as a **manual reference-report baseline**, not a live VirusTotal web service test. | Condition B provides automated diffing; missing source fields in fixtures count as unavailable, not analyst error. |

### Session Administration, Incomplete Task Handling & 4-Metric Reporting:
- **Time Limit**: Exactly **12 minutes (720 seconds)** per scenario task.
- **Incomplete Tasks (Censoring)**: If a participant reaches 12 minutes before finishing all four questions, time is recorded as **`720s (censored)`**; do not extrapolate or invent completion times.
- **Unattempted Questions**: Unanswered questions are recorded as **`Not Completed / Unattempted`** rather than automatically as `0/5 Incorrect`.
- **4-Metric Reporting Standard**: For every task session, evaluators report four distinct, unblended metrics:
  1. **Completion Status**: `Completed within 720s` vs `Censored at 720s (Incomplete)`.
  2. **Questions Attempted**: `k / 4` questions attempted.
  3. **Points Earned**: `X / 20` points (unattempted questions receive 0 earned points without dropping the fixed 20-point scale).
  4. **Task Time**: `T seconds` (or `720s censored`).
- **Benchmark Eligibility**: The full-task proficiency benchmark ($\ge 17/20$, 85%) applies **only to completed tasks (4/4 questions attempted)**. For incomplete tasks (<4 attempted), the benchmark is recorded strictly as **`Not Assessable (Incomplete Task)`**; partial scores are never compared directly to completed 20-point scores, avoiding confounding speed with correctness.
- **Source-Resolvable Pointers**: Pointers in the output (e.g. `/behavior/dropped/0`) are source-resolvable JSON Pointer paths (RFC 6901) that resolve against the input documents; they are not interactive browser hyperlinks.
- **Reported Metadata Scope**: The comparator verifies **reported SHA-256 metadata equivalence across JSON reports**; it does not perform independent re-hashing of guest filesystem binaries directly from disk images.

---

## 3. Standardized Incident Scenarios

### Scenario X: Multi-Stage Staged Evasion Dropper
- **Fixtures**: `data/report_format_a_cape.json` (Report A: CAPE v2.5 schema) vs `data/report_format_b_falcon.json` (Report B: Falcon-like approximation schema).
- **Fixture Provenance**: Controlled synthetic fixture pair representing simulated multi-sandbox output for an evasion dropper.
- **Briefing**:
  > *"You are triaging an escalated phishing incident involving sample `invoice_oct2026.exe`. The sample was executed in two different sandbox environments. You have 12 minutes to evaluate the multi-stage behavior and answer the four triage questions below based strictly on recorded evidence."*

#### Scenario X Questionnaire:
1. **Reported Dropped Artifact Scope**: Based on the reports, do these entries represent matching reported SHA-256 values, modified variants, or completely different binaries? Explain what the reported evidence proves and what limitations remain regarding byte-level binary identity.
2. **Process Tree Lineage**: In Environment 1, PID 4156 executed a PowerShell cradle. Which process in Environment 2 performed the equivalent step? Is this alignment certain or heuristic?
3. **Network Event Presence & Causation**: Environment 1 recorded a TCP observation to `203.0.113.88:8080`. Environment 2 did not record this connection. Did this connection occur in Environment 2? Explain the omission.
4. **Attribution Boundary**: Can `203.0.113.88:8080` be confirmed as an active Command-and-Control (C2) server based on the sandbox telemetry? Justify your answer.

---

### Scenario Y: Sanitized CAPE v2 Export Telemetry Triage
- **Fixtures**: `data/real_sanitized_cape_v2_export.json` (Sanitized CAPE v2.2 schema export fixture) vs `data/virustotal_behavior_summary_reference.json` (Aggregated reference summary).
- **Fixture Provenance**: Sanitized CAPE v2.2 schema export fixture derived from native CAPE Sandbox v2.2 JSON reporting schema; external hosts/IPs sanitized with RFC 5737 documentation blocks and synthetic test mutexes.
- **Briefing**:
  > *"You are reviewing a sanitized CAPE v2.2 schema export fixture from an enterprise sandbox against an aggregated threat portal summary. You have 12 minutes to identify missing artifacts, verify process execution, and determine if telemetry omissions can be explained by environment constraints."*

#### Scenario Y Questionnaire:
1. **Hash Verification & Dropped Scope**: What dropped files are corroborated across both the CAPE fixture and the summary? Are there dropped artifacts observed in only one report? Cite reported SHA-256 metadata from the reports.
2. **Interpreter Commandline Divergence**: Did the suspicious PowerShell script execute via an intermediate cmd.exe shell wrapper or directly under the parent binary? What does the source lineage prove?
3. **Missing Telemetry & Policy Restraints**: Identify whether any network connections were omitted, blocked by firewall policies, or unexplained. What evidence supports this?
4. **Pointer Verification**: For every discrepancy identified, cite the exact source document and path/pointer where an analyst can independently inspect the raw telemetry.

---

## 4. Question-Specific 20-Point Scoring Rubric

Each question is evaluated on **tailored, domain-specific criteria** (4 questions $\times$ 5 points each = 20 points total):

### Scenario X Rubric (20 Points Total)

```
+-------------------------------------------------------------------------------------------------------------------------------+
| Question 1: Dropped Artifact Reported Digest Equivalence (5 Points)                                                           |
+-------------------------------------------------------------------------------------------------------------------------------+
| Criteria                                                                                                              | Pts   |
+-------------------------------------------------------------------------------------------------------------------------------+
| Core Conclusion: Identifies matching reported SHA-256 values across reports.                                          | 0 - 2 |
| (Awards full credit if participant notes that reports contain matching reported SHA-256 values, which provides strong  |       |
| identity evidence if report metadata is trustworthy, while explicitly noting that report diffing does not             |       |
| independently establish byte-for-byte binary identity from disk images. Do not penalize for stating this limitation). |       |
| Reported Digest Proof: Cites reported 64-char SHA-256 (a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0).| 0 - 1 |
| Discrepancy Awareness: Notes filename divergence (update_payload.exe vs staged_runner.bin) due to staging paths.      | 0 - 1 |
| Source Provenance: Points to source locations (/behavior/dropped/0 and /execution/created_files/0).                   | 0 - 1 |
+-------------------------------------------------------------------------------------------------------------------------------+

+-------------------------------------------------------------------------------------------------------------------------------+
| Question 2: Process Tree Lineage & Heuristic Correlation (5 Points)                                                           |
+-------------------------------------------------------------------------------------------------------------------------------+
| Criteria                                                                                                              | Pts   |
+-------------------------------------------------------------------------------------------------------------------------------+
| Core Alignment: Aligns PID 4156 (Env 1) with PID 8896 (Env 2) performing equivalent PowerShell download cradle.      | 0 - 2 |
| Argument Equivalence: Analyzes matching command arguments (Invoke-WebRequest download of stage2.bin).                 | 0 - 1 |
| Hierarchy Recognition: Notes both execute under cmd.exe wrapper at depth 3.                                           | 0 - 1 |
| Epistemic Boundary: Formally recognizes alignment as a heuristic match (score 0.85-0.94), not absolute identity.      | 0 - 1 |
+-------------------------------------------------------------------------------------------------------------------------------+

+-------------------------------------------------------------------------------------------------------------------------------+
| Question 3: Network Event Presence & Causation (5 Points)                                                                     |
+-------------------------------------------------------------------------------------------------------------------------------+
| Criteria                                                                                                              | Pts   |
+-------------------------------------------------------------------------------------------------------------------------------+
| Observation Status: Identifies event is observed in Env 1 but unrecorded in Env 2 telemetry.                         | 0 - 2 |
| Policy Context: Cites Env 2 system warning WARN_EGRESS_POLICY intercepting outbound port 8080 traffic.                | 0 - 1 |
| Epistemic Distinction: Recognizes that absence in Env 2 telemetry does NOT prove non-occurrence in reality.           | 0 - 1 |
| Causal Boundary: Notes causal link is a plausible contextual hypothesis, but relationship is not strictly established. | 0 - 1 |
+-------------------------------------------------------------------------------------------------------------------------------+

+-------------------------------------------------------------------------------------------------------------------------------+
| Question 4: Attribution Boundary & Telemetry Rigor (5 Points)                                                                 |
+-------------------------------------------------------------------------------------------------------------------------------+
| Criteria                                                                                                              | Pts   |
+-------------------------------------------------------------------------------------------------------------------------------+
| Core Conclusion: Concludes attribution is NO / UNPROVEN based on provided telemetry.                                  | 0 - 2 |
| Telemetry Scope: Explains telemetry records an outbound socket destination, not an established C2 handshake.         | 0 - 1 |
| Documentation Block: Recognizes 203.0.113.88 is in RFC 5737 TEST-NET-3 documentation block.                           | 0 - 1 |
| Attribution Rigor: Strictly avoids speculative labels ("confirmed C2", "threat actor server") without proof.          | 0 - 1 |
+-------------------------------------------------------------------------------------------------------------------------------+
```

### Scenario Y Rubric (20 Points Total)

```
+-------------------------------------------------------------------------------------------------------------------------------+
| Question 1: Hash Verification & Dropped Scope (5 Points)                                                                      |
+-------------------------------------------------------------------------------------------------------------------------------+
| Criteria                                                                                                              | Pts   |
+-------------------------------------------------------------------------------------------------------------------------------+
| Corroboration: Identifies update_payload.exe as corroborated across fixture and summary by reported SHA-256.          | 0 - 2 |
| Unilateral Scope: Identifies mutex_flag.tmp as recorded only in CAPE fixture                                          | 0 - 1 |
| (Reported SHA-256: c5e8f1b2d49a37210e4fbc8712a0956487e41203876541290384756102938475).                                |       |
| Evidence Citation: References reported SHA-256 digest, unique prefix, or guest path for corroborated artifact.        | 0 - 1 |
| (Participants earn credit for evidence identification and citation; memorization of full 64-char hash is not required)|       |
| Provenance Citation: Resolves pointers to /dropped/0 and /dropped/1 in CAPE fixture.                                   | 0 - 1 |
+-------------------------------------------------------------------------------------------------------------------------------+

+-------------------------------------------------------------------------------------------------------------------------------+
| Question 2: Interpreter Commandline Lineage (5 Points)                                                                        |
+-------------------------------------------------------------------------------------------------------------------------------+
| Criteria                                                                                                              | Pts   |
+-------------------------------------------------------------------------------------------------------------------------------+
| Lineage Recognition: Identifies 3-level hierarchy (sample -> cmd.exe -> powershell.exe).                              | 0 - 2 |
| Argument Context: Analyzes encoded command argument on cmd.exe spawning PowerShell cradle.                            | 0 - 1 |
| Summary Flattening: Explains that VT summary flattens processes into a list, obscuring execution parentage.           | 0 - 1 |
| Provenance Citation: Resolves pointer to /behavior/processes/2 in CAPE fixture.                                       | 0 - 1 |
+-------------------------------------------------------------------------------------------------------------------------------+

+-------------------------------------------------------------------------------------------------------------------------------+
| Question 3: Missing Telemetry & Policy Restraints (5 Points)                                                                  |
+-------------------------------------------------------------------------------------------------------------------------------+
| Criteria                                                                                                              | Pts   |
+-------------------------------------------------------------------------------------------------------------------------------+
| Omission Status: Identifies that port 8080 TCP stream in CAPE fixture is absent from summary reference.              | 0 - 2 |
| Absence of Policy Warning: Notes that summary notes "None" for limitations; omission cannot be attributed to policy.   | 0 - 1 |
| Epistemic Discipline: Concludes omission cause is unverified/unexplained in summary without speculating.              | 0 - 1 |
| Provenance Citation: Resolves pointer to /network/tcp/1 in CAPE fixture.                                              | 0 - 1 |
+-------------------------------------------------------------------------------------------------------------------------------+

+-------------------------------------------------------------------------------------------------------------------------------+
| Question 4: Source Pointer Verification (5 Points)                                                                            |
+-------------------------------------------------------------------------------------------------------------------------------+
| Criteria                                                                                                              | Pts   |
+-------------------------------------------------------------------------------------------------------------------------------+
| Pointer Validity: Provides valid RFC 6901 pointers for cited discrepancies.                                           | 0 - 2 |
| Bidirectional Verification: Confirms pointers resolve to valid source nodes in raw JSON fixture.                       | 0 - 1 |
| Unmapped Field Awareness: Notes that unmapped sections (signatures, memory, apistats) are surfaced, not dropped.       | 0 - 1 |
| Rigorous Documentation: Avoids quoting raw text without identifying source file and path.                             | 0 - 1 |
+-------------------------------------------------------------------------------------------------------------------------------+
```

### Predefined Task Performance Threshold:
- **Scoring Standard**: Applicable **only to completed tasks (4/4 questions attempted within 720s)**.
- **Proficiency Benchmark**: $\ge 85\%$ ($\ge 17/20$ points) indicates proficient forensic reasoning across reported metadata verification and epistemic boundaries.
- **Incomplete Tasks (<4 Questions Attempted)**: Recorded as **`Not Assessable (Incomplete Task)`**; partial scores are reported alongside completion status (`k / 4 attempted`) and task time (`720s censored`), and are never directly compared to completed 20-point scores.
- **Measurement Qualification**: This benchmark evaluates task performance on these specific prepared scenarios; it is not a surrogate for commercial adoption or product-market fit.

---

## 5. Formalized Safety Metric: Unsupported Conclusions Rate ($UCR$)

> **Definition**: The proportion of independent analytical claims where an analyst asserts a conclusion that exceeds what the underlying telemetry establishes.

$$UCR = \frac{N_{\text{unsupported claims}}}{N_{\text{total analytical claims}}}$$

### Claim Unit Definition & Analysis Rules:
1. **Unit of Analysis**: One independently verifiable factual, causal, or attribution assertion.
   - Example 1: *"The file has matching reported SHA-256 metadata"* = 1 claim (supported).
   - Example 2: *"The connection failed because the firewall blocked it, proving the C2 server was neutralized"* = 2 claims (1 causal leap + 1 attribution leap).
2. **Edge Case: Zero Claims**: If an answer contains zero analytical claims, the denominator is zero. Record $UCR = \text{N/A}$ (do not record as 0.0%).
3. **Answer Length Variations**: Always report both raw counts ($N_{unsupported}, N_{total}$) alongside the ratio $UCR$.
4. **Condition $\times$ Scenario $\times$ Question Breakdown**:
   - To avoid concealing question-specific safety regressions behind pooled averages, report $UCR$ stratified by **Condition $\times$ Scenario $\times$ Question**, with raw claim counts and severity breakdowns.
5. **Non-Causal Observational Labeling (No Individual Crossover Pairing)**:
   - On individual scoring sheets, record unsupported claims as condition-specific claims within that task session.
   - Do **not** pair an individual participant's error on Scenario X with their answer on Scenario Y.
   - Evaluate error patterns at the **cohort level within the same scenario and question** using non-causal observational labels:
     - *Observed only in prototype-condition responses*
     - *Observed only in baseline-condition responses*
     - *Observed across both condition responses*
   - **Causality Restriction**: Strictly avoid causal terminology (e.g. *"Prototype-Introduced"*, *"Baseline-Only"*, *"Prototype-Eliminated"*, *"Tool-Caused"*). Cohort-level differences across 5–8 participants describe sample patterns; they do not prove that the tool caused an error to appear or disappear.
6. **Non-Independence of Participant Claims**:
   - Multiple claim statements from the same participant may stem from a single shared misconception. Evaluators describe raw counts, distinct patterns, and severity categories without treating individual claims as statistically independent observations.

### Severity Classification:

| Category | Severity | Operational Definition | Concrete Example |
| :--- | :--- | :--- | :--- |
| **Causal Leap** | **High** | Asserting that telemetry absence proves an event did not occur in reality. | *"Env 2 proves the malware never attempted an outbound connection."* |
| **Attribution Leap** | **High** | Labeling an uncorroborated IP/domain as "C2" or "threat infrastructure" without protocol proof. | *"203.0.113.88 is confirmed as the attacker's Command and Control server."* |
| **Certainty Leap** | **Medium** | Asserting a heuristic process alignment is absolute mathematical ground truth. | *"PID 4156 and PID 8896 are mathematically guaranteed to be the exact same process."* |
| **Handshake Assumption** | **Medium** | Asserting a completed TCP connection from a raw socket observation without handshake evidence. | *"The malware established a full TCP connection and exfiltrated data."* |
| **Provenance Failure** | **Low** | Quoting a discrepancy without citing a resolvable JSON pointer or source path. | *"It's somewhere in the Falcon report logs."* |

### Dual-Reviewer Scoring & Arbitration:
- Anonymized participant answer sheets are independently scored by two reviewers against the Ground-Truth Key and Coding Rules.
- Disagreements on claim boundaries or severity are resolved via documented consensus discussion; unresolved items default to the more conservative classification.

### Exploratory Pilot Benchmark:
- If $UCR_A > 0$: Condition B target is $UCR_B \le 0.5 \times UCR_A$.
- If $UCR_A = 0$: Condition B target is $UCR_B = 0$ (verifying that the prototype does not introduce unsupported claims).
- *Reporting Standard*: Task completion time, accuracy score, questions attempted, and UCR are reported as separate outcomes. They are never blended into a single composite score.

---

## 6. Independently Reviewed Ground-Truth Key

```
+----+---------------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Q# | Domain                    | Verified Ground-Truth Answer & Resolvable Evidence                                                                                                          |
+----+---------------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------+
| SX | Dropped Payload Identity  | MATCHING REPORTED SHA-256 VALUES (`a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0`).                                                    |
| 1  |                           | Resolvable Pointers: Report A `/behavior/dropped/0`, Report B `/execution/created_files/0`. Filenames diverge due to staging paths.                          |
|    |                           | Epistemic Limitation: Establishes reported metadata equality; does not independently establish byte-for-byte binary identity from disk images.              |
+----+---------------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------+
| SX | Process Lineage Alignment | HEURISTIC MATCH (Score: 0.94).                                                                                                                              |
| 2  |                           | PID 4156 (Env 1) aligns with PID 8896 (Env 2). Both execute equivalent Invoke-WebRequest PowerShell cradle under cmd.exe wrapper at depth 3.               |
|    |                           | Resolvable Pointers: Report A `/behavior/processes/2`, Report B `/execution/process_tree/0/children/0/children/0`. Alignment is heuristic, not certain.     |
+----+---------------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------+
| SX | Network Event Causation   | UNRECORDED IN ENV 2; PLAUSIBLE POLICY CORRELATION.                                                                                                          |
| 3  |                           | Env 1 has TCP observation (`/behavior/network/tcp/1`); Env 2 logged system warning WARN_EGRESS_POLICY (`/submission_info/system_warnings/1`).               |
|    |                           | Causal relationship is plausible contextual similarity, but unestablished. Non-occurrence in reality is not established. Address is RFC 5737 TEST-NET-3.   |
+----+---------------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------+
| SX | Threat Attribution        | UNPROVEN / NO.                                                                                                                                              |
| 4  |                           | Raw telemetry only logs a destination IP:port socket; does not establish C2 handshake or application command stream. Address is TEST-NET-3 documentation.  |
+----+---------------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------+
| SY | Corroborated Artifacts    | CORROBORATED: `update_payload.exe` (Reported SHA-256: `a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0`).                                 |
| 1  |                           | UNILATERAL: `mutex_flag.tmp` (Reported SHA-256: `c5e8f1b2d49a37210e4fbc8712a0956487e41203876541290384756102938475`) recorded only in CAPE fixture (`/dropped/1`).|
+----+---------------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------+
| SY | Lineage Divergence        | CAPE fixture proves 3-level lineage: `invoice_doc_sanitized.exe` -> `cmd.exe` -> `powershell.exe`. Resolvable Pointer: `/behavior/processes/2`.            |
| 2  |                           | Aggregated summary reference flattens process strings and obscures execution parentage.                                                                     |
+----+---------------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------+
| SY | Network Omission          | Unexplained omission: port 8080 TCP stream in CAPE (`/network/tcp/1`) is absent from summary reference; summary records "None" for limitations.             |
| 3  |                           | Cause of omission is unverified; cannot be attributed to egress policy.                                                                                     |
+----+---------------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------+
| SY | Provenance Verification   | Valid RFC 6901 pointers resolve to exact keys in CAPE fixture (`/dropped/0`, `/network/tcp/1`, `/behavior/processes/2`).                                    |
| 4  |                           | Unmapped sections (`signatures`, `memory`, `apistats`, `debug`) are surfaced under unsupported_fields rather than dropped.                                  |
+----+---------------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------+
```

---

## 7. Data Handling & Verifiable Cryptographic Erasure Protocol

Before requesting or receiving any sanitized reports from external organizations:

1. **Explicit Legal & Employer Authorization**:
   - Written authorization must be obtained from the participant's data owner or legal/security leadership. A participant's personal consent for an interview does not substitute for organizational approval.
   - Initial rehearsal and pilot sessions use prepared evaluation fixtures only. No external organizational telemetry will be accepted until the storage infrastructure and authorization protocol are formally countersigned.
2. **Documented Pseudonymization & Redaction**:
   - Internal Active Directory domain names and corporate hostnames must be replaced with consistent pseudonyms (e.g. `HOST-CORP-A.internal`) to preserve cross-report correlation without exposing infrastructure.
   - Redaction checklist: employee usernames, internal RFC 1918 IPv4/RFC 4193 IPv6 addresses, API tokens/headers, customer identifiers, and proprietary local paths.
3. **Strict Binary Prohibition**:
   - **Under no circumstances will live malware binaries, active scripts, or executable payloads be accepted or transferred.** Telemetry JSON logs only.
4. **Encrypted Storage Container & Dedicated Key Management**:
   - External telemetry and pilot session artifacts are stored exclusively on a dedicated, isolated encrypted virtual volume:
     - **Volume Creation**: Created via `hdiutil create -encryption AES-256 -size 5g -fs APFS -type SPARSEBUNDLE -volname SandboxPilotData SandboxPilotData` (or LUKS2 container on Linux).
     - **Key Management**: A unique, cryptographically random 256-bit passphrase is generated and stored exclusively in an isolated local keychain item (`security add-generic-password -s "SandboxPilotData" -a "Evaluator"`). No iCloud Keychain sync, no recovery keys, and no Time Machine / cloud backups are permitted.
     - **Comprehensive Scope**: All collected JSON reports, intermediate scratch files, participant notes, transcripts, audio recordings, and temporary CLI output buffers reside exclusively within `/Volumes/SandboxPilotData`.
     - Access is restricted exclusively to named study evaluators.
5. **Retention & Verifiable Cryptographic Erasure**:
   - Telemetry retained for a maximum of 30 days during active analysis.
   - **Verified Deletion Procedure**:
     1. Unmount the encrypted sparse bundle (`hdiutil detach /Volumes/SandboxPilotData`).
     2. Permanently delete the volume passphrase from the keychain (`security delete-generic-password -s "SandboxPilotData"`).
     3. Overwrite the volume header and keybag bands containing the wrapped volume encryption keys using cryptographically secure random bytes (`dd if=/dev/urandom of=SandboxPilotData.sparsebundle/bands/... bs=4m count=2 conv=notrunc`).
     4. Recursively delete the sparsebundle directory (`rm -rf SandboxPilotData.sparsebundle`).
     5. Generate and sign an audit deletion certificate confirming key destruction and container removal for the data owner.
6. **Voluntary Evaluation Statement**:
   - Participants are formally informed that the comparator is an exploratory research utility, not an accredited incident-response or production triage platform.

---

## 8. Scenario-Driven Modular Participant Scoring Sheet

```markdown
# Participant Evaluation Record
Participant ID: _________   Role: ________________________   Experience: _______ yrs
Assigned Group: [ ] Group A   [ ] Group B   [ ] Group C   [ ] Group D (Pre-allocated Block: ____)

====================================================================================================
TASK 1 SESSION
====================================================================================================
- Administered Scenario: [ ] Scenario X   [ ] Scenario Y
- Condition:            [ ] Manual Reference Baseline   [ ] Evidence-Aware Prototype
- 4-Metric Reporting:
  1. Completion Status:   [ ] Completed within limit   [ ] Censored at 720s (Incomplete)
  2. Questions Attempted: ___ / 4 questions
  3. Points Earned:       ___ / 20 points (Unattempted questions recorded as Not Completed)
  4. Task Time:           Start: _______ | End: _______ | Duration: ______ sec (or 720s censored)
- Full-Task Benchmark (>= 17/20, >= 85%):
  [ ] Met (Completed Task)   [ ] Not Met (Completed Task)   [ ] Not Assessable (Incomplete Task)

SCORING (Apply rubric matching the Administered Scenario):
[ ] IF SCENARIO X WAS ADMINISTERED:
    Q1 (Reported Digest Equivalence): [ /2 matching_hashes] + [ /1 proof] + [ /1 diff] + [ /1 pointer] = ___ / 5
    Q2 (Process Tree Lineage):         [ /2 align] + [ /1 args] + [ /1 hierarchy] + [ /1 epistemic] = ___ / 5
    Q3 (Network Causation):            [ /2 presence] + [ /1 policy] + [ /1 absence!=proof] + [ /1 caus] = ___ / 5
    Q4 (Attribution Rigor):            [ /2 attribution] + [ /1 scope] + [ /1 testnet3] + [ /1 rigor] = ___ / 5

[ ] IF SCENARIO Y WAS ADMINISTERED:
    Q1 (Corroborated Scope):           [ /2 corroboration] + [ /1 unilateral] + [ /1 hash_cite] + [ /1 ptr] = ___ / 5
    Q2 (Lineage Divergence):           [ /2 lineage] + [ /1 args] + [ /1 flattening] + [ /1 ptr] = ___ / 5
    Q3 (Missing Telemetry):            [ /2 omission] + [ /1 policy_check] + [ /1 epistemic] + [ /1 ptr] = ___ / 5
    Q4 (Pointer Integrity):            [ /2 pointer_valid] + [ /1 bidirectional] + [ /1 unmapped] + [ /1] = ___ / 5

CLAIMS & SAFETY EVALUATION:
- Total Analytical Claims Made ($N_{total}$): ___
- Unsupported Claims Count ($N_{unsupported}$): ___
- UCR ($N_{unsupported} / N_{total}$): ___ % (Record N/A if $N_{total} = 0$)
- Severity Breakdown:
  - High (Causal / Attribution Leaps): ___
  - Medium (Certainty Leaps / Handshake Assumptions): ___
  - Low (Provenance Failures): ___

====================================================================================================
TASK 2 SESSION
====================================================================================================
- Administered Scenario: [ ] Scenario X   [ ] Scenario Y
- Condition:            [ ] Manual Reference Baseline   [ ] Evidence-Aware Prototype
- 4-Metric Reporting:
  1. Completion Status:   [ ] Completed within limit   [ ] Censored at 720s (Incomplete)
  2. Questions Attempted: ___ / 4 questions
  3. Points Earned:       ___ / 20 points (Unattempted questions recorded as Not Completed)
  4. Task Time:           Start: _______ | End: _______ | Duration: ______ sec (or 720s censored)
- Full-Task Benchmark (>= 17/20, >= 85%):
  [ ] Met (Completed Task)   [ ] Not Met (Completed Task)   [ ] Not Assessable (Incomplete Task)

SCORING (Apply rubric matching the Administered Scenario):
[ ] IF SCENARIO X WAS ADMINISTERED:
    Q1 (Reported Digest Equivalence): [ /2 matching_hashes] + [ /1 proof] + [ /1 diff] + [ /1 pointer] = ___ / 5
    Q2 (Process Tree Lineage):         [ /2 align] + [ /1 args] + [ /1 hierarchy] + [ /1 epistemic] = ___ / 5
    Q3 (Network Causation):            [ /2 presence] + [ /1 policy] + [ /1 absence!=proof] + [ /1 caus] = ___ / 5
    Q4 (Attribution Rigor):            [ /2 attribution] + [ /1 scope] + [ /1 testnet3] + [ /1 rigor] = ___ / 5

[ ] IF SCENARIO Y WAS ADMINISTERED:
    Q1 (Corroborated Scope):           [ /2 corroboration] + [ /1 unilateral] + [ /1 hash_cite] + [ /1 ptr] = ___ / 5
    Q2 (Lineage Divergence):           [ /2 lineage] + [ /1 args] + [ /1 flattening] + [ /1 ptr] = ___ / 5
    Q3 (Missing Telemetry):            [ /2 omission] + [ /1 policy_check] + [ /1 epistemic] + [ /1 ptr] = ___ / 5
    Q4 (Pointer Integrity):            [ /2 pointer_valid] + [ /1 bidirectional] + [ /1 unmapped] + [ /1] = ___ / 5

CLAIMS & SAFETY EVALUATION:
- Total Analytical Claims Made ($N_{total}$): ___
- Unsupported Claims Count ($N_{unsupported}$): ___
- UCR ($N_{unsupported} / N_{total}$): ___ % (Record N/A if $N_{total} = 0$)
- Severity Breakdown:
  - High (Causal / Attribution Leaps): ___
  - Medium (Certainty Leaps / Handshake Assumptions): ___
  - Low (Provenance Failures): ___

====================================================================================================
CONDITION X SCENARIO X QUESTION CLAIM REPORTING TABLE TEMPLATE
====================================================================================================
| Condition | Scenario | Question | Total Claims ($N_{tot}$) | Unsupported ($N_{uns}$) | UCR (%) | High Severity | Med Severity | Low Severity | Observational Pattern Label |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| Baseline  | SX       | Q1       |          |               |         |               |              |              |                             |
| Baseline  | SX       | Q2       |          |               |         |               |              |              |                             |
| Baseline  | SX       | Q3       |          |               |         |               |              |              |                             |
| Baseline  | SX       | Q4       |          |               |         |               |              |              |                             |
| Prototype | SX       | Q1       |          |               |         |               |              |              |                             |
| Prototype | SX       | Q2       |          |               |         |               |              |              |                             |
| Prototype | SX       | Q3       |          |               |         |               |              |              |                             |
| Prototype | SX       | Q4       |          |               |         |               |              |              |                             |
| Baseline  | SY       | Q1       |          |               |         |               |              |              |                             |
| Baseline  | SY       | Q2       |          |               |         |               |              |              |                             |
| Baseline  | SY       | Q3       |          |               |         |               |              |              |                             |
| Baseline  | SY       | Q4       |          |               |         |               |              |              |                             |
| Prototype | SY       | Q1       |          |               |         |               |              |              |                             |
| Prototype | SY       | Q2       |          |               |         |               |              |              |                             |
| Prototype | SY       | Q3       |          |               |         |               |              |              |                             |
| Prototype | SY       | Q4       |          |               |         |               |              |              |                             |
```

---

## 9. Pre-Pilot Rehearsal & Debrief Protocol

### Pre-Pilot Rehearsal Checklist (Testing Concrete Difficulty Mismatches):
Before administering the protocol to the study cohort, conduct **two rehearsal sessions** with 1–2 non-study practitioners using prepared evaluation fixtures only. Rehearsal participants are excluded from the main study cohort.

The rehearsal must evaluate concrete procedural and cognitive mismatches across tasks:
1. **Unfamiliar Schema Knowledge Load**: Does Scenario Y demand vendor schema knowledge (e.g. CAPE root nesting) that Scenario X does not? If so, clarify the scenario briefing.
2. **Pointer Navigation & File Inspection Load**: Does one scenario require navigating significantly more JSON pointers, larger file sizes, or more windows than the other?
3. **Evidence Completeness**: Are all specific data points needed to answer every question verified to exist in the supplied JSON fixtures?
4. **Rubric Inference Symmetry**: Does one rubric reward an inference that the other scenario never asks the participant to make?
5. **Answer Leakage**: Does question phrasing accidentally reveal the intended answer or bias the participant toward a specific conclusion?
6. **Equal Evidence Access & Timing Parity**: Can both conditions be completed with equal access to evidence within the 12-minute budget?
7. **Dual-Reviewer Calibration**:
   - Both evaluators independently score the anonymized rehearsal answer sheets.
   - Compare claim segmentation (what counts as a discrete claim), rubric points assigned, and severity classifications.
   - Reconcile differences; document arbitration rules.
8. **Version-Locking Rule**: If any task, rubric, instruction, or briefing text is modified as a result of rehearsal, the protocol version is formally incremented (e.g. to Protocol v5.1) and documented before main cohort recruitment.

### Post-Pilot Structured Debrief (Phase 4):
1. **Task-Based Observation (Capture Unaided vs Prompted)**:
   - *"What, if anything, would you do differently after seeing this output?"*
   - *"Which conclusions can you support directly from the evidence shown?"*
   - *"What would you still need to verify in the raw reports?"*
   - *"What, if anything, was less useful or more confusing than your usual workflow?"*
   - *(Evaluator Rule: Record whether insights were reached unaided or only after interviewer explanation. Do not count prompted conclusions as evidence of independent tool efficacy).*
2. **Pointer Verification Reality**:
   - *"Did you inspect the source-resolvable pointers, or did you rely primarily on the summary table?"*
3. **Adoption Blockers**:
   - *"What would prevent your team from adopting a CLI comparator in your daily investigation pipeline?"*
4. **Concrete Follow-up Commitment**:
   - *"Subject to formal employer and data-owner authorization under our data-handling protocol, would your team be willing to test this on 2–3 sanitized internal reports in a follow-up trial?"*
   - *(Evaluation Standard: Treat agreement as a concrete follow-up commitment—not as proof of purchasing intent, commercial adoption, or product-market fit).*
