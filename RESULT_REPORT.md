# Evidence-Aware Sandbox Comparator: Engineering & Audit Report (Milestone 4 -> 5)

**Status**: Milestone 4 Engineering Hardening, Holdout Audit, CAPE v2 Schema Ingestion & Pre-Rehearsal Lock Complete  
**Codebase**: [`sandbox_comparator/`](file:///Users/namanbhatt/cfp/sandbox_comparator)  
**Execution Command**: `python3 cli.py --format markdown`  
**Test Suite**: `python3 -m unittest test_prototype.py test_calibration_and_semantics.py test_holdout_and_provenance.py test_real_cape_ingestion.py` (**23 passed, 0 failed, 0 errors**)  

---

## Executive Summary & Engineering Verdict

> [!IMPORTANT]
> **Verdict: Prototype Frozen; Rehearsal Protocol Version-Locked; Ready for Dry Run.**  
> Feature development is strictly frozen (no cloud backends, AI summarizers, or web UIs) to prioritize workflow validation with 5–8 practitioners. This milestone resolves all methodological, semantic, and experimental design caveats:
> 1. **Scenario-Driven Modular Scoring Sheet**: Corrected the evaluation form in [`PILOT_PACKET.md`](file:///Users/namanbhatt/cfp/sandbox_comparator/PILOT_PACKET.md) to select rubrics dynamically by the administered scenario (Scenario X vs Scenario Y), fully supporting the counterbalanced crossover design for all four groups (A, B, C, D) without scoring key mismatch.
> 2. **Reported Hash Metadata Scope**: Documented that Scenario X fixtures contain controlled synthetic report metadata. The comparator verifies **reported SHA-256 metadata equivalence across JSON reports**; it does not claim independent binary-level re-hashing from disk images. Automated tests verify that cited RFC 6901 pointers resolve to exact matching 64-character digests (`a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0`).
> 3. **Non-Causal Cohort-Level Error Analysis**: Formally separated condition-level UCR comparisons from individual paired crossover claims. Observational patterns are categorized using descriptive labels (*Observed only in baseline responses*, *Observed only in prototype responses*, *Observed across both*), acknowledging that cohort differences do not establish tool causality.
> 4. **Incomplete Task Scoring Rules**: Predefined that incomplete tasks (censored at 720s) report points earned on attempted questions, with the full-task proficiency benchmark ($\ge 17/20$) marked **Not Assessable (Incomplete Task)**, avoiding conflating speed with correctness.
> 5. **Neutral Task-Based Interview Inquiries**: Replaced hypothetical benefit questions in [`INTERVIEW_PROTOCOL.md`](file:///Users/namanbhatt/cfp/sandbox_comparator/INTERVIEW_PROTOCOL.md) with task-based observation probes, made VirusTotal inquiries conditional on actual usage, and separated unaided observations from guided walkthrough comprehension.
> 6. **Sanitized CAPE v2.2 Schema Export Fixture Provenance**: Documented `data/real_sanitized_cape_v2_export.json` as a sanitized CAPE v2.2 schema export fixture, derived from native CAPE Sandbox v2.2 reporting structures with RFC 5737 documentation blocks, anonymized paths, and synthetic mutexes. All generated pointers resolve bidirectionally.
> 7. **Achievable Cryptographic Erasure Safeguards**: Refined the data-handling protocol to specify storage on a dedicated encrypted virtual volume, 30-day maximum retention, and volume encryption key destruction (cryptographic erasure), separating individual interview consent from formal employer/data-owner authorization.

---

## 1. Disentangled Telemetry Semantics & Provenance Resolution

The comparator strictly separates recorded observations from analytical inferences:

| Entity | Observation Presence | Connection State / Type | Causal Status | Specific Policy Record | Evidence Pointers | Epistemic Interpretation |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`update_payload.exe` / `staged_runner.bin`** | `OBSERVED_IN_BOTH` | `REPORTED_HASH_MATCH` | `CONFIRMED` | *(None)* | A: `/behavior/dropped/0`<br>B: `/execution/created_files/0` | Reconciled across runs by reported SHA-256 hash metadata despite naming discrepancy. |
| **`mutex_flag.tmp`** | `OBSERVED_ONLY_IN_A` | `FILE_OBSERVATION` | `POTENTIAL_ENVIRONMENT_LIMITATION` | *(None)* | A: `/behavior/dropped/1` | Observed in A; Report B hit execution timeout at 60s; non-occurrence is unconfirmed. |
| **`crash_reporter.log`** | `OBSERVED_ONLY_IN_B` | `FILE_OBSERVATION` | `UNEXPLAINED` | *(None)* | B: `/execution/created_files/1` | Observed in B; Report A telemetry omits this file without recorded limitations. |
| **`TCP://203.0.113.88:8080`** | `OBSERVED_ONLY_IN_A` | `UNKNOWN` (Socket log without handshake proof) | `PLAUSIBLE_HYPOTHESIS` | Report B [WARN_EGRESS_POLICY]: Blocked non-standard TCP ports (8080). | Observation: `/behavior/network/tcp/1`<br>Policy Record: `/submission_info/system_warnings/1` | TCP observation present in Report A; Report B contains a general egress-policy warning mentioning port 8080; relationship between the records is not established. Address is RFC 5737 TEST-NET-3 documentation prefix. |

---

## 2. Process Matching Calibration & Holdout Audit

### Development vs. Holdout Set Metrics

```
+------------------------------------+--------------------------+------------------------------+------------------------------------+
| Metric (Holdout Evaluation Set)    | Simple Baseline Matcher  | Calibrated Heuristic Matcher | Exact 95% Binomial CI (Heuristic)  |
+------------------------------------+--------------------------+------------------------------+------------------------------------+
| True Positives (TP)                | 8 / 8                    | 8 / 8                        | [63.1%, 100.0%]                    |
| False Positives (FP)               | 7 / 8                    | 2 / 8                        | [3.2%, 65.1%]                      |
| True Negatives (TN)                | 1 / 8                    | 6 / 8                        | [34.9%, 96.8%]                     |
| False Negatives (FN)               | 0 / 8                    | 0 / 8                        | [0.0%, 36.9%]                      |
| Precision                          | 53.3%                    | 80.0% (+26.7%)               | [44.4%, 97.5%]                     |
| Recall (Sensitivity)               | 100.0%                   | 100.0%                       | [63.1%, 100.0%]                    |
| False Match Rate                   | 87.5%                    | 25.0% (-62.5%)               | [3.2%, 65.1%]                      |
| F1-Score                           | 0.696                    | 0.889 (+27.7%)               | N/A                                |
+------------------------------------+--------------------------+------------------------------+------------------------------------+
```

### Statistical Qualifications & Audit Findings
- **Sample Size Sensitivity**: On $N=16$ holdout pairs (8 positive, 8 negative), a single additional false positive drops precision from 80.0% to 72.7%.
- **Prevalence Dependence**: The reported 80.0% precision is conditional on this corpus's 50% positive-pair prevalence. In enterprise workloads where true process matches are rarer, precision will be lower.
- **Independence Audit**: Every pair in `get_holdout_evaluation_corpus()` has a verified `provenance_family` and `ground_truth_rationale`. Command lines, GUIDs, and arguments were held strictly out-of-sample and never used to tune baseline weights or rules.

---

## 3. Sanitized CAPE v2 Schema Ingestion Audit

To test beyond synthetic approximations, the parser was audited against a native CAPE Sandbox v2 format export fixture (`data/real_sanitized_cape_v2_export.json`):
1. **Schema Format & Version**: Successfully parsed native `2.2-CAPE` report format.
2. **Parsed Entities**: Accurately extracted primary sample SHA-256, 4 processes with full execution lineages, 2 dropped files, and 4 network events.
3. **Surfaced Unsupported Fields**: Explicitly surfaced unmapped vendor sections under `unsupported_fields` (`signatures`, `memory`, `apistats`, `debug`, `behavior.summary.keys`, `behavior.summary.mutexes`) rather than silently discarding them.
4. **Pointer Resolution**: 100% of generated RFC 6901 pointers resolve bidirectionally against source keys (`/dropped/0`, `/network/tcp/1`, `/behavior/processes/2`).

---

## 4. Disaggregated Pipeline Profiling ($N=100$)

- **Environment**: Single-threaded Python 3.9 on Apple Silicon (macOS).
- **Warm-Up**: 10 initial iterations discarded to prime OS caches and bytecode execution.
- **Input Metadata**: Report A (3,518 bytes), Report B (3,376 bytes), Total Fixture (6,894 bytes).
- **Phase Breakdown**:
  - **File I/O Ingestion**: Mean `0.051 ms` (Median `0.048 ms`)
  - **Schema Parsing & Normalization**: Mean `0.142 ms` (Median `0.138 ms`)
  - **Entity Matching & Reconciliation**: Mean `0.108 ms` (Median `0.102 ms`)
  - **RFC 6901 Pointer Resolution Check**: Mean `0.045 ms` (Median `0.042 ms`)
- **End-to-End Latency**: Mean `0.353 ms` | Median `0.332 ms` | p95 `0.412 ms`
- **Measurement Boundary Accounting**: Sum of phase means is $0.346\text{ ms}$; total end-to-end mean is $0.353\text{ ms}$. The $0.007\text{ ms}$ delta represents timer call resolution overhead (`time.perf_counter`) and intermediate variable assignments between measurement blocks.
- **Workload Framing**: Pure machine execution ($< 1\text{ ms}$) must never be conflated with human triage. The estimated 60–120s prototype cognitive review and 18-minute VirusTotal manual workflow model are preliminary hypotheses to be empirically tested during the pilot.

---

## 5. Experimental Controls & Protocol Hardening

The pilot protocol ([`PILOT_PACKET.md`](file:///Users/namanbhatt/cfp/sandbox_comparator/PILOT_PACKET.md)) incorporates eight audited safeguards:

1. **Predefined Randomized Block Allocation**: Participants are allocated using predefined randomized blocks of four across Groups A, B, C, and D generated with fixed seed `RANDOM_SEED = 20261028`, with strict sequential assignment from Block 2 for partial cohorts ($N=5, 6, \text{ or } 7$). Rehearsal participants (R1, R2) are excluded from the study cohort.
2. **Fair Baseline Standards**: Condition A is designated as a *Manual Reference-Report Baseline* with access to the exact same raw JSON files and reference data. Missing source fields in fixtures count as unavailable, not participant error.
3. **Domain-Specific 20-Point Rubric**: Replaced generic grading with question-specific criteria tailored to each task (reported metadata SHA-256 equivalence verification, lineage alignment, presence vs causality, attribution boundaries).
4. **4-Metric Task Outcome Reporting**: Unattempted questions are counted as *Not Completed / Unattempted* (not automatically 0/5 incorrect). Every session reports completion status, questions attempted ($k/4$), points earned ($X/20$), and task time ($T$ sec or $720\text{s censored}$). The 20-point benchmark ($\ge 17/20$, 85%) is marked **`Not Assessable (Incomplete Task)`** for incomplete sessions to avoid confounding speed with correctness.
5. **Non-Causal UCR Reporting Breakdown**: Unsupported claims are reported stratified by **Condition $\times$ Scenario $\times$ Question**, with raw counts ($N_{unsupported}, N_{total}$) and severity breakdowns. Evaluated at the cohort level using non-causal observational labels (*Observed only in prototype responses*, *Observed only in baseline responses*, *Observed across both*). Causal language is strictly prohibited. Multiple claims from a single participant are not treated as independent observations.
6. **Exploratory Pilot Benchmark**: Target is defined as $UCR_B \le 0.5 \times UCR_A$ when $UCR_A > 0$, or $UCR_B = 0$ when $UCR_A = 0$ as a non-regression target. Broad statistical superiority claims are explicitly avoided for small cohorts.
7. **Verifiable Cryptographic Erasure Protocol**: External telemetry and session artifacts reside on a dedicated APFS encrypted sparse bundle. Erasure is verified by unmounting, deleting the isolated keychain entry, overwriting keybag bands with random bytes, and deleting the bundle directory. Rehearsal and initial pilot sessions use prepared evaluation fixtures only.
8. **Neutral Interview Protocol & Unaided vs Prompted Tracking**: [`INTERVIEW_PROTOCOL.md`](file:///Users/namanbhatt/cfp/sandbox_comparator/INTERVIEW_PROTOCOL.md) separates Phase 4 into unaided inspection, guided walkthrough, and debrief. Prompted insights are explicitly barred from being counted as independent tool accuracy improvements. Follow-up agreement is evaluated as a trial commitment, not market validation.

---

## 6. Three-Tier Adoption Gates for Milestone 5

| Gate | Evidentiary Standard | Status |
| :--- | :--- | :--- |
| **Gate 1: Technical Integrity** | Ingestion of sanitized CAPE v2.2 schema export fixture; 100% pointer resolution against fixture; unmapped vendor sections surfaced. Validates compatibility with this schema fixture (not universal compatibility across all CAPE variants). | **PASSED** (23 automated unit tests). |
| **Gate 2: Pilot Protocol Integrity** | Predefined randomized block crossover design ($N=5\text{ to }8$); 4-metric task reporting; non-causal UCR breakdown; verified cryptographic erasure protocol; neutral 3-step Phase 4 interview guide. | **PASSED** (Audited and version-locked in `PILOT_PACKET.md` v5.0 and `INTERVIEW_PROTOCOL.md` v5.0). |
| **Gate 3: Pre-Pilot Rehearsal & Decision Gate** | Two dry-run rehearsal sessions testing schema knowledge load, pointer navigation load, evidence presence, and dual-reviewer calibration; followed by controlled pilot with $N=5\text{ to }8$. | **READY FOR PRE-PILOT REHEARSAL**. |
