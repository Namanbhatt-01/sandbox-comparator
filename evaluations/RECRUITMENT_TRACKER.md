# Main Cohort Recruitment & Screening Tracker (Milestone 5)

**Protocol Version**: `v5.1 Locked Baseline`  
**Technology Baseline**: `dfec53743414b3cc95f48b20f74e84ad1f885469` (`dfec537`)  
**Target Sample**: 5 to 8 Qualified Practitioners (Pre-allocated Blocks 1 & 2)  
**Quarantine Notice**: Rehearsal participants R1 and R2 are permanently quarantined and excluded from this cohort.  
**Outreach Target Pool**: 14 Target Candidates across DFIR, Malware RE, Threat Intel, and SOC Escalation.

---

## 1. Milestone 5 Execution Checklist (0 / 5 Complete)

```
[ ] 1. Prepare the outreach list
    -> Identify 12–15 real practitioners; role labels are target profiles, not evidence of completed contact.
[ ] 2. Send the first outreach batch
    -> Use the LinkedIn DM or community message from the execution kit; track contact date and response.
[ ] 3. Screen consistently
    -> Ask all five screening questions; record a sanitized, concrete discrepancy and verify the 30-day criterion.
[ ] 4. Assign only after eligibility
    -> Use the locked P1–P8 allocation order; do not assign study IDs until screening and consent are complete.
[ ] 5. Run and capture the session
    -> Use the frozen commit, controlled fixtures, task timer, separate condition scores, and dual reviewer scoring.
```

---

## 2. Candidate Outreach Pool & 5-Question Screening Ledger

> [!IMPORTANT]
> **Decoupling Rule**: Candidate IDs (`C01`–`C14`) represent prospective individuals in the outreach funnel. They are **never** assigned to Study IDs (`P1`–`P8`) until all 5 screening inquiries are completed, verified, and written consent is obtained. Ineligible or withdrawn candidates are documented with full disposition notes; no candidate substitution is permitted into locked slots.

| Cand. ID | Target Role Category | Outreach Channel | Contact Date | Q1: 30d Comp? | Q2: Tools Used | Q3: Concrete Discrepancy Cited? | Q4: Verified Role & Experience | Q5: Availability Window | Screening Disposition | Assigned Study ID |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **C01** | Senior DFIR Consultant | LinkedIn Direct | Pending | [ ] Y [ ] N | *(Pending)* | [ ] Y [ ] N | *(Pending)* | *(Pending)* | [ ] Contact Pending | *(Unassigned)* |
| **C02** | Threat Intel Lead (TI Lead) | Infosec Community | Pending | [ ] Y [ ] N | *(Pending)* | [ ] Y [ ] N | *(Pending)* | *(Pending)* | [ ] Contact Pending | *(Unassigned)* |
| **C03** | SOC Tier 3 Escalation Lead | Direct Message | Pending | [ ] Y [ ] N | *(Pending)* | [ ] Y [ ] N | *(Pending)* | *(Pending)* | [ ] Contact Pending | *(Unassigned)* |
| **C04** | Malware Reverse Engineer | Direct Message | Pending | [ ] Y [ ] N | *(Pending)* | [ ] Y [ ] N | *(Pending)* | *(Pending)* | [ ] Contact Pending | *(Unassigned)* |
| **C05** | Senior Detection Engineer | LinkedIn Direct | Pending | [ ] Y [ ] N | *(Pending)* | [ ] Y [ ] N | *(Pending)* | *(Pending)* | [ ] Contact Pending | *(Unassigned)* |
| **C06** | Incident Response Lead (MDR)| Infosec Community | Pending | [ ] Y [ ] N | *(Pending)* | [ ] Y [ ] N | *(Pending)* | *(Pending)* | [ ] Contact Pending | *(Unassigned)* |
| **C07** | CSIRT Technical Analyst | Direct Message | Pending | [ ] Y [ ] N | *(Pending)* | [ ] Y [ ] N | *(Pending)* | *(Pending)* | [ ] Contact Pending | *(Unassigned)* |
| **C08** | Threat Hunting Specialist | LinkedIn Direct | Pending | [ ] Y [ ] N | *(Pending)* | [ ] Y [ ] N | *(Pending)* | *(Pending)* | [ ] Contact Pending | *(Unassigned)* |
| **C09** | DFIR Analyst (Enterprise) | Infosec Community | Pending | [ ] Y [ ] N | *(Pending)* | [ ] Y [ ] N | *(Pending)* | *(Pending)* | [ ] Contact Pending | *(Unassigned)* |
| **C10** | Detection Engineer (Endpoint)| Direct Message | Pending | [ ] Y [ ] N | *(Pending)* | [ ] Y [ ] N | *(Pending)* | *(Pending)* | [ ] Contact Pending | *(Unassigned)* |
| **C11** | Threat Intel Researcher | LinkedIn Direct | Pending | [ ] Y [ ] N | *(Pending)* | [ ] Y [ ] N | *(Pending)* | *(Pending)* | [ ] Contact Pending | *(Unassigned)* |
| **C12** | Reverse Engineer (Binary) | Infosec Community | Pending | [ ] Y [ ] N | *(Pending)* | [ ] Y [ ] N | *(Pending)* | *(Pending)* | [ ] Contact Pending | *(Unassigned)* |
| **C13** | SOC Tier 3 Incident Lead | Direct Message | Pending | [ ] Y [ ] N | *(Pending)* | [ ] Y [ ] N | *(Pending)* | *(Pending)* | [ ] Contact Pending | *(Unassigned)* |
| **C14** | Senior DFIR Consultant | LinkedIn Direct | Pending | [ ] Y [ ] N | *(Pending)* | [ ] Y [ ] N | *(Pending)* | *(Pending)* | [ ] Contact Pending | *(Unassigned)* |

*Disposition Values*: `Contact Pending`, `In Screening`, `Ineligible (Failed Q1/Q3)`, `Eligible (Awaiting Consent)`, `Consented & Assigned`, `Withdrawn`.

---

## 3. Confirmed Participant Allocation & Scheduling Table

Only candidates with disposition **`Consented & Assigned`** are entered into this table, assigned strictly in order to the next available Study ID (`P1` through `P8`):

```
+-------+----------+----------------+-----------------------------------+-----------------------------------+---------------+--------------+---------------------+-------------------+
| Block | Study ID | Assigned Group | Task 1 (First Session)            | Task 2 (Second Session)           | Confirmed CID | Consent Date | Scheduled Date/Time | Session Completed |
+-------+----------+----------------+-----------------------------------+-----------------------------------+---------------+--------------+---------------------+-------------------+
| 1     | P1       | Group B        | Scenario Y — Manual Baseline      | Scenario X — Evidence Prototype   | [Awaiting]    | —            | —                   | [ ] Incomplete    |
| 1     | P2       | Group D        | Scenario Y — Evidence Prototype   | Scenario X — Manual Baseline      | [Awaiting]    | —            | —                   | [ ] Incomplete    |
| 1     | P3       | Group A        | Scenario X — Manual Baseline      | Scenario Y — Evidence Prototype   | [Awaiting]    | —            | —                   | [ ] Incomplete    |
| 1     | P4       | Group C        | Scenario X — Evidence Prototype   | Scenario Y — Manual Baseline      | [Awaiting]    | —            | —                   | [ ] Incomplete    |
+-------+----------+----------------+-----------------------------------+-----------------------------------+---------------+--------------+---------------------+-------------------+
| 2     | P5       | Group C        | Scenario X — Evidence Prototype   | Scenario Y — Manual Baseline      | [Awaiting]    | —            | —                   | [ ] Incomplete    |
| 2     | P6       | Group A        | Scenario X — Manual Baseline      | Scenario Y — Evidence Prototype   | [Awaiting]    | —            | —                   | [ ] Incomplete    |
| 2     | P7       | Group D        | Scenario Y — Evidence Prototype   | Scenario X — Manual Baseline      | [Awaiting]    | —            | —                   | [ ] Incomplete    |
| 2     | P8       | Group B        | Scenario Y — Manual Baseline      | Scenario X — Evidence Prototype   | [Awaiting]    | —            | —                   | [ ] Incomplete    |
+-------+----------+----------------+-----------------------------------+-----------------------------------+---------------+--------------+---------------------+-------------------+
```

---

## 4. Partial-Cohort Gate Evaluation Standard ($N < 8$)

The locked protocol defines the primary adoption gate standard:
> **Specialized Workflow Tool Gate**: $\ge 5$ of 8 practitioners pass Dimensions 1–4, AND at least **2 practitioners commit to reviewing sanitized organizational reports under the Data Handling Protocol**.

### Handling Cohorts Smaller than Eight ($N = 5, 6, \text{ or } 7$):
- **Preserve Locked Standard**: The 5-of-8 threshold is mathematically fixed to an 8-practitioner balanced crossover design.
- **Reporting Rule**: If recruitment concludes with fewer than 8 participants (e.g. $N=5, 6, \text{ or } 7$):
  1. The gate outcome is reported strictly as **`Not Fully Evaluable (Incomplete Cohort: N/8 completed)`** against the formal 8-participant standard.
  2. Evaluators report the descriptive proportions (e.g. $4/6$ or $5/7$ passed Dimensions 1–4) without adjusting the threshold post-hoc or claiming statistical significance.
  3. No post-hoc re-weighting or subjective threshold reduction is permitted.

---

## 5. Discrepancy Verification Checklist (Screening Gate Q3)

Before marking a candidate as **Eligible**, verify that their response to Q3 represents a genuine, sanitized operational discrepancy:

- [ ] **Hash / Payload Naming Discrepancy**: A dropped file had different file names or paths in two environments despite matching cryptographic hash metadata.
- [ ] **Execution / Process Tree Divergence**: An intermediate command-line wrapper (e.g. `cmd.exe /c` or PowerShell cradle) or child process was logged in one environment but collapsed or omitted in another.
- [ ] **Network Egress Omission vs Policy Block**: An outbound connection appeared in one sandbox but was missing in another due to egress filtering, timeout, or simulation boundary.
- [ ] **Portal Flattening Anomaly**: A multi-engine threat portal (e.g. VirusTotal) listed IOCs as a flat set, obscuring which sandbox observed which artifact or destroying parent-child execution order.

*Candidates citing purely hypothetical interest without a concrete 30-day incident are marked Ineligible.*
