# Sandbox Comparator — Architectural Reference & Technical Specification

## 1. System Mission & Core Paradigm

The **Evidence-Aware Sandbox Comparator** is a specialized, air-gapped forensic reconciliation engine engineered to solve **cross-sandbox telemetry divergence** in malware analysis and digital forensics / incident response (DFIR).

When identical malware samples run in disparate sandboxes (e.g., CAPE Sandbox, CrowdStrike Falcon Sandbox, Joe Sandbox, Hatching Triage), observed behaviors often disagree due to:
1. **Dynamic Execution Stochasticity**: Randomized process IDs (PIDs), dynamic memory addresses, temporary directory staging, GUID mutation.
2. **Collection Limitations**: Per-sandbox execution timeouts (e.g., 60s cap), hypervisor evasion, synthetic user interaction deficiencies.
3. **Environment Policies**: Sandbox network egress filtering, sinkholing, or protocol translation blocking outbound C2.
4. **Schema Heterogeneity**: Incompatible report JSON topologies, nested process dictionaries versus flat event streams.

Traditional approaches either merge telemetry uncritically (masking evasion and creating unverified consensus) or perform naive syntactic text diffing (producing uninterpretable noise).

The Sandbox Comparator solves this via **three foundational pillars**:
- **Epistemic Disentanglement**: Strict separation between *observation presence* (whether an event was recorded) and *causal explanation* (why it occurred or was omitted).
- **Global Optimal Bipartite Matching**: Linear sum assignment (Munkres algorithm) over calibrated multi-dimensional feature similarity matrices to reconcile process lineages across randomized PIDs.
- **Strict RFC 6901 Evidence Provenance**: Every reconciled node links back to its exact JSON pointer (`/behavior/processes/0`, `/execution/created_files/1`) in the raw vendor export for unassailable forensic auditability.

---

## 2. High-Level System Architecture

```
                    +------------------------------------+
                    |        Air-Gapped Raw Reports      |
                    |  (CAPE v2 JSON, Falcon JSON, etc.) |
                    +-----------------+------------------+
                                      |
                     [engine.parsers.auto_detector]
                                      |
                    +-----------------v------------------+
                    |    Normalized Canonical Schemas     |
                    | (NormReport, NormProc, NormFile)   |
                    +-----------------+------------------+
                                      |
                     [engine.reconciler.EvidenceComparator]
                                      |
           +--------------------------+--------------------------+
           |                                                     |
+----------v-----------+                              +----------v-----------+
|  Process Reconciliation |                              | File Reconciliation  |
|  - Jaccard Token Sim |                              | - SHA-256 Exact Hash |
|  - Lineage Path Tree |                              | - Malformed Detection|
|  - Global Assignment |                              | - Causal Attribution |
+----------+-----------+                              +----------+-----------+
           |                                                     |
           +--------------------------+--------------------------+
                                      |
           +--------------------------+--------------------------+
           |                                                     |
+----------v-----------+                              +----------v-----------+
| Network Reconciliation|                              | Limitations Modeling |
| - Protocol / IP / Port|                             | - Egress Filtering   |
| - Policy Record Link |                              | - Execution Timeouts |
+----------+-----------+                              +----------+-----------+
                                      |
                    +-----------------v------------------+
                    |     Synthesized Forensic Output    |
                    |  (Analysis Summary + ATT&CK + Diff)|
                    +-----------------+------------------+
                                      |
           +--------------------------+--------------------------+
           |                                                     |
+----------v-----------+                              +----------v-----------+
|   Local-First Web UI  |                             |   High-Speed Rust CLI|
| (127.0.0.1 Air-Gapped)|                             |   (rust/src/lib.rs)  |
+----------------------+                              +----------------------+
```

---

## 3. Dual-Engine Architecture: Python & Rust Core

The Sandbox Comparator is engineered with a **dual-engine architecture** ensuring both rich ecosystem integration and high-throughput batch evaluation:

### 3.1 Python Reference Engine (`engine/`)
- **FastAPI Backend (`web/app.py`)**: Asynchronous, local-loopback-only web service (`127.0.0.1:8000`) serving the Corelight Investigator-style analytical dashboard.
- **Scipy & NumPy Optimization**: High-performance linear sum assignment (`scipy.optimize.linear_sum_assignment`) solving global bipartite graph matching in milliseconds.
- **Pydantic Validation**: Canonical schemas enforcing type guarantees across varied JSON inputs.

### 3.2 Standalone Rust Core (`rust/`)
- **High-Throughput Ingestion**: Compiled native binary leveraging `serde_json` and zero-copy deserialization for enterprise batch processing pipelines.
- **Deterministic Parity**: Guarantees identical heuristic similarity scoring, threshold filtering (0.45 lower bound), and RFC 6901 pointer resolution verified through integration test suites (`rust/tests/test_parity.rs`).
- **Memory Safety**: UTF-8 boundary slicing guards (`char_indices`) preventing panics on truncated multi-byte internationalized strings.

---

## 4. Reconciler Algorithm & Heuristic Scoring

Process reconciliation evaluates candidates through a weighted multi-factor heuristic model:

$$\text{Similarity}(P_A, P_B) = w_{\text{img}} \cdot S_{\text{img}} + w_{\text{cmd}} \cdot S_{\text{cmd}} + w_{\text{anc}} \cdot S_{\text{anc}} + w_{\text{dep}} \cdot S_{\text{dep}}$$

Where:
- $S_{\text{img}}$: Executable basename identity (exact match = 1.0, case-insensitive match = 0.9, mismatch = 0.0).
- $S_{\text{cmd}}$: Command-line argument token Jaccard similarity:
  $$J(A, B) = \frac{|T_A \cap T_B|}{|T_A \cup T_B|}$$
- $S_{\text{anc}}$: Ancestor lineage overlap ratio, evaluating the parent-child chain back to the initial execution root.
- $S_{\text{dep}}$: Execution tree depth alignment penalty.

Matches are partitioned into:
- **`MATCHED`** ($\ge 0.70$): High-confidence corroborated process execution.
- **`POSSIBLE_MATCH`** ($0.45 \le \text{Score} < 0.70$): Ambiguous candidate requiring analyst inspection.
- **`UNRESOLVED`** ($< 0.45$): Single-report execution or uncorroborated anomaly.

---

## 5. RFC 6901 Provenance Model

Every reconciled artifact links to its origin through standard RFC 6901 JSON Pointers. When an analyst clicks an evidence badge in the UI:
1. The pointer URI (`rfc6901:///behavior/processes/0`) retrieves the exact JSON subtree from the in-memory report.
2. The Evidence Inspector drawer renders:
   - The JSON pointer string.
   - Telemetry summary.
   - Epistemic interpretation (distinguishing observed presence from non-occurrence).
   - Pretty-printed raw JSON snippet formatted for chain-of-custody documentation.
