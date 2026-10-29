# Evidence-Aware Sandbox Comparator

[![CI](https://github.com/Namanbhatt-01/sandbox-comparator/actions/workflows/ci.yml/badge.svg)](https://github.com/Namanbhatt-01/sandbox-comparator/actions)
[![Tests: 75 Passing](https://img.shields.io/badge/tests-75%20passing-brightgreen.svg)](tests/)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Architecture: Offline--First](https://img.shields.io/badge/architecture-offline--first-emerald.svg)]()
[![Privacy: Zero--Cloud--Telemetry](https://img.shields.io/badge/telemetry-zero--outbound--telemetry-blue.svg)]()

> **An offline-first behavioral comparison and evidence verification layer for malware sandbox reports.**  
> Sit on top of your existing sandbox exports (CAPE, Falcon, Cuckoo) to reconcile divergent execution traces, correlate transient PIDs, isolate environment dropouts, and verify every analytical conclusion against RFC 6901 source pointers.

---

## 1. Five-Minute First-Run Quickstart

Follow this 5-minute route to install, launch, inspect a finding, and verify the test suite:

### Step 1: Install Package Locally
Clone and install into your local environment (requires Python 3.9+):
```bash
git clone https://github.com/Namanbhatt-01/sandbox-comparator.git
cd sandbox-comparator
pip install -e .
```
*(Or run `make install`)*

### Step 2: Launch the Local Web Workspace
Start the local dashboard (default bind is strictly `127.0.0.1:8000`):
```bash
sandbox-comparator ui
# Or: make ui
```
Your browser will open automatically at `http://127.0.0.1:8000`.

### Step 3: Inspect a Finding
1. Click **"Scenario Y: Schema Divergence (CAPE v2.4 vs Synthetic Falcon-approx)"** on the top panel.
2. Under the **Process Trees** tab, note how `invoice_oct2026.exe` is matched despite divergent PIDs (`PID 3420` vs `PID 4112`).
3. Click the blue RFC 6901 pointer link (`🔍 /behavior/processes/0/process_name`) to slide open the raw JSON evidence drawer and inspect the source evidence.

### Step 4: Run CLI Comparison & Export
Compare two reports directly in your terminal and generate an executive Markdown diff:
```bash
sandbox-comparator compare \
  --report-a data/report_format_a_cape.json \
  --report-b data/report_format_b_falcon.json \
  --output diff.md
```

### Step 5: Verify Test Suite
Run the complete test suite (58 Python tests, 17 Rust parity tests, DOM XSS tests, and offline privacy verification):
```bash
make test-all
# Or: make test && make dom-test && make rust-test
```

---

## 2. Why Sandbox Comparator?

Security analysts frequently submit malware to multiple sandboxes or execute repeated analysis runs to observe evasive behaviors. However, comparing two multi-megabyte JSON reports manually in browser tabs or running naive text diffs leads to acute cognitive fatigue and analytical errors:
- **Identifier Drift**: Ephemeral Process IDs (PIDs) change across every run, causing text diffs to show 100% divergence even when identical commands executed.
- **Payload Naming Discrepancies**: The same dropped artifact may be logged under different filenames or transient paths (`%TEMP%` vs `%APPDATA%`).
- **Unwarranted Attribution Leaps**: Analysts frequently assume that an omitted network connection represents intentional anti-analysis evasion, failing to notice that the second sandbox timed out or hit an egress firewall rule.
- **Privacy & Sensitivity**: Organizations cannot upload sensitive internal incident triage reports to public multi-engine SaaS platforms without triggering compliance violations.

**Sandbox Comparator solves this locally:**
1. **Behavioral Normalization**: Maps diverse vendor schemas into a common behavioral model (processes, dropped files, sockets, limitation warnings).
2. **Anchor-Preserving Greedy Bipartite Matching**: Deterministically aligns process trees using multi-factor similarity heuristics (image name, command-line arguments, ancestry depth) with intrinsic attribute tie-breaking, preserving unambiguous anchor matches without relying on volatile PIDs.
3. **Causal Limitation Attribution**: Contextually correlates absent telemetry with runtime boundaries (firewall blocks, execution timeouts) rather than speculating about evasive malware actions.
4. **Source Evidence Provenance**: Every matched or missing entity links directly to an RFC 6901 JSON pointer identifying the corresponding value within the parsed source document structure.
5. **100% Offline-First Execution**: Runs entirely on your local machine with zero external network requests or font imports.

---

---

## 3. Concrete Demonstration Walkthrough

When comparing the reference test fixtures `data/report_format_a_cape.json` (CAPE Sandbox v2.4 export) against `data/report_format_b_falcon.json` (Synthetic Falcon-like approximation fixture):

1. **Unambiguous Anchor Match (`invoice_oct2026.exe`)**:
   - Report A logs `PID 3420`; Report B logs `PID 4112`.
   - The engine scores the pair at `1.00` based on exact image name match, identical command line, and tree root depth, establishing `MATCHED` / `CORROBORATED_EXECUTION` without PID dependence.
2. **Ambiguous Process Alignment (`update_payload.exe` vs `staged_runner.bin`)**:
   - Report A observed `PID 3840` (`update_payload.exe /quiet`); Report B observed `PID 4500` (`staged_runner.bin --install`).
   - Image names differ, but both share common parentage under `powershell.exe` and tree depth 2.
   - The engine computes heuristic similarity score `0.45`, categorizing it as `POSSIBLE_MATCH (AMBIGUOUS)` and preserving alternative candidates in the evidence ledger rather than falsely claiming definitive identity.
3. **Causal Attribution of Network Divergence (`TCP://203.0.113.88:8080`)**:
   - Report A logged outbound socket traffic to port 8080; Report B recorded no socket events for this endpoint.
   - Rather than inferring evasive behavior, the engine inspects Report B's runtime limitations and correlates this absence with `WARN_EGRESS_POLICY_BLOCK` (`/submission_info/system_warnings/0`), explaining that egress filtering in Sandbox B prevented observation.

---

## 4. Workspace Features & CLI Usage

### Local Web Workspace
- **Curated Evaluation Presets**: Instant one-click loading of *Scenario Y (Schema Divergence: CAPE v2.4 fixture vs Synthetic Falcon approximation)* and *Scenario X (Structural Variation: CAPE v2.4 fixture vs Sanitized CAPE v2.2 native fixture)*.
- **Zero-Cloud Drag-and-Drop**: Drag any two sandbox JSON reports directly into the browser. Raw files are parsed in-memory on your CPU without uploading to any external server.
- **RFC 6901 Evidence Inspector**: Click any pointer to slide open the raw JSON evidence snippet and inspect provenance boundaries.
- **One-Click Export**: Export an executive Markdown reconciliation diff (`.md`) or structured JSON delta.

### Command-Line Interface (CLI)

**Python CLI**:
```bash
# Compare two reports and print an executive Markdown diff
sandbox-comparator compare --report-a data/report_format_a_cape.json --report-b data/report_format_b_falcon.json

# Output structured JSON for automation & SOAR pipelines
sandbox-comparator compare --report-a run1.json --report-b run2.json --format json -o diff.json
```

**High-Performance Standalone Rust CLI**:
For air-gapped forensic jump-boxes or CI/CD pipelines where Python is not installed:
```bash
# Build standalone native binary
make rust-build

# Run native binary directly (sub-5ms execution runtime)
./rust/target/release/sandbox-comparator --report-a data/report_format_a_cape.json --report-b data/report_format_b_falcon.json
```
> **Empirical Performance Benchmark**: Measured over $N=50$ invocations on default fixtures (`report_format_a_cape.json` and `report_format_b_falcon.json`): **Python In-Memory End-to-End Mean: 0.47 ms (p95: 0.61 ms); Rust CLI Full Process Mean: 3.11 ms (p95: 3.65 ms)** (macOS ARM64).

### Python SDK Usage
Integrate the evidence-aware reconciler directly into your DFIR scripts:
```python
import json
from engine.parsers import parse_auto_report
from engine.reconciler import EvidenceComparator

with open("cape_run1.json") as f1, open("falcon_run2.json") as f2:
    norm_a = parse_auto_report(json.load(f1), report_id="cape_run")
    norm_b = parse_auto_report(json.load(f2), report_id="falcon_run")

comparator = EvidenceComparator(norm_a, norm_b)
comparison = comparator.reconcile()

print(f"Sample SHA-256: {comparison.sample_sha256}")
print(f"Reconciled processes: {len(comparison.reconciled_processes)}")
for p in comparison.reconciled_processes:
    print(f"  [{p.confidence.value}] {p.image_name} (Score: {p.heuristic_similarity_score:.2f})")
```

---

## 5. Architecture & Data Privacy

```
+-----------------------------------------------------------------------------------------+
| CLIENT ENVIRONMENT (100% LOCAL & OFFLINE)                                               |
|                                                                                         |
|  [ Modern Dark Web UI ] <======== HTTP / JSON ========> [ Local Python Engine ]         |
|  - Drag-and-Drop Local Files                             - Dynamic Schema Sniffer       |
|  - Interactive Evidence Drawer                           - RFC 6901 Provenance Resolver |
|  - Real-time Markdown Export                             - Anchor-Preserving Matcher    |
|                                                          - Causal Attribution Logic     |
+-----------------------------------------------------------------------------------------+
                                      |
                                      X  NO CLOUD EGRESS / NO TELEMETRY TRANSMITTED
                                      |
                              [ External Internet ]
```

### The Offline-First Security Guarantee
When analyzing proprietary threat intelligence or incident response artifacts, telemetry privacy is non-negotiable. 
- **Strict Loopback Binding**: The local web UI server binds exclusively to `127.0.0.1:8000` by default. Do not expose this server to `0.0.0.0` or untrusted LANs without TLS and authentication.
- **In-Memory Local Processing**: Raw report JSONs are parsed in-memory on your local CPU.
- **Zero External Telemetry or Font Requests**: The interface relies 100% on native system UI fonts; no assets are loaded from Google Fonts, CDNs, or external APIs.

---

## 6. Reconciliation Engine Principles

### 1. Process Alignment: Greedy Score-Sorted Matching with Anchor Preservation
Rather than unconstrained tree traversal or global maximum-weight assignment (e.g., Hungarian algorithm), the reconciler evaluates candidate process pairs above threshold ($\tau \ge 0.45$) and applies greedy score-sorted matching with anchor preservation:
- **Why Greedy Anchor Preservation vs Hungarian Algorithm**: A global maximum-weight assignment algorithm seeks to maximize the *sum* of edge weights across the entire bipartite graph. In adversarial process tree matching, this causes "displacement anomalies": an optimal global solver can break an unmistakable anchor match (e.g. an initial dropper with identical name and arguments scoring `0.95`) to pair it with something else if two marginal child processes (scoring `0.50` each) yield a higher total sum ($0.50 + 0.50 = 1.00 > 0.95$). Security analysts require anchor matches to remain locked first; the greedy algorithm ensures the highest-confidence evidence anchors are never traded away.
- **Intrinsic Deterministic Tie-Breaking**: To eliminate dependency on report list order, ties in candidate scores are broken deterministically by sorting on intrinsic properties (image name, command line, lineage path, source PID).
- **Two-Way Ambiguity Detection**: If another candidate node scores within $\Delta < 0.15$ of the best match—either forward (another B node for this A node) or in reverse (sibling competition: another A node competing for the same B node)—the match is demoted to `POSSIBLE_MATCH (AMBIGUOUS)` and recorded in the evidence ledger.
- **Missing Ancestry Tolerance**: Disjoint ancestry penalties are applied only when *both* reports record non-empty parent lineages that actively conflict. If one sandbox omits parentage, it is treated as unrecorded telemetry rather than contradiction.

### 2. Hash-Collision Resistant File Dedup
Many malware samples write the same binary to multiple persistence locations or drop empty marker files. The engine groups file observations by cryptographic SHA-256 hash without overwriting duplicate drops, preserving every path and pointer. Malformed or missing hashes are isolated from verified hashes and reconciled by path with clear caveats.

### 3. Calibrated Network Semantics
Network records are treated strictly as socket logs:
- **Singleton Endpoint Overlap**: When an endpoint is logged once in both reports without discriminating telemetry (ephemeral source port, PID, or timestamp), it is categorized as `SINGLETON_ENDPOINT_OVERLAP` / `ENDPOINT_MATCH` (`UNEXPLAINED`). It confirms destination contact but does not overclaim a verified stream-level session.
- **Direct Identifier Match**: When connection records share matching discriminating attributes (source port, PID, or synchronized timestamps), they are corroborated as `DIRECT_IDENTIFIER_MATCH` / `CORROBORATED_SOCKET`.
- **Aggregate Endpoint Clustering**: Repeated undifferentiated socket records are grouped into a single `AGGREGATE_ENDPOINT_CLUSTER` rather than arbitrary 1-to-1 pairings.
- **Honest Connection Semantics**: The tool does not assert `ESTABLISHED` or `CONFIRMED` without packet-level capture proving a 3-way handshake or application payload exchange. Omissions are linked contextually to sandbox runtime limitations (e.g., egress firewall blocks or timeouts).

---

## 7. Repository Provenance & Commit Ledger

The `sandbox_comparator` engine originated within a broader malware research monorepo (`apt36-rapidrust-research`) and was extracted into this standalone public repository via `git subtree split`. Because `git subtree split` synthesizes new root-level commits, the commit hashes correspond as follows:

| Milestone / Event | Monorepo Commit | Standalone Repo Commit | Scope & Verified Deliverable |
| :--- | :--- | :--- | :--- |
| **Milestone 5 Pre-Rehearsal Lock** | `dfec537434...` | `fa12a78045...` | Protocol v5.0 pre-pilot baseline lock |
| **Milestone 5 Protocol v5.1 Lock** | `7bf8d1b2a9...` | `a00ceb161d...` | Rehearsal findings, pilot kits, and decoupled trackers |
| **Product MVP & Engine Hardening** | `product-mvp` branch | `product-mvp` branch | Order-independent matcher, hash dedup, local web app |

All fixture hashes in `data/*.json` match the SHA-256 ledger in [`evaluations/PILOT_PACKET.md`](evaluations/PILOT_PACKET.md) with 100% cryptographic parity.

---

## 8. Supported Schemas & Qualification Matrix

| Sandbox Platform | Testing Status | Dataset Qualification | Parser Module |
| :--- | :--- | :--- | :--- |
| **CAPE Sandbox v2.x** | Fully Verified | Tested against real sanitized production CAPE v2.2 & v2.4 JSON dumps (`data/real_sanitized_cape_v2_export.json`) | `engine.parsers.cape_parser` |
| **Falcon Sandbox Cloud** | Synthetic Approximation | Synthesized structural approximation fixture (`data/report_format_b_falcon.json`) for schema divergence validation; real proprietary CrowdStrike Falcon enterprise reports require customer tenant export | `engine.parsers.falcon_parser` |
| **Cuckoo Sandbox v2.x** | Community Mapping | Backward-compatible ingestion via CAPE schema adapter | `engine.parsers.cape_parser` |
| **Custom / Unknown** | Generic Fallback | Schema detector sniffs process, dropped file, and network arrays with defensive error isolation | `engine.parsers.detector` |

---

## 9. Calibration Limitations & Methodology Guardrails

In compliance with scientific transparency and auditability:
- **Heuristic Calibration Corpus**: The empirical similarity matcher was calibrated on $N=16$ development pairs and evaluated on an independent held-out set of $N=16$ pairs ($8$ true matching pairs $+ 8$ non-matching negative/imposter pairs).
- **Evaluation Breakdown & Denominators**:
  - Ground Truth: $8$ Positive pairs, $8$ Negative pairs ($N=16$).
  - Model Predictions: $10$ pairs classified as positive matches ($8$ True Positives, $2$ False Positives), $6$ pairs classified as non-matches ($6$ True Negatives, $0$ False Negatives).
  - **Holdout Precision**: $\frac{\text{TP}}{\text{TP} + \text{FP}} = \frac{8}{10} = 80.0\%$ (Exact Clopper-Pearson 95% CI: $[44.4\%, 97.5\%]$).
  - **Holdout Recall**: $\frac{\text{TP}}{\text{TP} + \text{FN}} = \frac{8}{8} = 100.0\%$ (Exact Clopper-Pearson 95% CI: $[63.1\%, 100.0\%]$).
  - **False Match Rate**: $\frac{\text{FP}}{\text{TN} + \text{FP}} = \frac{2}{8} = 25.0\%$ (Exact Clopper-Pearson 95% CI: $[3.2\%, 65.1\%]$).
- **Base Rate Caveat**: Real-world comparisons across large process trees ($50 \times 50 = 2,500$ candidate pairs) have a much lower match prevalence ($<1\%$). Analysts should always review alternative candidate nodes surfaced in the evidence drawer.
- **Scope & Security Limitations**: This is a security-hardened local MVP, not a claim of formal security certification or a comprehensive independent security audit. The JSDOM test suite is a regression test, not proof of complete XSS immunity. Validate offline deployment requirements in your intended environment before ingesting sensitive telemetry.

---

## 10. Test Suite & Verification

Run the full automated verification suite (68 automated tests: 50 Python unit/hardening/security tests, 13 Rust integration/parity tests, 5 WHATWG JSDOM browser tests, and privacy audit):
```bash
make test-all
```

To run individual benchmark, ingestion, and browser security tests:
```bash
# Run multi-language performance benchmark (Python and Rust CLI, N=50)
make benchmark

# Verify browser-level WHATWG DOM XSS prevention (Node/JSDOM)
make dom-test

# Verify real CAPE v2.2 native ingestion
python3 -m unittest tests/test_real_cape_ingestion.py

# Verify engine hardening (dedup, network honesty, greedy bipartite order-independence)
python3 -m unittest tests/test_engine_hardening.py

# Verify adversarial payload fuzzing and error sanitization
python3 -m unittest tests/test_fuzzing_and_security.py

# Verify provenance pointers and holdout CI
python3 -m unittest tests/test_holdout_and_provenance.py

# Verify Rust standalone CLI parity
make rust-test

# Verify zero-egress privacy & air-gap compliance
make audit-privacy
```

---

## 11. Product Editions & Commercial Roadmap

Sandbox Comparator is built under an open-core, utility-first model:
- **Community Edition (Free / MIT)**: 100% offline-first CLI and local web workspace; CAPE, Falcon, and Cuckoo ingestion; anchor-preserving greedy bipartite matching; RFC 6901 evidence inspector; Markdown exports.
- **Professional Edition (Planned / ₹999/mo)**: Any.Run & Joe Sandbox native parsers; persistent SQLite workspace history; automated YARA/Sigma rule generation; executive PDF reports.
- **Team & Enterprise (Planned / ₹4,999/mo)**: Private self-hosted sync layer; SOAR webhooks (Splunk Phantom, Cortex XSOAR); centralized cryptographically signed audit logs.

For complete product specifications, compliance alignment (GDPR / HIPAA / SOC 2), and architectural guarantees, see [**docs/PRODUCT_SPEC.md**](docs/PRODUCT_SPEC.md), [**docs/ARCHITECTURE.md**](docs/ARCHITECTURE.md), and [**docs/AIRGAP_SECURITY_MODEL.md**](docs/AIRGAP_SECURITY_MODEL.md).

---

## 12. Security, Quality & Community Governance

- **Security & Vulnerability Disclosure**: See [**SECURITY.md**](SECURITY.md) for our responsible disclosure policy, response SLAs, and security guarantees.
- **Contributing Guidelines**: See [**CONTRIBUTING.md**](CONTRIBUTING.md) for local environment setup, parser contribution guidelines, and PR checklists.
- **Code of Conduct**: We adhere to the [**Contributor Covenant v2.1**](CODE_OF_CONDUCT.md).
- **Changelog & Releases**: See [**CHANGELOG.md**](CHANGELOG.md) for release notes across versions.

---

## 13. License

Released under the [MIT License](LICENSE).
Copyright (c) 2026 Naman Bhatt.


