# Evidence-Aware Sandbox Comparator

[![CI](https://github.com/Namanbhatt-01/sandbox-comparator/actions/workflows/ci.yml/badge.svg)](https://github.com/Namanbhatt-01/sandbox-comparator/actions)
[![Tests: 28 Passing](https://img.shields.io/badge/tests-28%20passing-brightgreen.svg)](tests/)
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
3. Click the blue RFC 6901 pointer link (`🔍 /behavior/processes/0/process_name`) to slide open the raw JSON evidence drawer and inspect the epistemic boundary.

### Step 4: Run CLI Comparison & Export
Compare two reports directly in your terminal and generate an executive Markdown diff:
```bash
sandbox-comparator compare \
  --report-a data/report_format_a_cape.json \
  --report-b data/report_format_b_falcon.json \
  --output diff.md
```

### Step 5: Verify Test Suite
Run the 28 unit and regression tests locally:
```bash
make test
# Or: python3 -m unittest discover -s . -p "test_*.py"
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
2. **Order-Independent Bipartite Matching**: Aligns process trees using multi-factor similarity heuristics (image name, command-line arguments, ancestry depth) without relying on volatile PIDs.
3. **Epistemic Disentanglement**: Separates what telemetry actually logged from what remains uncertain.
4. **Source Evidence Provenance**: Every matched or missing entity links directly to an RFC 6901 JSON pointer resolving to the exact raw source line.
5. **100% Offline-First Execution**: Runs entirely on your local machine with zero external network requests or font imports.

---

## 3. Workspace Features & CLI Usage

### Local Web Workspace
- **Curated Evaluation Presets**: Instant one-click loading of *Scenario Y (Schema Divergence: CAPE v2.4 fixture vs Synthetic Falcon approximation)* and *Scenario X (Structural Variation: CAPE v2.4 fixture vs Sanitized CAPE v2.2 native fixture)*.
- **Zero-Cloud Drag-and-Drop**: Drag any two sandbox JSON reports directly into the browser. Raw files are parsed in-memory on your CPU without uploading to any external server.
- **RFC 6901 Evidence Inspector**: Click any pointer to slide open the raw JSON evidence snippet and inspect epistemic boundaries.
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
# Build standalone native binary (<5ms execution runtime)
make rust-build

# Run native binary directly
./rust/target/release/sandbox-comparator --report-a data/report_format_a_cape.json --report-b data/report_format_b_falcon.json
```

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

## 3. Architecture & Data Privacy

```
+-----------------------------------------------------------------------------------------+
| CLIENT ENVIRONMENT (100% LOCAL & OFFLINE)                                               |
|                                                                                         |
|  [ Modern Dark Web UI ] <======== HTTP / JSON ========> [ Local Python Engine ]         |
|  - Drag-and-Drop Local Files                             - Dynamic Schema Sniffer       |
|  - Interactive Evidence Drawer                           - RFC 6901 Provenance Resolver |
|  - Real-time Markdown Export                             - Global Bipartite Matcher     |
|                                                          - Epistemic Causality Engine   |
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

## 5. Reconciliation Engine Principles

### 1. Process Alignment via Global Bipartite Matching
Rather than greedy top-down traversal, the reconciler evaluates all candidate process pairs across reports and resolves the global maximum similarity assignment.
- **Similarity Factors**: Image name exactness, command-line token Jaccard similarity, tree depth delta, and parent lineage overlap.
- **Ambiguity Detection**: If multiple candidate nodes score within $\Delta < 0.15$ of each other, the node is flagged as `POSSIBLE_MATCH (AMBIGUOUS)` and all alternative candidate PIDs are recorded in the evidence ledger.

### 2. Hash-Collision Resistant File Dedup
Many malware samples write the same binary to multiple persistence locations or drop empty marker files. The engine groups file observations by cryptographic hash without overwriting duplicate drops, preserving every path and pointer.

### 3. Epistemically Honest Network Semantics
Network records are treated strictly as socket logs:
- Both reports observing `TCP://203.0.113.88:8080` sets state to `SOCKET_RECORD_LOGGED` and causal status to `CORROBORATED_SOCKET`.
- It explicitly does **not** assert `ESTABLISHED` or `CONFIRMED` without packet-level capture proving a 3-way handshake or application payload exchange.
- Omissions are linked contextually to sandbox runtime limitations (e.g., firewall policy warnings or timeouts).

---

## 6. Repository Provenance & Commit Ledger

The `sandbox_comparator` engine originated within a broader malware research monorepo (`apt36-rapidrust-research`) and was extracted into this standalone public repository via `git subtree split`. Because `git subtree split` synthesizes new root-level commits, the commit hashes correspond as follows:

| Milestone / Event | Monorepo Commit | Standalone Repo Commit | Scope & Verified Deliverable |
| :--- | :--- | :--- | :--- |
| **Milestone 5 Pre-Rehearsal Lock** | `dfec537434...` | `fa12a78045...` | Protocol v5.0 pre-pilot baseline lock |
| **Milestone 5 Protocol v5.1 Lock** | `7bf8d1b2a9...` | `a00ceb161d...` | Rehearsal findings, pilot kits, and decoupled trackers |
| **Product MVP & Engine Hardening** | `product-mvp` branch | `product-mvp` branch | Order-independent matcher, hash dedup, local web app |

All fixture hashes in `data/*.json` match the SHA-256 ledger in `PILOT_PACKET.md` with 100% cryptographic parity.

---

## 7. Supported Schemas & Extensibility

| Sandbox Platform | Schema Level | Provenance Status | Parser Module |
| :--- | :--- | :--- | :--- |
| **CAPE Sandbox v2.x** | Documented Open-Source Schema | Verified against CAPE v2.2 & v2.4 JSON dumps | `engine.parsers.cape_parser` |
| **Falcon Sandbox Cloud** | Synthetic v7.x Approximation | Synthesized Behavioral Approximation Fixture | `engine.parsers.falcon_parser` |
| **Cuckoo Sandbox v2.x** | Community Layout | Backward-Compatible Ingestion | `engine.parsers.cape_parser` |
| **Custom / Unknown** | Generic Autodetection | Defensive Fallback Parser | `engine.parsers.detector` |

---

## 8. Calibration Limitations & Methodology Guardrails

In compliance with scientific transparency and auditability:
- **Heuristic Calibration Corpus**: The empirical similarity matcher was calibrated on $N=16$ development pairs and tested on $N=16$ held-out pairs.
- **Confidence Interval**: The observed $80.0\%$ holdout precision ($8/10$) yields an exact Clopper-Pearson 95% confidence interval of $[44.4\%, 97.5\%]$.
- **Base Rate Caveat**: Real-world comparisons across large process trees ($50 \times 50 = 2,500$ candidate pairs) have a much lower match prevalence ($<1\%$). Analysts should always review alternative candidate nodes surfaced in the evidence drawer.

---

## 9. Test Suite & Verification

Run the full automated unit test suite (28 unit and regression tests):
```bash
python3 -m unittest discover -s . -p "test_*.py"
```

To run individual benchmark and ingestion tests:
```bash
# Verify real CAPE v2.2 native ingestion
python3 -m unittest test_real_cape_ingestion.py

# Verify engine hardening (dedup, network honesty, bipartite order-independence)
python3 -m unittest test_engine_hardening.py

# Verify provenance pointers and holdout CI
python3 -m unittest test_holdout_and_provenance.py
```

---

## 10. Product Editions & Commercial Roadmap

Sandbox Comparator is built under an open-core, utility-first model:
- **Community Edition (Free / MIT)**: 100% offline-first CLI and local web workspace; CAPE, Falcon, and Cuckoo ingestion; global bipartite matching; RFC 6901 evidence inspector; Markdown exports.
- **Professional Edition (Planned / ₹999/mo)**: Any.Run & Joe Sandbox native parsers; persistent SQLite workspace history; automated YARA/Sigma rule generation; executive PDF reports.
- **Team & Enterprise (Planned / ₹4,999/mo)**: Private self-hosted sync layer; SOAR webhooks (Splunk Phantom, Cortex XSOAR); centralized cryptographically signed audit logs.

For complete product specifications, compliance alignment (GDPR / HIPAA / SOC 2), and architectural guarantees, see [**PRODUCT_SPEC.md**](PRODUCT_SPEC.md).

---

## 11. License

Released under the [MIT License](LICENSE).


