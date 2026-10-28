# Sandbox Comparator: Commercial Product Specification

**Product Name**: Sandbox Comparator  
**Category**: Digital Forensics & Incident Response (DFIR) / Automated Malware Telemetry Reconciliation  
**Target Market**: Independent Security Analysts, DFIR Incident Response Firms, MDR Providers, Enterprise SOC Tier 3 & Threat Intelligence Teams  
**Deployment Model**: 100% Offline-First (Local Workstation / Air-Gapped Private VPC)  

---

## 1. Executive Summary & Problem Space

Enterprise security teams rely heavily on automated dynamic malware analysis sandboxes (CAPE Sandbox, CrowdStrike Falcon Sandbox, Any.Run, Joe Sandbox, Hatching Triage) to evaluate suspicious attachments, droppers, and zero-day binaries. 

However, modern malware exhibits anti-analysis evasion, conditional staging, and environment-dependent behavior. Consequently, analysts routinely execute samples across multiple sandboxes or repeat runs with varying network routes or sleep-bypass hooks.

### The Operational Problem
1. **Identifier Drift**: Across repeated runs, ephemeral Process IDs (PIDs) change randomly. Naive textual diffs (`diff`, `git diff`, `jq`) show near-100% false divergence.
2. **Schema Fragmentation**: Every sandbox vendor outputs inconsistent JSON schemas (e.g. CAPE stores dropped files in `/dropped` while Falcon uses `/execution/created_files`).
3. **Epistemic Leaps & Hallucinated Attributions**: Analysts frequently conclude that an omitted network connection in Run B indicates active evasion, overlooking that the sandbox timed out or hit a local firewall policy.
4. **Data Privacy Barriers**: Incident response investigations involve proprietary client telemetry, internal IP addresses, and sensitive corporate binaries that cannot be uploaded to public multi-engine threat aggregation platforms (e.g., VirusTotal Enterprise) without violating NDAs and privacy compliance laws.

---

## 2. Product Positioning & Value Proposition

> **"A comparison and evidence layer for existing malware sandboxes."**  
> Sandbox Comparator does not detonate malware; it sits directly on top of the report exports that security teams already generate, enabling evidence-traceable, mathematically robust behavioral reconciliation.

```
+----------------------------------------------------------------------------------------------------+
| CORE VALUE PROPOSITION MATRIX                                                                      |
+------------------------------+---------------------------+-----------------------------------------+
| Feature Area                 | Legacy Multi-Tab Workflow | Sandbox Comparator                      |
+------------------------------+---------------------------+-----------------------------------------+
| Process Alignment            | Manual visual search      | Order-Independent Bipartite Matcher     |
| Transient PID Handling       | Memorization / text notes | Multi-factor similarity scoring (0-1.0) |
| Dropped Artifacts            | Flat filename inspection  | Cryptographic hash dedup & path diffing |
| Telemetry Omissions          | Unverified speculation    | Epistemic correlation with policy warnings|
| Auditability & Verification  | Unlinked summary tables   | Exact RFC 6901 source JSON pointers     |
| Privacy Guarantee            | Often uploads to cloud    | 100% Offline-First / Zero Cloud Egress  |
+------------------------------+---------------------------+-----------------------------------------+
```

---

## 3. Product Editions & Commercial Tiers

Sandbox Comparator is offered under a transparent, utility-grounded licensing model designed for rapid bootstrap adoption:

### Tier 1: Community Edition (Free & Open Source)
- **Target**: Students, security researchers, individual reverse engineers.
- **Licensing**: Permissive MIT License.
- **Capabilities**:
  - Full CLI (`sandbox-comparator`) and interactive local web interface (`http://127.0.0.1:8000`).
  - Ingestion for CAPE Sandbox v2.x, Falcon Sandbox Cloud Engine (synthetic v7.x), and generic schemas.
  - Global maximum-weight bipartite process matching with ambiguity detection.
  - RFC 6901 JSON pointer generation.
  - Markdown report export.
  - 100% offline-first execution with zero external network connectivity.

### Tier 2: Professional Edition (₹799–₹999 / user / month or ₹7,999 / year)
- **Target**: Independent DFIR consultants, boutique red/blue team contractors, senior malware analysts.
- **Capabilities (Community +)**:
  - Extended vendor ingestion pack: Native Any.Run, Hatching Triage, Joe Sandbox, and Windows Defender ATP sandbox exports.
  - Persistent SQLite-backed local investigation workspace: save comparisons, tag investigations, and maintain sample history.
  - Executive PDF & Structured STIX 2.1 / MISP threat-intelligence export.
  - Discrepancy-to-YARA and Discrepancy-to-Sigma rule generator: automatically outputs detection rules targeting corroborated artifacts across runs.

### Tier 3: Team & Enterprise Edition (₹4,999–₹7,999 / month for 5 seats)
- **Target**: Managed Detection & Response (MDR) providers, enterprise SOC escalation pods, corporate CSIRTs.
- **Capabilities (Professional +)**:
  - Local-first sync layer: share investigation diffs securely across analysts via customer-controlled storage (MinIO / S3 / Postgres).
  - Headless CI/CD / SOAR integration webhook (Splunk Phantom, Palo Alto Cortex XSOAR, Swimlane).
  - Centralized audit trail with cryptographically signed analysis provenance.
  - Priority engineering support and custom parser development.

---

## 4. Architecture & Data Security Guarantee

```
+----------------------------------------------------------------------------------------------------+
| 100% OFFLINE-FIRST CLIENT ARCHITECTURE                                                             |
|                                                                                                    |
|  [ Analyst Browser / CLI ]                                                                         |
|            |                                                                                       |
|            | (HTTP Localhost / RFC 6901 Pointers)                                                  |
|            v                                                                                       |
|  [ Local Python Engine: FastAPI + Munkres Matcher + Schema Sniffer ]                               |
|            |                                                                                       |
|            +----> [ Report A JSON ] (In-Memory Processing Only)                                    |
|            +----> [ Report B JSON ] (In-Memory Processing Only)                                    |
|                                                                                                    |
|  X ZERO CLOUD TRANSMISSION  |  X ZERO EXTERNAL TELEMETRY  |  X AIR-GAPPED READY                    |
+----------------------------------------------------------------------------------------------------+
```

### Privacy & Regulatory Design Considerations
*Disclaimer: Sandbox Comparator is an independent software tool. The following points represent architectural privacy design principles rather than formal regulatory certification or compliance attestation.*

By processing telemetry exclusively within the customer's local execution boundary (`127.0.0.1`) without egress to external servers, the local-first architecture is designed to support teams in meeting common internal security objectives:
- **Data Residency & Cross-Border Principles (e.g., GDPR Art. 44 design alignment)**: Local execution avoids transferring incident evidence, IP addresses, or potential PII to third-party multi-engine cloud providers.
- **Sensitive Data Isolation (e.g., HIPAA § 164.312 considerations)**: Eliminates external transmission of electronic data contained in dynamic sandbox traces.
- **Customer Control Boundary (e.g., SOC 2 Security Principles)**: Incident telemetry remains entirely within customer-controlled infrastructure; no vendor-side multi-tenant databases or logs are maintained.

---

## 5. Technical Specifications & Engine Boundaries

1. **Process Alignment Engine**:
   - Computes bipartite similarity across Process Image Name (40%), Command Argument Jaccard token overlap (35%), Ancestry Lineage overlap (15%), and Tree Depth delta (10%).
   - Ambiguity Threshold: Surfaces alternative candidate PIDs whenever an alternate candidate scores within $\Delta < 0.15$ of the optimal pairing.
2. **File Reconciler**:
   - Groups dropped files by cryptographic SHA-256 with compound path indexing `(sha256, normalized_path)`.
   - Preserves multi-location drops and zero-byte files without dictionary overwrite.
3. **Network Causality Engine**:
   - Decouples raw socket records from causal overclaims.
   - States explicitly: *"Telemetry confirms both environments logged socket activity; does not establish full application-layer handshake completion or identical payload transmission without packet-level capture."*
4. **RFC 6901 Pointer Resolution**:
   - Every analytical entity references an RFC 6901 path (`/behavior/processes/2`, `/dropped/0`) allowing instant programmatic audit against source documents.

---

## 6. Development & Launch Milestones

- **Milestone 1–5 (Completed)**: Empirical validation, Protocol v5.1 locking, R1/R2 procedural rehearsals, and engine hardening.
- **Product Launch (Phase 1, Days 1–14)**: Publish standalone repository, distribute screen-only interactive demo, and initiate Phase 1 practitioner interviews.
- **Usability Expansion (Phase 2, Days 15–35)**: Expand schema parser pack to Any.Run and Joe Sandbox; integrate memory-safe streaming JSON parser.
- **Commercial Monetization (Phase 3–4, Days 36–90)**: Deploy Razorpay Subscriptions for Indian and international early adopters; offer initial Pro licenses to active trial participants.

