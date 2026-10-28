# Sandbox Comparator — Documentation

Welcome to the technical documentation library for the **Evidence-Aware Sandbox Comparator**.

## Documentation Index

- [**System Architecture & Engine Specification**](ARCHITECTURE.md)
  Deep-dive into the disentangled behavioral reconciliation model, dual-engine strategy (Python Munkres + Rust Core), heuristic scoring, and RFC 6901 evidence provenance model.

- [**Air-Gap & Zero-Egress Security Model**](AIRGAP_SECURITY_MODEL.md)
  Analysis of the threat model, 100% offline air-gap guarantees, loopback binding security, and browser-level DOM XSS defense-in-depth.

- [**Commercial Product Specification**](PRODUCT_SPEC.md)
  Full product requirements, target DFIR/SOC persona alignment, competitive landscape (VirusTotal, ANY.RUN, Hybrid Analysis), and enterprise deployment topology.

---

For empirical evaluations, interview transcripts, and pilot execution materials, refer to [`../evaluations/`](../evaluations/).
For test suites and regression specifications, refer to [`../tests/`](../tests/).
