# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0-local-mvp] - 2026-10-28

### Added
- **Core Reconciliation Engine**:
  - Greedy score-sorted bipartite process matching with anchor preservation and symmetric ambiguity detection.
  - Multi-path file observation grouping keyed by SHA-256 with conflict detection and surrogate handling for unhashed artifacts.
  - Dynamic network socket causal attribution, connecting egress block limitations to unobserved remote endpoints.
  - Calibrated network semantics: single un-discriminated connections marked `SINGLETON_ENDPOINT_OVERLAP` / `ENDPOINT_MATCH`; undifferentiated repeated connections consolidated into `AGGREGATE_ENDPOINT_CLUSTER` rather than arbitrary 1-to-1 pairings.
  - Sample hash divergence guard: flags cross-sample comparisons with explicit `SAMPLE_HASH_MISMATCH` limitations and warning banners.
  - Missing ancestry tolerance: applies disjoint tree penalty only when both reports provide active conflicting lineage, preventing false penalties when one sandbox omits parentage.
- **Evidence Provenance**:
  - Full RFC 6901 JSON pointer generation for every process, file, network event, and environment limitation.
  - Slide-out forensic drawer in web UI displaying raw source snippets and causal boundaries.
- **Defensive Parser Hardening**:
  - Native CAPE Sandbox v2.x parser supporting authentic root schema and community wrappers, with PID reuse warnings.
  - Synthetic Falcon-like sandbox parser supporting hierarchical process trees and system warning blocks, with surrogate IDs preventing PID 0 collisions.
  - Autodetection module for seamless routing between schema types.
  - Safe dictionary helpers (`_safe_dict`) and type guards preventing crashes on malformed inputs.
- **Standalone Rust Core CLI**:
  - High-performance Rust reimplementation in `rust/` with sub-5ms execution runtime.
  - Verified 13-test bit-for-bit parity with Python engine on reference scenarios.
  - Safe UTF-8 character boundary string truncation preventing multi-byte panics.
- **Air-Gapped Web Workspace & Tooling**:
  - Localhost FastAPI daemon strictly bound to `127.0.0.1:8000`.
  - Zero external web fonts (native system font stack) and zero outbound network telemetry verified across Python and Rust sources.
  - Interactive scenario presets (Scenario X: CAPE v2.2 vs v2.4, Scenario Y: CAPE vs Synthetic Falcon).
  - Reproducible benchmark harness (`scripts/run_benchmarks.py`) comparing Python and Rust over $N=50$ iterations.
- **Security & Quality Assurance**:
  - Complete 68-test automated test suite (50 Python unit & security tests, 13 Rust parity integration tests, 5 WHATWG DOM XSS tests).
  - Browser-level WHATWG DOM XSS regression suite (`test_dom_xss.js`) running under JSDOM.
  - Multi-platform GitHub Actions CI matrix covering Python 3.9, 3.10, 3.11, 3.12, and Rust on Ubuntu 22.04.

### Changed
- Sanitized API error handling in `web/app.py`: internal tracebacks and filesystem paths are logged server-side, returning generic HTTP 422 messages to clients.
- Switched UI evidence inspection to an in-memory integer-indexed registry (`openEvidenceByIndex`), eliminating attribute injection vectors.

---

## [0.9.0-research] - 2026-10-28
- Initial research prototype for APT36 RapidRust forensic reconciliation.
- Monorepo extraction via `git subtree split`.
- Protocol v5.1 interview protocol and empirical calibration corpus.

