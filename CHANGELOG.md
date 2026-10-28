# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0-local-mvp] - 2026-10-28

### Added
- **Core Reconciliation Engine**:
  - Global maximum-weight bipartite process matching with ambiguity detection.
  - Multi-path file observation grouping keyed by SHA-256 with conflict detection.
  - Dynamic network socket causal attribution, connecting egress block limitations to unobserved remote endpoints.
- **Evidence Provenance**:
  - Full RFC 6901 JSON pointer generation for every process, file, network event, and environment limitation.
  - Slide-out forensic drawer in web UI displaying raw source snippets and epistemic boundaries.
- **Defensive Parser Hardening**:
  - Native CAPE Sandbox v2.x parser supporting authentic root schema and community wrappers.
  - Synthetic Falcon-like sandbox parser supporting hierarchical process trees and system warning blocks.
  - Autodetection module for seamless routing between schema types.
  - Safe dictionary helpers (`_safe_dict`) and type guards preventing crashes on malformed inputs.
- **Standalone Rust Core CLI**:
  - High-performance Rust reimplementation in `rust/` with sub-millisecond execution runtime.
  - Verified bit-for-bit parity with Python engine on reference scenarios.
  - Safe UTF-8 character boundary string truncation preventing multi-byte panics.
- **Air-Gapped Web Workspace**:
  - Localhost FastAPI daemon strictly bound to `127.0.0.1:8000`.
  - Zero external web fonts (native system font stack) and zero outbound network telemetry.
  - Interactive scenario presets (Scenario X: CAPE v2.2 vs v2.4, Scenario Y: CAPE vs Synthetic Falcon).
- **Security & Quality Assurance**:
  - Complete 34-test Python verification and adversarial security suite.
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

