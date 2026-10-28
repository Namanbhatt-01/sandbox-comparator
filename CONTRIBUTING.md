# Contributing to Sandbox Comparator

Thank you for your interest in contributing to **Sandbox Comparator**! We welcome contributions from malware researchers, reverse engineers, and developers.

---

## 1. Development Principles

When contributing to Sandbox Comparator, adhere to these non-negotiable principles:

1. **Evidence-Aware Forensics**: Never collapse distinct analytical dimensions. Observation presence (`OBSERVED_IN_BOTH`, `OBSERVED_ONLY_IN_A`), causal explanations (`CORROBORATED_EXECUTION`, `POTENTIAL_ENVIRONMENT_LIMITATION`), and epistemic interpretations must remain separate.
2. **RFC 6901 Provenance**: Every finding, process, file, and network event must maintain an explicit RFC 6901 JSON pointer back to the exact token in the source report.
3. **100% Offline-First / Zero Telemetry**: Never introduce external CDNs, remote web fonts, analytics trackers, or phone-home network calls. All dependencies must be locally bundled or system-provided.
4. **Python & Rust Parity**: Any changes to core reconciliation logic, parsing rules, or evidence pointer models must be implemented and tested in both the Python engine (`engine/`) and the Rust engine (`rust/src/`).
5. **DOM XSS Immunity**: Never interpolate unsanitized strings into HTML templates or inline event handlers. Always escape dynamic content and test DOM mutations via `make dom-test`.

---

## 2. Setting Up Your Development Environment

### Prerequisites
- Python 3.9+
- Rust 1.75+ (Cargo)
- Node.js 18+ (for browser DOM security testing)

### Installation
```bash
# Clone the repository
git clone https://github.com/Namanbhatt-01/sandbox-comparator.git
cd sandbox-comparator

# Install Python dependencies in editable mode
make install

# Install DOM testing dependencies
npm install
```

---

## 3. Running the Test Suite

Before opening a pull request, ensure all test suites pass cleanly:

```bash
# Run the complete verification suite (Python, DOM XSS, and Rust)
make test-all

# Or run individual test targets:
make test       # 34 Python unit, regression, and security tests
make dom-test   # Browser-level WHATWG DOM XSS regression tests (JSDOM)
make rust-test  # Rust core engine and parity tests
```

---

## 4. Project Architecture & File Layout

```
sandbox_comparator/
├── cli.py                     # Python CLI entrypoint
├── run_app.py                 # Local web application launcher
├── engine/                    # Core Python reconciliation engine
│   ├── models.py              # Data models (Disentangled dimensions)
│   ├── provenance.py          # RFC 6901 JSON pointer builder
│   ├── reconciler.py          # Bipartite matching & causal reconciliation
│   └── parsers/               # Vendor report ingestion
│       ├── detector.py        # Schema autodetection
│       ├── cape_parser.py     # Native & community CAPE v2 parser
│       └── falcon_parser.py   # Synthetic Falcon-like schema parser
├── web/                       # Local web dashboard
│   ├── app.py                 # FastAPI backend daemon
│   └── static/index.html      # Air-gapped dark-mode dashboard
├── rust/                      # Standalone high-performance Rust core CLI
│   ├── Cargo.toml
│   ├── src/                   # Rust reconciler, models, parsers, CLI
│   └── tests/                 # Cross-language parity tests
├── data/                      # Fixtures and benchmark references
├── tests/                     # Test documentation and coverage matrix
├── test_*.py                  # Python unit, regression, and security suites
└── test_dom_xss.js            # Live browser-level DOM XSS regression test
```

---

## 5. Adding a New Sandbox Parser

To add support for a new sandbox format (e.g. Any.Run, Joe Sandbox, Hatching Triage):
1. Create a parser module in `engine/parsers/<vendor>_parser.py`.
2. Implement the standard normalization returning `NormalizedReport`.
3. Ensure every extracted observation builds an `EvidencePointer` using `build_rfc6901_pointer()`.
4. Wrap all dictionary and list ingestions defensively using `_safe_dict()` and type guards.
5. Update `engine/parsers/detector.py` with schema signature detection rules.
6. Implement the equivalent parser in `rust/src/parsers/<vendor>.rs`.
7. Add parity integration tests in `rust/tests/test_parity.rs` and Python unit tests in `test_*.py`.

---

## 6. Pull Request Guidelines

1. **Branch Naming**: Use descriptive prefixes: `feat/`, `fix/`, `docs/`, `refactor/`.
2. **Commit Messages**: Follow Conventional Commits:
   - `feat(engine): add Any.Run export parser`
   - `fix(web): prevent potential DOM injection in table cell`
3. **CI Requirement**: All GitHub Actions matrix checks (Python 3.9, 3.10, 3.11, 3.12, Rust, DOM tests) must pass with green checkmarks.
4. **Documentation**: Update `README.md`, `PRODUCT_SPEC.md`, or `CHANGELOG.md` if your change affects public APIs, CLI flags, or schema models.
