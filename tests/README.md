# Test Suite & Verification Architecture

This directory documents the comprehensive verification, regression, fuzzing, and parity testing framework for **Sandbox Comparator**.

---

## 1. Test Architecture Overview

The test architecture ensures scientific integrity, algorithmic correctness, cross-language parity, and defense against hostile payloads.

```
Total Automated Tests: 38 (34 Python/DOM + 4 Rust Parity)
```

| Test Suite File | Type | Test Count | Focus Area |
| :--- | :--- | :--- | :--- |
| [`test_fuzzing_and_security.py`](../test_fuzzing_and_security.py) | Security / Fuzzing | 5 tests | Malformed JSON types, adversarial `<script>`/`<img>` payloads, API error sanitization, JSDOM execution |
| [`test_engine_hardening.py`](../test_engine_hardening.py) | Engine / Correctness | 6 tests | SHA-256 deduplication, network attribution honesty, order-independent bipartite matching |
| [`test_real_cape_ingestion.py`](../test_real_cape_ingestion.py) | Parser / Integration | 4 tests | Authentic native CAPE v2.2 export ingestion, RFC 6901 pointer resolution |
| [`test_calibration_and_semantics.py`](../test_calibration_and_semantics.py) | Algorithm / Forensics | 7 tests | Heuristic similarity weighting, disentangled dimension verification |
| [`test_holdout_and_provenance.py`](../test_holdout_and_provenance.py) | Scientific / Calibration | 6 tests | Held-out validation corpus, Clopper-Pearson 95% confidence intervals |
| [`test_prototype.py`](../test_prototype.py) | Regression | 6 tests | Baseline pipeline end-to-end reconciliation and markdown export |
| [`test_dom_xss.js`](../test_dom_xss.js) | Browser Security | 1 suite (4 tables) | WHATWG DOM tree inspection, zero script execution, numeric onclick verification |
| [`rust/tests/test_parity.rs`](../rust/tests/test_parity.rs) | Parity / Rust | 4 tests | Bit-for-bit parity between Python and Rust engines across scenarios X and Y |

---

## 2. Running Tests

### Complete Verification Suite
Run all Python, DOM security, and Rust tests in one command:
```bash
make test-all
```

### Python Suite
```bash
make test
# Or: python3 -m unittest discover -s . -p "test_*.py"
```

### Browser DOM Security Suite
Directly executes `web/static/index.html` inside WHATWG JSDOM with script execution enabled:
```bash
make dom-test
# Or: node test_dom_xss.js
```

### Standalone Rust Core CLI Tests
```bash
make rust-test
# Or: cd rust && cargo test
```

---

## 3. Security Test Assurances

1. **Adversarial JSON Types**: All parsers (`cape_parser`, `falcon_parser`, `detector`) are systematically fuzzed with non-dict types (strings, integers, booleans, lists, `None`) in place of expected sub-dictionaries to verify immunity against `AttributeError` and `TypeError`.
2. **Path & Traceback Leakage**: API tests verify that internal exceptions containing sensitive host filesystem paths (e.g. `/Users/namanbhatt/...`) are strictly logged server-side and never returned in client HTTP 422 responses.
3. **DOM XSS Injection**: The JSDOM suite asserts that hostile HTML tags injected via report fields are properly escaped into text nodes, with 0 `<script>`, `<img>`, or `<svg>` tags created in the live table bodies.
