# Sandbox Comparator — Air-Gap & Zero-Egress Security Model

## 1. Security Philosophy: Air-Gapped Zero-Egress

Malware analysis and digital forensics require strict isolation. When analyzing confidential intelligence, targeted advanced persistent threats (APTs), or proprietary corporate artifacts, data must never leave the analyst workstation or local secure network.

The Sandbox Comparator is built from the ground up to operate in **100% offline, air-gapped environments**:
- **Zero External CDNs**: All HTML, JavaScript, and CSS assets are bundled directly within the package (`web/static/`).
- **Local-Only System Font Stack**: No requests to external typography providers (`fonts.googleapis.com` or `fonts.gstatic.com`). Uses native platform system fonts (`-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif`).
- **Loopback Enforcement**: The backend launcher (`run_app.py`) defaults strictly to `127.0.0.1`. If an operator specifies `0.0.0.0`, a loud security warning is displayed on standard output to prevent unintended LAN exposure.
- **Zero Outbound Telemetry**: No third-party error trackers (Sentry), analytics engines (Google Analytics, Mixpanel), or outbound HTTP client pings exist anywhere in the backend engine or web client.

---

## 2. Threat Model & Countermeasures

| Threat Vector | Mitigation Strategy | Verification Mechanism |
| :--- | :--- | :--- |
| **Data Exfiltration / Egress** | Air-gap architecture; zero external HTTP clients or scripts. | `scripts/verify_offline_privacy.py` automated static analysis in CI. |
| **Browser-Level DOM XSS** | Contextual HTML escaping on all dynamic report fields (filenames, processes, hashes, URLs, limitation descriptions); integer-indexed evidence registry rather than string interpolation in event handlers. | `tests/test_dom_xss.js` WHATWG JSDOM browser simulation with adversarial canaries. |
| **Adversarial Malformed JSON** | Defensive type validation in report parsers (`isinstance(dict)`, fallback handling for non-string hashes, malformed PIDs). | `tests/test_fuzzing_and_security.py` fuzzing test suite. |
| **Information Disclosure via 500 Errors** | Reconciliation exceptions are caught server-side and logged internally; client receives a sanitized HTTP 422 with a generic error detail. | `test_fuzzing_and_security.py` assertion on API error responses. |
| **Memory Unsafety / Panic on Truncation** | Rust core engine enforces UTF-8 character boundary validation (`char_indices`) prior to string slicing. | `rust/tests/test_parity.rs` automated tests. |

---

## 3. DOM XSS Defense-in-Depth

Untrusted malware sandbox reports frequently contain hostile adversarial values designed to attack analyst dashboards (e.g., process names crafted as `calc.exe"><script>alert(1)</script>`).

To guarantee security against DOM XSS:
1. **HTML Entity Encoding**: All user-supplied or report-supplied strings inserted into DOM element content are passed through `escapeHtml()`:
   ```javascript
   function escapeHtml(str) {
     if (!str) return '';
     return String(str)
       .replace(/&/g, '&amp;')
       .replace(/</g, '&lt;')
       .replace(/>/g, '&gt;')
       .replace(/"/g, '&quot;')
       .replace(/'/g, '&#039;');
   }
   ```
2. **Numeric-Indexed Evidence Registry**: Rather than constructing inline event handlers with interpolated report strings (e.g. `onclick="openEvidence('${pointer}')"`), all evidence objects are stored in an in-memory `evidenceRegistry` array. The DOM renders only a safe integer index:
   ```html
   <a class="pointer-link" onclick="openEvidenceByIndex(0)">...</a>
   ```
3. **Automated Verification**: JSDOM executes `web/static/index.html` with active script evaluation enabled against comprehensive XSS payloads across all tables, findings cards, summary verdicts, and drawer elements.
