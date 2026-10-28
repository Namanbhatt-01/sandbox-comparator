# Security Policy

## Reporting Security Issues

We take the security of Sandbox Comparator seriously. If you believe you have discovered a vulnerability, security flaw, or potential information disclosure in Sandbox Comparator, please follow responsible disclosure guidelines.

**Do not report security vulnerabilities through public GitHub issues.**

### Reporting Method
Please report vulnerabilities privately via GitHub Security Advisories:
- Navigate to the [Security Advisories](https://github.com/Namanbhatt-01/sandbox-comparator/security/advisories) tab on GitHub and click **"New draft security advisory"**.
- Alternatively, email the maintainer directly at: `the.namanbhatt109@gmail.com` with the subject line: `[SECURITY] Sandbox Comparator Vulnerability Report`.

Please include:
1. Description of the vulnerability and affected components (e.g., parser, reconciler, web API, frontend).
2. Step-by-step reproduction steps or proof-of-concept (PoC) payload.
3. Impact assessment (e.g., DOM XSS, denial of service, memory safety, path disclosure).
4. Any proposed remediations.

### Response SLA
- **Initial Acknowledgement**: Within 24 hours.
- **Triage & Reproduction**: Within 48 hours.
- **Patch & Advisory Release**: Critical vulnerabilities patched within 7 days.

---

## Security Architecture & Guarantees

Sandbox Comparator is engineered specifically for malware analysts and security operation teams handling sensitive threat data.

### 1. Zero-Egress Execution Boundary
- **Localhost Only**: The local web server defaults to binding exclusively to `127.0.0.1:8000`. A clear terminal warning is emitted if LAN binding (`0.0.0.0`) is explicitly requested.
- **Zero Outbound Telemetry**: The application transmits zero telemetry, zero analytics, and zero crash reports to external servers.
- **Air-Gapped Ready**: The web interface utilizes local system font stacks and self-contained static assets, eliminating any runtime requests to external CDNs or Google Fonts.

### 2. Frontend DOM XSS Immunity
- All dynamic data rendered in the user interface (process names, lineage paths, file names, paths, SHA-256 hashes, network IPs, URLs, limitation codes, and descriptions) is strictly escaped via HTML entity encoding before insertion into table elements.
- Evidence inspection uses an in-memory registry accessed via integer indices (`openEvidenceByIndex(number)`). Raw user data is never interpolated into inline event handlers (`onclick`, `onload`, `onerror`).
- Drawer forensic views populate raw snippets and summaries strictly using `element.textContent`, preventing script execution on hostile strings.
- Automated WHATWG-compliant DOM tests (`test_dom_xss.js`) run in CI to verify zero DOM tag injection.

### 3. Defensive Parser Hardening
- Parsers implement type guards (`_safe_dict`, `isinstance(..., list)`) to prevent `AttributeError` or `TypeError` crashes on malformed or corrupted JSON inputs.
- API endpoints log reconciliation exceptions server-side and return generic, sanitized HTTP 422 messages to clients, preventing filesystem path or stack trace leakage.

### 4. Memory Safety & UTF-8 Integrity
- The standalone core CLI is written in Rust, preventing memory corruption vulnerabilities (buffer overflows, use-after-free).
- String truncations and preview extractions in the Rust engine strictly calculate UTF-8 character boundaries (`char_indices().nth()`) to prevent multi-byte panics on adversarial unicode payloads.

---

## Supported Versions

| Version | Supported | Security Maintenance |
| :--- | :--- | :--- |
| `1.0.x` (`v1.0.0-local-mvp`) | :white_check_mark: | Active support and security updates |
| `0.x` (Legacy / Pre-release) | :x: | Deprecated / No security maintenance |

