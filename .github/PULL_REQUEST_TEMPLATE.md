## Description
<!-- Provide a concise summary of the changes in this pull request. -->

## Type of Change
- [ ] Bug fix (non-breaking change fixing an issue)
- [ ] New feature (non-breaking change adding forensic capability or parser)
- [ ] Breaking change (fix or feature modifying public CLI/API contracts)
- [ ] Documentation update
- [ ] Security / Hardening improvement

## Quality & Parity Checklist
- [ ] All tests pass cleanly (`make test-all`).
- [ ] Zero DOM XSS regression verified (`make dom-test`).
- [ ] Offline privacy audit passes (`make audit-privacy`).
- [ ] Parity verified between Python (`engine/`) and Rust (`rust/src/`).
- [ ] No external CDNs, fonts, or network telemetry introduced.
- [ ] RFC 6901 pointers maintained for all extracted findings.
