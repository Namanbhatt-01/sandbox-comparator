.PHONY: help install test dom-test audit-privacy ui compare benchmark clean rust-build rust-test test-all

help:
	@echo "Sandbox Comparator — Product Developer Commands"
	@echo "==============================================="
	@echo "  make install       Install Python dependencies and reproducible Node test modules"
	@echo "  make test          Run the Python test suite (58 unit, hardening, and security tests)"
	@echo "  make dom-test      Run the browser-level WHATWG DOM XSS regression suite (Node/JSDOM)"
	@echo "  make audit-privacy Verify offline zero-egress compliance and local font/asset integrity"
	@echo "  make rust-build    Build the standalone high-performance Rust core CLI"
	@echo "  make rust-test     Run Rust unit and parity integration tests (17 tests)"
	@echo "  make test-all      Run all tests: Python (58), DOM XSS, Privacy Audit, and Rust Parity (17)"
	@echo "  make ui            Launch the local-first web application (http://127.0.0.1:8000)"
	@echo "  make compare       Run CLI report comparison on default demo fixtures"
	@echo "  make benchmark     Run performance and runtime benchmark"
	@echo "  make clean         Remove build artifacts, caches, and temp files"

install:
	pip install -r requirements.txt
	pip install -e .
	@if command -v npm >/dev/null 2>&1; then \
		echo "Installing Node test dependencies with npm ci..."; \
		npm ci || echo "Warning: 'npm ci' failed. DOM XSS tests may not run locally."; \
	else \
		echo "Notice: Node.js/npm not found. DOM XSS tests will be skipped locally (run in CI)."; \
	fi

test:
	python3 -m unittest discover -s tests -p "test_*.py"

dom-test:
	@if node -e "require('jsdom')" >/dev/null 2>&1; then \
		node tests/test_dom_xss.js; \
	elif command -v npm >/dev/null 2>&1; then \
		echo "jsdom not found in node_modules, running npm ci..."; \
		npm ci && node tests/test_dom_xss.js; \
	else \
		echo "Node.js or jsdom not found. Skipping DOM XSS tests (run 'npm ci' to enable)."; \
	fi

audit-privacy:
	python3 scripts/verify_offline_privacy.py

rust-build:
	cd rust && cargo build --release

rust-test:
	cd rust && cargo test

test-all: test dom-test audit-privacy rust-test

ui:
	python3 run_app.py

compare:
	python3 cli.py --report-a data/report_format_a_cape.json --report-b data/report_format_b_falcon.json

benchmark:
	python3 scripts/run_benchmarks.py

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.py[cod]" -delete
	rm -rf build/ dist/ *.egg-info .pytest_cache/
	cd rust && cargo clean 2>/dev/null || true

