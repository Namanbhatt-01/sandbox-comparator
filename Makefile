.PHONY: help install test dom-test audit-privacy ui compare benchmark clean rust-build rust-test test-all

help:
	@echo "Sandbox Comparator — Product Developer Commands"
	@echo "==============================================="
	@echo "  make install       Install Python dependencies"
	@echo "  make test          Run the complete Python test suite (42 unit, hardening, and security tests)"
	@echo "  make dom-test      Run the browser-level WHATWG DOM XSS regression suite (Node/JSDOM)"
	@echo "  make audit-privacy Verify offline zero-egress compliance and local font/asset integrity"
	@echo "  make rust-build    Build the standalone high-performance Rust core CLI"
	@echo "  make rust-test     Run Rust unit and parity integration tests"
	@echo "  make test-all      Run all tests: Python, DOM XSS, Privacy Audit, and Rust Parity"
	@echo "  make ui            Launch the local-first web application (http://127.0.0.1:8000)"
	@echo "  make compare       Run CLI report comparison on default demo fixtures"
	@echo "  make benchmark     Run performance and runtime benchmark"
	@echo "  make clean         Remove build artifacts, caches, and temp files"

install:
	pip install -r requirements.txt
	pip install -e .

test:
	python3 -m unittest discover -s tests -p "test_*.py"

dom-test:
	node tests/test_dom_xss.js

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
	python3 -c "from engine.reconciler import ExecutionBenchmark; b = ExecutionBenchmark.run_benchmark(50); print('Mean runtime:', b['end_to_end_runtime_ms']['mean'], 'ms')"

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.py[cod]" -delete
	rm -rf build/ dist/ *.egg-info .pytest_cache/
	cd rust && cargo clean 2>/dev/null || true

