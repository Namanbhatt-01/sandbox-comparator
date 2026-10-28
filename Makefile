.PHONY: help install test ui compare benchmark clean

help:
	@echo "Sandbox Comparator — Product Developer Commands"
	@echo "==============================================="
	@echo "  make install    Install Python dependencies"
	@echo "  make test       Run the complete 28-test verification suite"
	@echo "  make ui         Launch the local-first web application (http://127.0.0.1:8000)"
	@echo "  make compare    Run CLI report comparison on default demo fixtures"
	@echo "  make benchmark  Run performance and runtime benchmark"
	@echo "  make clean      Remove build artifacts, caches, and temp files"

install:
	pip install -r requirements.txt

test:
	python3 -m unittest discover -s . -p "test_*.py"

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

