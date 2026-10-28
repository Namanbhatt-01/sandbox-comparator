"""
Regression and fuzzing test suite for adversarial payloads, malformed JSON inputs,
and API error disclosure prevention.
"""

import unittest
from unittest.mock import patch
from fastapi import HTTPException

from engine.parsers import parse_auto_report, parse_cape_report, parse_falcon_report
from engine.parsers.detector import detect_schema
from engine.reconciler import EvidenceComparator
from web.app import compare_reports, serialize_comparison, CompareRequest


class TestFuzzingAndSecurity(unittest.TestCase):
    """Verifies that parsers, reconciler, and API endpoints are resilient to malformed and hostile payloads."""

    def test_malformed_primitive_types_in_cape_parser(self):
        """CAPE parser must safely handle non-dict primitives in place of objects/lists."""
        adversarial_inputs = [
            {"info": "not_a_dict", "target": 123, "behavior": False, "debug": "error"},
            {"info": [], "target": "str_target", "behavior": 999, "network": "offline"},
            {"info": {"errors_or_warnings": "not_a_list"}, "dropped": "corrupted_array"},
            {"behavior": {"processes": "bad_procs", "dropped": 123, "network": 456, "summary": "none"}},
            {"dropped": [{"name": 123, "guest_paths": "not_a_list", "sha256": None}]},
            {"behavior": {"network": {"dns": "not_a_list", "http": 123, "tcp": None}}},
            None,
            {},
        ]
        for raw in adversarial_inputs:
            # Must not throw AttributeError, TypeError, or ValueError
            report = parse_cape_report(raw, report_id="test_cape")
            self.assertIsNotNone(report)
            self.assertEqual(report.report_id, "test_cape")

    def test_malformed_primitive_types_in_falcon_parser(self):
        """Falcon parser must safely handle non-dict primitives in place of objects/lists."""
        adversarial_inputs = [
            {"submission_info": "not_a_dict", "execution": 123},
            {"submission_info": 123, "execution": "corrupted"},
            {"submission_info": {"sample_metadata": "not_a_dict", "system_warnings": "not_a_list"}},
            {"execution": {"process_tree": "bad_tree", "created_files": 456, "network_traffic": "none"}},
            {"execution": {"network_traffic": {"dns_requests": "invalid", "http_transactions": None}}},
            {"execution": {"process_tree": [None, "invalid_node", 123, {"pid": "non_numeric_pid"}]}},
            None,
            {},
        ]
        for raw in adversarial_inputs:
            report = parse_falcon_report(raw, report_id="test_falcon")
            self.assertIsNotNone(report)
            self.assertEqual(report.report_id, "test_falcon")

    def test_detector_schema_resilience(self):
        """Schema detector must never crash when passed arbitrary non-dict or malformed types."""
        fuzz_cases = [
            None,
            "",
            "random string",
            12345,
            True,
            [],
            [1, 2, 3],
            {"submission_info": 12345},  # primitive in submission_info
            {"submission_info": "str_val"},
            {"info": "cape_primitive"},
            {"execution": "string_execution"},
        ]
        for c in fuzz_cases:
            res = detect_schema(c)
            self.assertIn(res, ["falcon", "cape", "unknown"])

    def test_xss_adversarial_payloads_in_all_fields(self):
        """Hostile HTML/script payloads in filenames, process names, commands, and network targets."""
        xss_cape = {
            "info": {
                "sandbox_name": "<script>alert('sandbox')</script>",
                "version": "v1.0<img src=x onerror=alert(1)>",
                "errors_or_warnings": ["<svg/onload=alert('warn')>"]
            },
            "target": {
                "file": {
                    "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "name": "calc.exe<script>alert('sample')</script>"
                }
            },
            "behavior": {
                "processes": [
                    {
                        "process_id": 100,
                        "process_name": "malware.exe\"><script>alert('proc')</script>",
                        "command_line": "malware.exe -arg \"'><svg/onload=alert('cmd')>",
                        "parent_id": None
                    }
                ],
                "dropped": [
                    {
                        "name": "payload.dll\"><img src=x onerror=alert(2)>",
                        "path": "C:\\Windows\\System32\\<script>alert(3)</script>.dll",
                        "sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                    }
                ],
                "network": {
                    "dns": [{"domain": "evil<script>.com", "resolved_ip": "1.2.3.4"}],
                    "http": [{"url": "http://evil<svg onload=alert(1)>.com/gate.php", "method": "POST"}],
                    "tcp": [{"dst_ip": "1.2.3.4", "dst_port": 8080}]
                }
            }
        }

        xss_falcon = {
            "submission_info": {
                "analyzer": "<script>alert('falcon')</script>",
                "sample_metadata": {
                    "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                },
                "system_warnings": [
                    {
                        "code": "WARN_<script>",
                        "description": "Network egress blocked: <img src=x onerror=alert(4)>"
                    }
                ]
            },
            "execution": {
                "process_tree": [
                    {
                        "pid": 200,
                        "ppid": None,
                        "name": "malware.exe\"><script>alert('proc')</script>",
                        "cmdline": "malware.exe -arg \"'><svg/onload=alert('cmd')>"
                    }
                ],
                "created_files": [
                    {
                        "filename": "C:\\temp\\dropped.dll\"><script>alert(5)</script>",
                        "sha256_hash": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                    }
                ],
                "network_traffic": {
                    "dns_requests": [{"hostname": "evil<script>.com", "ip_addresses": ["1.2.3.4"]}],
                    "http_transactions": [{"uri": "http://evil<svg onload=alert(1)>.com/gate.php", "method": "POST"}],
                    "active_tcp_streams": [{"destination_ip": "1.2.3.4", "destination_port": 8080}]
                }
            }
        }

        # 1. Parsing must complete cleanly
        norm_a = parse_auto_report(xss_cape, report_id="xss_a")
        norm_b = parse_auto_report(xss_falcon, report_id="xss_b")

        # 2. Reconciliation must succeed
        comparator = EvidenceComparator(norm_a, norm_b)
        result = comparator.reconcile()

        # 3. Serialization to web payload must succeed
        serialized = serialize_comparison(result)
        self.assertIn("reconciled_processes", serialized)
        self.assertIn("reconciled_files", serialized)
        self.assertIn("reconciled_network", serialized)

        # 4. Process match verified
        matched_procs = [p for p in serialized["reconciled_processes"] if p["observation_presence"] == "OBSERVED_IN_BOTH"]
        self.assertEqual(len(matched_procs), 1)

    def test_api_reconciliation_error_sanitization_no_leak(self):
        """API must return HTTP 422 with sanitized detail and never leak filesystem paths or stack traces."""
        req = CompareRequest(
            report_a_raw={"info": {}},
            report_b_raw={"info": {}}
        )

        with patch("web.app.EvidenceComparator") as mock_comparator:
            # Simulate an internal crash containing a sensitive host path
            mock_comparator.side_effect = RuntimeError("Fatal error in /Users/namanbhatt/private/db/secret.key: memory corruption")
            
            with self.assertRaises(HTTPException) as ctx:
                compare_reports(req)
            
            exc = ctx.exception
            self.assertEqual(exc.status_code, 422)
            # Detail must be sanitized
            self.assertEqual(exc.detail, "Invalid report payload or unsupported schema structure.")
            # Verify no path leakage
            self.assertNotIn("/Users/namanbhatt", str(exc.detail))
            self.assertNotIn("secret.key", str(exc.detail))
            self.assertNotIn("Fatal error", str(exc.detail))

    def test_browser_dom_xss_execution_prevention(self):
        """Executes the live web UI inside WHATWG JSDOM to verify zero script execution on hostile payloads."""
        import shutil
        import subprocess
        from pathlib import Path

        this_dir = Path(__file__).resolve().parent
        candidate_scripts = [
            this_dir / "test_dom_xss.js",
            this_dir / "tests" / "test_dom_xss.js",
            this_dir.parent / "tests" / "test_dom_xss.js",
        ]
        js_script = next((p for p in candidate_scripts if p.exists()), None)
        if not js_script:
            self.skipTest("test_dom_xss.js not found")

        node_bin = shutil.which("node")
        if not node_bin:
            self.skipTest("Node.js runtime not found on host")

        res = subprocess.run(
            [node_bin, str(js_script)],
            capture_output=True,
            text=True
        )
        self.assertEqual(
            res.returncode, 0,
            f"DOM XSS Suite failed with output:\n{res.stdout}\n{res.stderr}"
        )
        self.assertIn("PASS: Browser-level DOM security suite verified", res.stdout)


if __name__ == "__main__":
    unittest.main()
