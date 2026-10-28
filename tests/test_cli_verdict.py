"""
Unit tests for cross-report activity classification and verdict generation.
Verifies that behavioral overlap is labeled accurately and neutrally without
unwarranted claims of confirmed compromise.
"""

import unittest
from cli import classify_cross_report_activity


class TestCliVerdict(unittest.TestCase):
    """Tests the three tiers of cross-report behavioral classification."""

    def test_corroborated_activity_both_processes_and_files(self):
        """When both processes and files match across runs, return corroborated alignment without asserting compromise."""
        verdict, summary = classify_cross_report_activity(matched_procs=2, matched_files=3)
        self.assertEqual(verdict, "CROSS-RUN ACTIVITY CORROBORATED")
        self.assertIn("2 process node(s)", summary)
        self.assertIn("3 file artifact(s)", summary)
        self.assertIn("does not establish maliciousness or confirm compromise", summary)

    def test_partial_activity_procs_only(self):
        """When only processes match, return partial alignment."""
        verdict, summary = classify_cross_report_activity(matched_procs=1, matched_files=0)
        self.assertEqual(verdict, "PARTIAL CROSS-RUN CORROBORATION")
        self.assertIn("1 process node(s)", summary)
        self.assertIn("0 file artifact(s)", summary)

    def test_partial_activity_files_only(self):
        """When only files match, return partial alignment."""
        verdict, summary = classify_cross_report_activity(matched_procs=0, matched_files=4)
        self.assertEqual(verdict, "PARTIAL CROSS-RUN CORROBORATION")
        self.assertIn("0 process node(s)", summary)
        self.assertIn("4 file artifact(s)", summary)

    def test_low_corroboration(self):
        """When zero processes and zero files match, return low alignment with epistemic caveat."""
        verdict, summary = classify_cross_report_activity(matched_procs=0, matched_files=0)
        self.assertEqual(verdict, "LOW CROSS-RUN CORROBORATION")
        self.assertIn("This does not establish that the behavior did not occur", summary)


if __name__ == "__main__":
    unittest.main()
