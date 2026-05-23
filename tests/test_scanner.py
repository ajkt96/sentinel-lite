"""Unit Tests for Sentinel-Lite"""

import unittest
from src.core.scanner import SentinelLite, RiskLevel, IdentityFinding


class TestSentinelLite(unittest.TestCase):

    def setUp(self):
        self.scanner = SentinelLite(cloud_provider="aws")

    def test_scanner_initialization(self):
        self.assertIsNotNone(self.scanner)
        self.assertEqual(self.scanner.cloud_provider, "aws")

    def test_identity_finding_creation(self):
        finding = IdentityFinding(
            finding_id="test-1",
            title="Test Finding",
            description="Test description",
            resource_id="arn:aws:iam::123456789:role/test",
            resource_type="IAM::Role",
            cloud_provider="AWS",
            severity=RiskLevel.HIGH
        )
        self.assertEqual(finding.title, "Test Finding")
        self.assertEqual(finding.severity, RiskLevel.HIGH)

    def test_compliance_audit(self):
        results = self.scanner.audit_compliance()
        self.assertIn('compliance_score', results)
        self.assertIn('findings', results)
        self.assertIn('framework', results)

    def test_dangerous_action_detection(self):
        findings = self.scanner.scan_iam_policies()
        self.assertGreater(len(findings), 0)
        critical_findings = [f for f in findings if f['severity'] == 'CRITICAL']
        self.assertGreater(len(critical_findings), 0)


if __name__ == '__main__':
    unittest.main()
