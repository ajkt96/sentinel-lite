"""
SENTINEL-LITE Core Scanner
Zero Trust Cloud IAM Security Validation Engine
"""

import json
import logging
from typing import Dict, List, Any
from dataclasses import dataclass
from enum import Enum
from datetime import datetime
import hashlib


class RiskLevel(Enum):
    CRITICAL = 5
    HIGH = 4
    MEDIUM = 3
    LOW = 2
    INFO = 1


@dataclass
class IdentityFinding:
    finding_id: str
    title: str
    description: str
    resource_id: str
    resource_type: str
    cloud_provider: str
    severity: RiskLevel
    remediation: str = ""
    detected_at: str = None

    def to_dict(self):
        if self.detected_at is None:
            self.detected_at = datetime.utcnow().isoformat()
        return {
            'finding_id': self.finding_id,
            'title': self.title,
            'description': self.description,
            'resource_id': self.resource_id,
            'resource_type': self.resource_type,
            'severity': self.severity.name,
            'remediation': self.remediation,
            'detected_at': self.detected_at
        }


class SentinelLite:
    """Main Scanner Orchestrator"""

    def __init__(self, cloud_provider: str = "aws"):
        self.logger = logging.getLogger("SentinelLite")
        self.cloud_provider = cloud_provider
        self.findings = []

    def scan_iam_policies(self) -> List[Dict]:
        """Scan IAM policies and detect risks"""
        self.logger.info(f"Scanning {self.cloud_provider} IAM policies...")

        dangerous_patterns = [
            "*:*", "iam:*", "sts:AssumeRole",
            "ec2:TerminateInstances", "s3:*", "rds:DeleteDBInstance"
        ]

        findings = []
        sample_policies = [
            {
                'name': 's3-admin-role',
                'actions': ['s3:*'],
                'resources': ['*'],
                'severity': RiskLevel.CRITICAL
            },
            {
                'name': 'lambda-execution',
                'actions': ['logs:CreateLogGroup', 'logs:CreateLogStream'],
                'resources': ['arn:aws:logs:*:*:*'],
                'severity': RiskLevel.LOW
            }
        ]

        for policy in sample_policies:
            for action in policy['actions']:
                for pattern in dangerous_patterns:
                    if pattern in action:
                        finding = IdentityFinding(
                            finding_id=f"sentinel-{hashlib.md5(policy['name'].encode()).hexdigest()[:8]}",
                            title=f"Dangerous Action: {action}",
                            description=f"Policy {policy['name']} allows {action} on all resources",
                            resource_id=policy['name'],
                            resource_type="IAM::Role",
                            cloud_provider=self.cloud_provider,
                            severity=policy['severity'],
                            remediation=f"Restrict {action} to specific resources"
                        )
                        findings.append(finding.to_dict())

        return findings

    def audit_compliance(self) -> Dict[str, Any]:
        """Audit against NIST 800-207 Zero Trust"""
        self.logger.info("Auditing NIST 800-207 compliance...")

        findings = self.scan_iam_policies()
        compliance_score = max(0, min(100, 100 - (len(findings) * 5)))

        return {
            'scan_timestamp': datetime.utcnow().isoformat(),
            'cloud_provider': self.cloud_provider,
            'total_findings': len(findings),
            'compliance_score': compliance_score,
            'findings': findings[:10],
            'framework': 'NIST SP 800-207 Zero Trust Architecture',
            'status': 'COMPLIANT' if compliance_score >= 80 else 'NON_COMPLIANT'
        }


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    scanner = SentinelLite(cloud_provider="aws")
    results = scanner.audit_compliance()
    print(json.dumps(results, indent=2))
