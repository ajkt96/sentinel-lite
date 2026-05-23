# SENTINEL-LITE: Zero Trust Cloud IAM Security Scanner

[![CI/CD](https://github.com/ajkt96/sentinel-lite/actions/workflows/ci.yml/badge.svg)](https://github.com/ajkt96/sentinel-lite/actions)
[![Python](https://img.shields.io/badge/Python-3.9%2B-blue)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Enterprise-grade AWS/Azure IAM security scanner implementing NIST 800-207 Zero Trust Architecture.

## Overview

Sentinel-Lite automates cloud identity and access management security assessment across AWS and Azure environments. Detects privilege escalation risks, identifies compliance gaps, and provides automated remediation guidance.

## Key Features

- Real-time IAM configuration scanning (AWS + Azure)
- Privilege escalation & lateral movement detection
- NIST 800-207 Zero Trust compliance auditing
- CIS Benchmark mapping
- Multi-account support (200+ accounts)
- Compliance drift detection

## Quick Start

```bash
# Setup
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

```python
from src.core.scanner import SentinelLite

scanner = SentinelLite(cloud_provider="aws")
results = scanner.audit_compliance()
print(results)
```

## Example Output

```json
{
  "cloud_provider": "aws",
  "compliance_score": 67,
  "total_findings": 12,
  "findings": [
    {
      "title": "Dangerous Action: s3:*",
      "severity": "CRITICAL",
      "remediation": "Restrict to specific buckets"
    }
  ]
}
```

## Architecture

```
Cloud APIs (AWS/Azure) → Scanner → Analyzer → Auditor → Reporter
```

## Performance

- Scans 200+ accounts in <5 minutes
- Analyzes 10K+ IAM policies in <2 minutes
- Generates reports in <1 minute

## Running Tests

```bash
pytest tests/ -v --cov=src
```

## License

MIT License
