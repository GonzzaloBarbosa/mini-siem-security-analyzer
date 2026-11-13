
# Mini-SIEM Security Analyzer

A lightweight Python-based security log analyzer designed to explore SIEM fundamentals, authentication monitoring, and rule-based threat detection.

## Overview

This project processes simulated authentication logs and identifies suspicious login patterns using configurable detection logic.

It demonstrates a basic security monitoring workflow:

**Log ingestion → Event parsing → Detection rules → Alerts → JSON reporting**

## Features

- Parse authentication events from CSV files
- Detect 5 failed login attempts from the same IP within 5 minutes
- Detect successful logins preceded by 5 or more failed attempts from the same IP within 5 minutes
- Generate structured security alerts
- Export alerts to a JSON report
- Validate detection behavior using suspicious and benign test scenarios

## Technologies

- Python 3
- Python standard library (`csv`, `datetime`, `collections`, `json`, `pathlib`)
- CSV authentication logs
- JSON reporting

No external Python dependencies are required.

## Detection Rules

| Rule | Description | Severity |
|------|-------------|----------|
| BRUTE_FORCE | 5 failed login attempts from one IP within 5 minutes | MEDIUM |
| SUSPICIOUS_SUCCESSFUL_LOGIN | Successful login following at least 5 failures from the same IP within 5 minutes | HIGH |

Severity levels are illustrative and do not represent a production risk assessment.

## Project Structure

```text
mini-siem-security-analyzer/
├── logs/
│   └── auth_logs.csv
├── reports/
│   └── security_alerts.json  (generated locally)
├── main.py
├── .gitignore
└── README.md
```

## How to Run

Clone the repository:

```bash
git clone https://github.com/GonzzaloBarbosa/mini-siem-security-analyzer.git
cd mini-siem-security-analyzer
```

Run the analyzer:

```bash
python main.py
```

The application generates a JSON report at:

`reports/security_alerts.json`

## Testing

Two scenarios have been manually validated:

1. **Suspicious activity:** Five failed authentication attempts followed by a successful login from the same IP. Expected result: 2 alerts.
2. **Normal activity:** Two failed authentication attempts followed by a successful login. Expected result: 0 alerts.

These tests confirm the behavior of the implemented thresholds; they do not establish production detection accuracy.

## Limitations

This is an educational security log analyzer, not a full SIEM platform.

- Uses simulated CSV logs rather than live event ingestion
- Does not integrate with Splunk or Elasticsearch
- Does not include dashboards or real-time monitoring
- Detection rules are simplified and may produce false positives or false negatives
- Login correlation is based on source IP, not necessarily the same user account

## Future Improvements

- Parse Linux SSH authentication logs
- Add automated unit tests
- Make detection thresholds configurable
- Introduce additional detection rules
- Explore integration with Splunk or the Elastic Stack

## Learning Objectives

This project was developed to strengthen practical knowledge of security monitoring, event correlation, and detection engineering while preparing for the CompTIA Security+ certification.
