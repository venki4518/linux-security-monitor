# Linux Security Monitoring System

A Python-based Linux security auditing tool that collects system information, reviews authentication logs, checks user accounts and file permissions, monitors system services, and gathers basic network information.

The project is designed as a practical cybersecurity learning project focused on Linux security fundamentals, defensive monitoring, Python automation, and structured security reporting.

## Project Objectives

- Understand Linux system security and administration.
- Audit user accounts and administrative privileges.
- Identify authentication failures from Linux authentication logs.
- Review permissions on important system directories.
- Identify failed systemd services.
- Collect listening-port, network-interface, and routing information.
- Check DNS resolution.
- Generate structured security findings and JSON reports.
- Apply Python unit testing and test coverage.

## Features

| Module | Functionality |
|---|---|
| System Audit | Collects OS, hostname, kernel, uptime, disk, and memory information |
| User Audit | Reviews local user accounts and sudo group membership |
| Log Analyzer | Identifies failed passwords, authentication failures, invalid users, and sudo sessions |
| Permission Audit | Reviews permissions and world-writable directories |
| Service Audit | Collects running, failed, and enabled systemd services |
| Network Audit | Collects listening ports, interfaces, routing information, and DNS results |
| Alert Engine | Validates and manages LOW, MEDIUM, and HIGH security findings |
| Report Generator | Produces timestamped JSON security reports |
| Main Controller | Coordinates all audit modules |

## Technology Stack

- **Language:** Python
- **Operating System:** Ubuntu Linux (WSL2 environment)
- **System Tools:** systemctl, ss, ip
- **Testing:** pytest, pytest-cov
- **Version Control:** Git and GitHub
- **Output:** JSON security reports

## Project Structure

```text
linux-security-monitor/
│
├── src/
│   ├── __init__.py
│   ├── main.py
│   ├── system_audit.py
│   ├── user_audit.py
│   ├── log_analyzer.py
│   ├── permission_audit.py
│   ├── service_audit.py
│   ├── network_audit.py
│   ├── alert_engine.py
│   └── report_generator.py
│
├── tests/
│   ├── __init__.py
│   ├── test_main.py
│   ├── test_system_audit.py
│   ├── test_user_audit.py
│   ├── test_log_analyzer.py
│   ├── test_permission_audit.py
│   ├── test_service_audit.py
│   ├── test_network_audit.py
│   ├── test_alert_engine.py
│   └── test_report_generator.py
│
├── reports/
│   └── .gitkeep
│
├── logs/
│   └── .gitkeep
│
├── requirements.txt
├── .gitignore
└── README.md
```

## Installation and Setup

### 1. Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/linux-security-monitor.git
cd linux-security-monitor
```

Replace `YOUR_USERNAME` with your GitHub username.

### 2. Create a virtual environment

```bash
python3 -m venv .venv
```

### 3. Activate the environment

```bash
source .venv/bin/activate
```

### 4. Install dependencies

```bash
pip install -r requirements.txt
```

## Running the Project

Run the main security audit from the project root:

```bash
python -m src.main
```

The program executes the available audit modules, collects findings, displays a summary, and generates a timestamped JSON report in the `reports/` directory.

Some checks may require additional permissions to access protected system information.

## Running Tests

Run the complete test suite:

```bash
pytest -v
```

Run tests with code coverage:

```bash
pytest --cov=src --cov-report=term-missing
```

### Current Test Results

- **Total tests:** 106
- **Passed:** 106
- **Failed:** 0
- **Overall code coverage:** 98%

Coverage is based on the current test suite and execution environment.

## Security Findings

The alert engine supports three severity levels:

| Severity | Meaning |
|---|---|
| HIGH | A finding that requires priority investigation |
| MEDIUM | A finding that requires review |
| LOW | An informational or lower-priority finding |

Authentication failure thresholds currently use:
- 1–4 failures: LOW
- 5–9 failures: MEDIUM
- 10 or more failures: HIGH

These are configurable project rules, not universal security standards. Findings require investigation before being treated as confirmed security incidents.

## Generated Reports

The report generator creates timestamped JSON files containing collected audit information and security findings.

Example report filename:

```text
reports/security_report_YYYYMMDD_HHMMSS.json
```

Generated reports and logs are excluded from Git to avoid publishing potentially sensitive system information.

## Current Limitations

- The project currently focuses on a Linux environment, specifically Ubuntu running under WSL2.
- Authentication analysis reads `/var/log/auth.log`; environments using only journald or another logging configuration may require adaptation.
- User and permission checks are based on the information accessible to the executing process.
- Service monitoring depends on systemd being available.
- Network checks collect basic system information; they do not constitute a full network intrusion detection system.
- Authentication and permission findings are indicators for investigation, not proof of an attack.
- WSL2 does not provide a complete view of the Windows host's security state.

## Future Improvements

- Add journald-based authentication log collection.
- Improve IP address validation and event correlation.
- Add configurable detection thresholds.
- Add scheduled security audits.
- Introduce structured logging and improved error handling.
- Add HTML security reports and dashboard visualizations.
- Add controlled security-event simulation for testing.
- Expand detection rules for suspicious system activity.

## Learning Outcomes

Through this project, I practised:

- Linux command-line operations and system administration.
- Linux users, groups, permissions, and sudo access.
- Authentication log analysis.
- systemd service monitoring.
- Network troubleshooting and DNS investigation.
- Python scripting and automation.
- Modular programming and exception handling.
- Unit testing, mocking, and code coverage.
- Git version control and project documentation.

## Disclaimer

This project is intended for educational and defensive security auditing purposes. Run it only on systems you own or are explicitly authorized to assess. Review generated findings before making security decisions.
