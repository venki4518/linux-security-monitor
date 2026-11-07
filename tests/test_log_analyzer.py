
import pytest

from src import log_analyzer


# --------------------------------------------------
# 1. LOG FILE READING TESTS
# --------------------------------------------------

def test_read_auth_logs_success(monkeypatch):
    class FakeLog:
        def read_text(self, encoding, errors):
            return (
                "Failed password for user\n"
                "Invalid user hacker"
            )

    monkeypatch.setattr(log_analyzer, "AUTH_LOG", FakeLog())

    entries = log_analyzer.read_auth_logs()

    assert len(entries) == 2
    assert entries[0] == "Failed password for user"
    assert entries[1] == "Invalid user hacker"


@pytest.mark.parametrize(
    "error",
    [
        PermissionError("Permission denied"),
        FileNotFoundError("File not found")
    ]
)
def test_read_auth_logs_errors(monkeypatch, capsys, error):
    class FakeLog:
        def read_text(self, encoding, errors):
            raise error

    monkeypatch.setattr(log_analyzer, "AUTH_LOG", FakeLog())

    entries = log_analyzer.read_auth_logs()

    assert entries == []
    assert "Unable to read authentication log" in capsys.readouterr().out


# --------------------------------------------------
# 2. LOG EVENT DETECTION TESTS
# --------------------------------------------------

def test_failed_password_detection():
    logs = [
        "Failed password for venkatesh from 192.168.1.10 port 22 ssh2"
    ]

    results = log_analyzer.analyze_logs(logs)

    assert len(results["failed_password"]) == 1


def test_invalid_user_detection():
    logs = [
        "Invalid user hacker from 192.168.1.20 port 22"
    ]

    results = log_analyzer.analyze_logs(logs)

    assert len(results["invalid_user"]) == 1


def test_authentication_failure_detection():
    logs = [
        "pam_unix(sshd:auth): authentication failure"
    ]

    results = log_analyzer.analyze_logs(logs)

    assert len(results["authentication_failure"]) == 1


def test_sudo_session_detection():
    logs = [
        "pam_unix(sudo:session): session opened for user root"
    ]

    results = log_analyzer.analyze_logs(logs)

    assert len(results["sudo_sessions"]) == 1


def test_ignore_grep_command():
    logs = [
        "Failed password for user from 192.168.1.10",
        "COMMAND=/usr/bin/grep Failed password"
    ]

    results = log_analyzer.analyze_logs(logs)

    assert len(results["failed_password"]) == 1


def test_detection_is_case_insensitive():
    logs = [
        "FAILED PASSWORD for user",
        "INVALID USER hacker",
        "AUTHENTICATION FAILURE"
    ]

    results = log_analyzer.analyze_logs(logs)

    assert len(results["failed_password"]) == 1
    assert len(results["invalid_user"]) == 1
    assert len(results["authentication_failure"]) == 1


def test_empty_log_entries():
    results = log_analyzer.analyze_logs([])

    assert results == {
        "failed_password": [],
        "authentication_failure": [],
        "invalid_user": [],
        "sudo_sessions": []
    }


def test_multiple_event_types_in_same_line():
    logs = [
        "Failed password and authentication failure for invalid user"
    ]

    results = log_analyzer.analyze_logs(logs)

    assert len(results["failed_password"]) == 1
    assert len(results["authentication_failure"]) == 1
    assert len(results["invalid_user"]) == 1


# --------------------------------------------------
# 3. SECURITY FINDING SEVERITY TESTS
# --------------------------------------------------

def make_failure_results(count):
    return {
        "failed_password": ["failure"] * count,
        "authentication_failure": [],
        "invalid_user": []
    }


def test_low_severity():
    findings = log_analyzer.generate_log_findings(
        make_failure_results(2)
    )

    assert len(findings) == 1
    assert findings[0]["severity"] == "LOW"


def test_medium_severity():
    findings = log_analyzer.generate_log_findings(
        make_failure_results(5)
    )

    assert findings[0]["severity"] == "MEDIUM"


def test_high_severity():
    findings = log_analyzer.generate_log_findings(
        make_failure_results(10)
    )

    assert findings[0]["severity"] == "HIGH"


def test_four_failures_are_low_severity():
    findings = log_analyzer.generate_log_findings(
        make_failure_results(4)
    )

    assert findings[0]["severity"] == "LOW"


def test_nine_failures_are_medium_severity():
    findings = log_analyzer.generate_log_findings(
        make_failure_results(9)
    )

    assert findings[0]["severity"] == "MEDIUM"


def test_no_failures_generate_no_findings():
    findings = log_analyzer.generate_log_findings(
        make_failure_results(0)
    )

    assert findings == []


def test_findings_include_expected_details():
    findings = log_analyzer.generate_log_findings(
        make_failure_results(2)
    )

    finding = findings[0]

    assert finding["title"] == "Authentication failures detected"
    assert "2 authentication failure events" in finding["description"]
    assert finding["category"] == "Authentication"


# --------------------------------------------------
# 4. IP ADDRESS EXTRACTION TESTS
# --------------------------------------------------

def test_extract_ipv4_addresses():
    events = [
        "Failed password from 192.168.1.10",
        "Failed password from 192.168.1.10",
        "Invalid user from 10.0.0.5"
    ]

    counts = log_analyzer.extract_ip_addresses(events)

    assert counts["192.168.1.10"] == 2
    assert counts["10.0.0.5"] == 1


def test_extract_ip_addresses_from_empty_events():
    counts = log_analyzer.extract_ip_addresses([])

    assert counts == {}


def test_extract_ip_addresses_when_none_exist():
    events = [
        "Failed password for user",
        "Invalid user hacker"
    ]

    counts = log_analyzer.extract_ip_addresses(events)

    assert counts == {}


def test_extract_multiple_ip_addresses_from_one_event():
    events = [
        "Connection from 192.168.1.10 to 10.0.0.5"
    ]

    counts = log_analyzer.extract_ip_addresses(events)

    assert counts["192.168.1.10"] == 1
    assert counts["10.0.0.5"] == 1


# --------------------------------------------------
# 5. REPORT DISPLAY TESTS
# --------------------------------------------------

def test_display_report_with_no_failures(capsys):
    results = {
        "failed_password": [],
        "authentication_failure": [],
        "invalid_user": [],
        "sudo_sessions": []
    }

    log_analyzer.display_report(results)

    output = capsys.readouterr().out

    assert "AUTHENTICATION SECURITY REPORT" in output
    assert "No matching authentication failures detected." in output


def test_display_report_with_failures_and_ip(capsys):
    results = {
        "failed_password": [
            "Failed password from 192.168.1.10"
        ],
        "authentication_failure": [],
        "invalid_user": [],
        "sudo_sessions": []
    }

    log_analyzer.display_report(results)

    output = capsys.readouterr().out

    assert "LOW: Authentication failures detected." in output
    assert "192.168.1.10: 1 event(s)" in output


def test_display_report_without_ip_addresses(capsys):
    results = {
        "failed_password": ["Failed password for user"],
        "authentication_failure": [],
        "invalid_user": [],
        "sudo_sessions": []
    }

    log_analyzer.display_report(results)

    output = capsys.readouterr().out

    assert "No IPv4 addresses found" in output


def test_display_report_high_severity(capsys):
    results = {
        "failed_password": ["failure"] * 10,
        "authentication_failure": [],
        "invalid_user": [],
        "sudo_sessions": []
    }

    log_analyzer.display_report(results)

    output = capsys.readouterr().out

    assert "HIGH: Multiple authentication failures detected." in output


# --------------------------------------------------
# 6. COMPLETE LOG ANALYSIS WORKFLOW
# --------------------------------------------------

def test_run_log_analysis(monkeypatch, capsys):
    logs = [
        "Failed password from 192.168.1.10",
        "Failed password from 192.168.1.10",
        "Invalid user hacker from 10.0.0.5",
        "Authentication failure from 10.0.0.5",
        "Failed password from 192.168.1.20",
        "pam_unix(sudo:session): session opened for user root"
    ]

    monkeypatch.setattr(
        log_analyzer,
        "read_auth_logs",
        lambda: logs
    )

    audit_data = log_analyzer.run_log_analysis()

    assert audit_data["total_log_entries"] == 6
    assert audit_data["failed_password_count"] == 3
    assert audit_data["invalid_user_count"] == 1
    assert audit_data["authentication_failure_count"] == 1
    assert audit_data["successful_sudo_sessions"] == 1
    assert audit_data["source_ip_counts"]["192.168.1.10"] == 2
    assert audit_data["log_available"] is True
    assert audit_data["findings"][0]["severity"] == "MEDIUM"

    output = capsys.readouterr().out

    assert "LOG ANALYSIS COMPLETED" in output


def test_run_log_analysis_with_empty_logs(monkeypatch):
    monkeypatch.setattr(
        log_analyzer,
        "read_auth_logs",
        lambda: []
    )

    audit_data = log_analyzer.run_log_analysis()

    assert audit_data["total_log_entries"] == 0
    assert audit_data["findings"] == []
    assert audit_data["log_available"] is False
