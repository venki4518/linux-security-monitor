
import pytest

from src.alert_engine import AlertEngine


# --------------------------------------------------
# 1. INITIALIZATION TESTS
# --------------------------------------------------

def test_alert_engine_initializes_with_empty_findings():
    engine = AlertEngine()

    assert engine.findings == []


# --------------------------------------------------
# 2. ADD FINDING TESTS
# --------------------------------------------------

def test_add_finding():
    engine = AlertEngine()

    engine.add_finding(
        title="Test security finding",
        description="Testing alert generation",
        severity="HIGH",
        category="Test"
    )

    assert len(engine.findings) == 1
    assert engine.findings[0]["severity"] == "HIGH"


def test_add_finding_stores_all_fields():
    engine = AlertEngine()

    engine.add_finding(
        title="Suspicious login",
        description="Multiple failed login attempts",
        severity="MEDIUM",
        category="Authentication"
    )

    finding = engine.findings[0]

    assert finding["title"] == "Suspicious login"
    assert finding["description"] == "Multiple failed login attempts"
    assert finding["severity"] == "MEDIUM"
    assert finding["category"] == "Authentication"
    assert "timestamp" in finding


def test_add_finding_generates_valid_timestamp():
    from datetime import datetime

    engine = AlertEngine()

    engine.add_finding(
        "Test", "Timestamp test", "LOW", "Test"
    )

    timestamp = engine.findings[0]["timestamp"]

    parsed_timestamp = datetime.fromisoformat(timestamp)

    assert parsed_timestamp.tzinfo is not None


def test_lowercase_severity_is_normalized():
    engine = AlertEngine()

    engine.add_finding(
        "Test", "Lowercase severity", "high", "Test"
    )

    assert engine.findings[0]["severity"] == "HIGH"


@pytest.mark.parametrize(
    "severity",
    ["INVALID", "CRITICAL", "", "INFO"]
)
def test_invalid_severity_raises_error(severity):
    engine = AlertEngine()

    with pytest.raises(ValueError, match="Invalid severity level"):
        engine.add_finding(
            "Test", "Invalid severity test", severity, "Test"
        )

    assert engine.findings == []


# --------------------------------------------------
# 3. ADD MULTIPLE FINDINGS TESTS
# --------------------------------------------------

def test_add_multiple_findings():
    engine = AlertEngine()

    findings = [
        {
            "title": "Failed login",
            "description": "Repeated login failures",
            "severity": "HIGH",
            "category": "Authentication"
        },
        {
            "title": "Open service",
            "description": "Service requires review",
            "severity": "MEDIUM",
            "category": "Network"
        }
    ]

    engine.add_findings(findings)

    assert len(engine.findings) == 2
    assert engine.findings[0]["title"] == "Failed login"
    assert engine.findings[1]["title"] == "Open service"


def test_add_empty_findings_list():
    engine = AlertEngine()

    engine.add_findings([])

    assert engine.findings == []


def test_add_findings_normalizes_lowercase_severity():
    engine = AlertEngine()

    findings = [
        {
            "title": "Test",
            "description": "Testing lowercase severity",
            "severity": "low",
            "category": "Test"
        }
    ]

    engine.add_findings(findings)

    assert engine.findings[0]["severity"] == "LOW"


# --------------------------------------------------
# 4. SUMMARY TESTS
# --------------------------------------------------

def test_alert_summary():
    engine = AlertEngine()

    engine.add_finding(
        "Finding 1", "High severity test", "HIGH", "Test"
    )

    engine.add_finding(
        "Finding 2", "Medium severity test", "MEDIUM", "Test"
    )

    engine.add_finding(
        "Finding 3", "Low severity test", "LOW", "Test"
    )

    summary = engine.get_summary()

    assert summary["total"] == 3
    assert summary["high"] == 1
    assert summary["medium"] == 1
    assert summary["low"] == 1


def test_empty_alert_summary():
    engine = AlertEngine()

    summary = engine.get_summary()

    assert summary == {
        "total": 0,
        "high": 0,
        "medium": 0,
        "low": 0
    }


def test_summary_with_multiple_high_findings():
    engine = AlertEngine()

    for number in range(3):
        engine.add_finding(
            f"Finding {number}",
            "High severity test",
            "HIGH",
            "Test"
        )

    summary = engine.get_summary()

    assert summary["total"] == 3
    assert summary["high"] == 3
    assert summary["medium"] == 0
    assert summary["low"] == 0


# --------------------------------------------------
# 5. DISPLAY FINDINGS TESTS
# --------------------------------------------------

def test_display_empty_findings(capsys):
    engine = AlertEngine()

    engine.display_findings()

    output = capsys.readouterr().out

    assert "SECURITY FINDINGS" in output
    assert "No security findings recorded." in output


def test_display_recorded_findings(capsys):
    engine = AlertEngine()

    engine.add_finding(
        "Suspicious login",
        "Multiple failed login attempts",
        "HIGH",
        "Authentication"
    )

    engine.display_findings()

    output = capsys.readouterr().out

    assert "Finding #1" in output
    assert "Suspicious login" in output
    assert "Multiple failed login attempts" in output
    assert "HIGH" in output
    assert "Authentication" in output
    assert "Timestamp" in output


def test_display_multiple_findings(capsys):
    engine = AlertEngine()

    engine.add_finding(
        "Finding One", "First test", "HIGH", "Test"
    )

    engine.add_finding(
        "Finding Two", "Second test", "LOW", "Test"
    )

    engine.display_findings()

    output = capsys.readouterr().out

    assert "Finding #1" in output
    assert "Finding #2" in output
    assert "Finding One" in output
    assert "Finding Two" in output
