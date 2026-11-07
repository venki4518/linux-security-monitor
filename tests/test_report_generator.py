
import json
from datetime import datetime

from src import report_generator


class FakeAlertEngine:
    def __init__(self):
        self.findings = [
            {
                "title": "Test security finding",
                "description": "This is a test finding.",
                "severity": "HIGH",
                "category": "Test"
            }
        ]

    def get_summary(self):
        return {
            "total": 1,
            "high": 1,
            "medium": 0,
            "low": 0
        }


def test_generate_report_creates_file(monkeypatch, tmp_path):
    monkeypatch.setattr(
        report_generator,
        "REPORT_DIRECTORY",
        tmp_path
    )

    system_data = {"operating_system": "Ubuntu"}
    user_data = {"total_accounts": 2}
    audit_data = {"network": {"dns_check": {"resolved": True}}}
    alert_engine = FakeAlertEngine()

    report_path = report_generator.generate_report(
        system_data,
        user_data,
        audit_data,
        alert_engine
    )

    assert report_path.exists()
    assert report_path.suffix == ".json"


def test_generate_report_contains_expected_data(monkeypatch, tmp_path):
    monkeypatch.setattr(
        report_generator,
        "REPORT_DIRECTORY",
        tmp_path
    )

    system_data = {"hostname": "test-machine"}
    user_data = {"total_accounts": 2}
    audit_data = {"permissions": {"directories_inspected": 4}}
    alert_engine = FakeAlertEngine()

    report_path = report_generator.generate_report(
        system_data,
        user_data,
        audit_data,
        alert_engine
    )

    with report_path.open(encoding="utf-8") as file:
        report = json.load(file)

    assert report["project"] == "Linux Security Monitoring System"
    assert report["system"] == system_data
    assert report["audits"]["users"] == user_data
    assert report["audits"]["other_audits"] == audit_data
    assert report["security_summary"] == alert_engine.get_summary()
    assert report["findings"] == alert_engine.findings


def test_generate_report_has_valid_timestamp(monkeypatch, tmp_path):
    monkeypatch.setattr(
        report_generator,
        "REPORT_DIRECTORY",
        tmp_path
    )

    report_path = report_generator.generate_report(
        {},
        {},
        {},
        FakeAlertEngine()
    )

    with report_path.open(encoding="utf-8") as file:
        report = json.load(file)

    timestamp = datetime.fromisoformat(report["scan_timestamp"])

    assert timestamp.tzinfo is not None


def test_generate_report_creates_directory(monkeypatch, tmp_path):
    report_directory = tmp_path / "new_reports"

    monkeypatch.setattr(
        report_generator,
        "REPORT_DIRECTORY",
        report_directory
    )

    report_path = report_generator.generate_report(
        {},
        {},
        {},
        FakeAlertEngine()
    )

    assert report_directory.is_dir()
    assert report_path.exists()


def test_generate_report_returns_path(monkeypatch, tmp_path):
    monkeypatch.setattr(
        report_generator,
        "REPORT_DIRECTORY",
        tmp_path
    )

    result = report_generator.generate_report(
        {},
        {},
        {},
        FakeAlertEngine()
    )

    assert result.parent == tmp_path
    assert result.name.startswith("security_report_")
    assert result.name.endswith(".json")
