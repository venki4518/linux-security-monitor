
import subprocess
from types import SimpleNamespace

from src import service_audit


def test_run_command_success(monkeypatch):
    def fake_run(command, **kwargs):
        return SimpleNamespace(
            returncode=0,
            stdout="test.service loaded active running Test service\n",
            stderr=""
        )

    monkeypatch.setattr(
        service_audit.subprocess,
        "run",
        fake_run
    )

    result = service_audit.run_command(["systemctl", "--version"])

    assert "test.service" in result


def test_run_command_failure(monkeypatch, capsys):
    def fake_run(command, **kwargs):
        return SimpleNamespace(
            returncode=1,
            stdout="",
            stderr="Access denied"
        )

    monkeypatch.setattr(
        service_audit.subprocess,
        "run",
        fake_run
    )

    result = service_audit.run_command(["systemctl", "--failed"])

    captured = capsys.readouterr()

    assert result == ""
    assert "Command returned code: 1" in captured.out
    assert "Access denied" in captured.out


def test_run_command_failure_without_stderr(monkeypatch, capsys):
    def fake_run(command, **kwargs):
        return SimpleNamespace(
            returncode=2,
            stdout="",
            stderr=""
        )

    monkeypatch.setattr(
        service_audit.subprocess,
        "run",
        fake_run
    )

    result = service_audit.run_command(["systemctl", "--failed"])

    captured = capsys.readouterr()

    assert result == ""
    assert "Command returned code: 2" in captured.out


def test_run_command_missing_command(monkeypatch, capsys):
    def fake_run(command, **kwargs):
        raise FileNotFoundError

    monkeypatch.setattr(
        service_audit.subprocess,
        "run",
        fake_run
    )

    result = service_audit.run_command(["unknown-command"])

    captured = capsys.readouterr()

    assert result == ""
    assert "Command not found" in captured.out


def test_running_services_filters_invalid_lines(monkeypatch):
    fake_output = (
        "cron.service loaded active running Regular background program\n"
        "dbus.service loaded active running D-Bus System Message Bus\n"
        "UNIT LOAD ACTIVE SUB DESCRIPTION\n"
        "\n"
    )

    monkeypatch.setattr(
        service_audit,
        "run_command",
        lambda command: fake_output
    )

    result = service_audit.get_running_services()

    assert len(result) == 2
    assert all(item.split()[0].endswith(".service") for item in result)


def test_failed_services_filters_invalid_lines(monkeypatch):
    fake_output = (
        "test-failed.service loaded failed failed Test failure\n"
        "UNIT LOAD ACTIVE SUB DESCRIPTION\n"
        "\n"
    )

    monkeypatch.setattr(
        service_audit,
        "run_command",
        lambda command: fake_output
    )

    result = service_audit.get_failed_services()

    assert result == [
        "test-failed.service loaded failed failed Test failure"
    ]


def test_enabled_services_filters_invalid_lines(monkeypatch):
    fake_output = (
        "cron.service enabled enabled\n"
        "ssh.service enabled enabled\n"
        "UNIT FILE STATE PRESET\n"
    )

    monkeypatch.setattr(
        service_audit,
        "run_command",
        lambda command: fake_output
    )

    result = service_audit.get_enabled_services()

    assert len(result) == 2
    assert "cron.service" in result[0]
    assert "ssh.service" in result[1]


def test_generate_service_findings_multiple():
    failed = [
        "cron.service loaded failed failed",
        "test.service loaded failed failed"
    ]

    findings = service_audit.generate_service_findings(failed)

    assert len(findings) == 2
    assert findings[0]["severity"] == "MEDIUM"
    assert findings[1]["severity"] == "MEDIUM"
    assert "cron.service" in findings[0]["description"]
    assert "test.service" in findings[1]["description"]


def test_generate_service_findings_empty():
    findings = service_audit.generate_service_findings([])

    assert findings == []


def test_run_service_audit_returns_expected_data(monkeypatch):
    running = ["cron.service loaded active running"]
    failed = ["test.service loaded failed failed"]
    enabled = ["cron.service enabled enabled"]

    monkeypatch.setattr(
        service_audit,
        "get_running_services",
        lambda: running
    )

    monkeypatch.setattr(
        service_audit,
        "get_failed_services",
        lambda: failed
    )

    monkeypatch.setattr(
        service_audit,
        "get_enabled_services",
        lambda: enabled
    )

    result = service_audit.run_service_audit()

    assert result["running_services_count"] == 1
    assert result["failed_services_count"] == 1
    assert result["enabled_services_count"] == 1

    assert result["running_services"] == running
    assert result["failed_services"] == failed
    assert result["enabled_services"] == enabled

    assert len(result["findings"]) == 1


def test_run_service_audit_without_failed_services(monkeypatch):
    monkeypatch.setattr(
        service_audit,
        "get_running_services",
        lambda: ["cron.service loaded active running"]
    )

    monkeypatch.setattr(
        service_audit,
        "get_failed_services",
        lambda: []
    )

    monkeypatch.setattr(
        service_audit,
        "get_enabled_services",
        lambda: ["cron.service enabled enabled"]
    )

    result = service_audit.run_service_audit()

    assert result["failed_services_count"] == 0
    assert result["findings"] == []
