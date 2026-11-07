
import subprocess
from types import SimpleNamespace

from src import network_audit


def test_run_command_success(monkeypatch):
    def fake_run(command, **kwargs):
        return SimpleNamespace(
            returncode=0,
            stdout="  network output  \n"
        )

    monkeypatch.setattr(
        network_audit.subprocess,
        "run",
        fake_run
    )

    result = network_audit.run_command(["ip", "addr"])

    assert result == "network output"


def test_run_command_failure(monkeypatch):
    def fake_run(command, **kwargs):
        return SimpleNamespace(
            returncode=1,
            stdout="",
            stderr="command failed"
        )

    monkeypatch.setattr(
        network_audit.subprocess,
        "run",
        fake_run
    )

    assert network_audit.run_command(["ip", "addr"]) == ""


def test_run_command_timeout(monkeypatch):
    def fake_run(command, **kwargs):
        raise subprocess.TimeoutExpired(command, 10)

    monkeypatch.setattr(
        network_audit.subprocess,
        "run",
        fake_run
    )

    assert network_audit.run_command(["ip", "addr"]) == ""


def test_run_command_missing_command(monkeypatch):
    def fake_run(command, **kwargs):
        raise FileNotFoundError

    monkeypatch.setattr(
        network_audit.subprocess,
        "run",
        fake_run
    )

    assert network_audit.run_command(["unknown-command"]) == ""


def test_get_listening_ports(monkeypatch):
    monkeypatch.setattr(
        network_audit,
        "run_command",
        lambda command: "TCP listening sockets"
    )

    assert network_audit.get_listening_ports() == "TCP listening sockets"


def test_get_process_details(monkeypatch):
    def fake_run_command(command):
        assert command == ["sudo", "ss", "-tulnp"]
        return "process details"

    monkeypatch.setattr(
        network_audit,
        "run_command",
        fake_run_command
    )

    assert network_audit.get_process_details() == "process details"


def test_get_network_interfaces(monkeypatch):
    def fake_run_command(command):
        assert command == ["ip", "addr"]
        return "interface details"

    monkeypatch.setattr(
        network_audit,
        "run_command",
        fake_run_command
    )

    assert network_audit.get_network_interfaces() == "interface details"


def test_get_routing_table(monkeypatch):
    def fake_run_command(command):
        assert command == ["ip", "route"]
        return "default via gateway"

    monkeypatch.setattr(
        network_audit,
        "run_command",
        fake_run_command
    )

    assert network_audit.get_routing_table() == "default via gateway"


def test_run_network_audit_returns_all_results(monkeypatch):
    monkeypatch.setattr(
        network_audit,
        "get_listening_ports",
        lambda: "listening ports"
    )

    monkeypatch.setattr(
        network_audit,
        "get_process_details",
        lambda: "process information"
    )

    monkeypatch.setattr(
        network_audit,
        "get_network_interfaces",
        lambda: "interface information"
    )

    monkeypatch.setattr(
        network_audit,
        "get_routing_table",
        lambda: "routing information"
    )

    monkeypatch.setattr(
        network_audit,
        "check_dns",
        lambda: {
            "domain": "example.com",
            "resolved": True,
            "ip_address": "192.0.2.10"
        }
    )

    result = network_audit.run_network_audit()

    assert result["listening_ports"] == "listening ports"
    assert result["process_details"] == "process information"
    assert result["network_interfaces"] == "interface information"
    assert result["routing_table"] == "routing information"
    assert result["dns_check"]["resolved"] is True
    assert result["findings"] == []


def test_run_network_audit_handles_dns_failure(monkeypatch):
    monkeypatch.setattr(
        network_audit,
        "get_listening_ports",
        lambda: ""
    )

    monkeypatch.setattr(
        network_audit,
        "get_process_details",
        lambda: ""
    )

    monkeypatch.setattr(
        network_audit,
        "get_network_interfaces",
        lambda: ""
    )

    monkeypatch.setattr(
        network_audit,
        "get_routing_table",
        lambda: ""
    )

    monkeypatch.setattr(
        network_audit,
        "check_dns",
        lambda: {
            "domain": "example.invalid",
            "resolved": False,
            "ip_address": None
        }
    )

    result = network_audit.run_network_audit()

    assert len(result["findings"]) == 1
    assert result["findings"][0]["severity"] == "MEDIUM"


def test_dns_success(monkeypatch):
    monkeypatch.setattr(
        network_audit.socket,
        "gethostbyname",
        lambda domain: "142.250.66.14"
    )

    result = network_audit.check_dns("google.com")

    assert result["resolved"] is True
    assert result["ip_address"] == "142.250.66.14"


def test_dns_failure(monkeypatch):
    def fake_dns(domain):
        raise network_audit.socket.gaierror

    monkeypatch.setattr(
        network_audit.socket,
        "gethostbyname",
        fake_dns
    )

    result = network_audit.check_dns("invalid.example")

    assert result["resolved"] is False
    assert result["ip_address"] is None


def test_dns_failure_generates_finding():
    result = network_audit.generate_network_findings({
        "domain": "invalid.example",
        "resolved": False,
        "ip_address": None
    })

    assert len(result) == 1
    assert result[0]["severity"] == "MEDIUM"


def test_dns_success_generates_no_finding():
    result = network_audit.generate_network_findings({
        "domain": "google.com",
        "resolved": True,
        "ip_address": "142.250.66.14"
    })

    assert result == []
