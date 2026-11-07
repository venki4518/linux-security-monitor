
from types import SimpleNamespace

from src import system_audit


def test_get_os_info(monkeypatch, tmp_path):
    os_file = tmp_path / "os-release"
    os_file.write_text('PRETTY_NAME="Ubuntu Test Edition"\n')

    monkeypatch.setattr(
        system_audit,
        "Path",
        lambda path: os_file if path == "/etc/os-release" else tmp_path / path
    )

    result = system_audit.get_os_info()

    assert result == "Ubuntu Test Edition"


def test_get_uptime(monkeypatch, tmp_path):
    uptime_file = tmp_path / "uptime"
    uptime_file.write_text("3665.00 1000.00")

    monkeypatch.setattr(
        system_audit,
        "Path",
        lambda path: uptime_file
    )

    result = system_audit.get_uptime()

    assert result == "1 hours, 1 minutes"


def test_get_memory_info(monkeypatch, tmp_path):
    memory_file = tmp_path / "meminfo"

    memory_file.write_text(
        "MemTotal: 8192000 kB\n"
        "MemAvailable: 4096000 kB\n"
    )

    monkeypatch.setattr(
        system_audit,
        "Path",
        lambda path: memory_file
    )

    result = system_audit.get_memory_info()

    assert result["total_mb"] == 8000.0
    assert result["available_mb"] == 4000.0
    assert result["used_mb"] == 4000.0


def test_get_memory_info_missing_data(monkeypatch, tmp_path):
    memory_file = tmp_path / "meminfo"
    memory_file.write_text("SomeOtherField: 1000 kB\n")

    monkeypatch.setattr(
        system_audit,
        "Path",
        lambda path: memory_file
    )

    result = system_audit.get_memory_info()

    assert result is None


def test_run_system_audit_returns_expected_fields(monkeypatch):
    monkeypatch.setattr(
        system_audit, "get_os_info", lambda: "Ubuntu Test"
    )
    monkeypatch.setattr(
        system_audit.platform, "node", lambda: "test-host"
    )
    monkeypatch.setattr(
        system_audit.getpass, "getuser", lambda: "test-user"
    )
    monkeypatch.setattr(
        system_audit.platform, "release", lambda: "test-kernel"
    )
    monkeypatch.setattr(
        system_audit.platform, "machine", lambda: "x86_64"
    )
    monkeypatch.setattr(
        system_audit, "get_uptime", lambda: "2 hours, 30 minutes"
    )
    monkeypatch.setattr(
        system_audit.shutil,
        "disk_usage",
        lambda path: SimpleNamespace(
            total=100 * 1024**3,
            used=40 * 1024**3,
            free=60 * 1024**3
        )
    )
    monkeypatch.setattr(
        system_audit, "get_memory_info", lambda: {
            "total_mb": 8000.0,
            "used_mb": 4000.0,
            "available_mb": 4000.0
        }
    )

    result = system_audit.run_system_audit()

    assert result["operating_system"] == "Ubuntu Test"
    assert result["hostname"] == "test-host"
    assert result["current_user"] == "test-user"
    assert result["kernel_version"] == "test-kernel"
    assert result["architecture"] == "x86_64"
    assert result["disk"]["total_gb"] == 100.0
    assert result["disk"]["used_gb"] == 40.0
    assert result["disk"]["free_gb"] == 60.0
    assert result["memory"]["total_mb"] == 8000.0


def test_run_system_audit_handles_missing_memory(monkeypatch):
    monkeypatch.setattr(
        system_audit, "get_os_info", lambda: "Ubuntu Test"
    )
    monkeypatch.setattr(
        system_audit.platform, "node", lambda: "test-host"
    )
    monkeypatch.setattr(
        system_audit.getpass, "getuser", lambda: "test-user"
    )
    monkeypatch.setattr(
        system_audit.platform, "release", lambda: "test-kernel"
    )
    monkeypatch.setattr(
        system_audit.platform, "machine", lambda: "x86_64"
    )
    monkeypatch.setattr(
        system_audit, "get_uptime", lambda: "1 hours, 0 minutes"
    )
    monkeypatch.setattr(
        system_audit.shutil,
        "disk_usage",
        lambda path: SimpleNamespace(
            total=100 * 1024**3,
            used=40 * 1024**3,
            free=60 * 1024**3
        )
    )
    monkeypatch.setattr(
        system_audit, "get_memory_info", lambda: None
    )

    result = system_audit.run_system_audit()

    assert result["memory"] is None
