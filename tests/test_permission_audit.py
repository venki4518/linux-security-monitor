
import stat

from src import permission_audit


def test_normal_directory(tmp_path):
    directory = tmp_path / "normal"
    directory.mkdir()
    directory.chmod(0o755)

    result = permission_audit.check_permissions(directory)

    assert result["permissions"] == "0o755"
    assert result["is_directory"] is True
    assert result["world_writable"] is False
    assert result["sticky_bit"] is False


def test_world_writable_directory(tmp_path):
    directory = tmp_path / "unsafe"
    directory.mkdir()
    directory.chmod(0o777)

    result = permission_audit.check_permissions(directory)

    assert result["world_writable"] is True
    assert result["sticky_bit"] is False


def test_sticky_bit_directory(tmp_path):
    directory = tmp_path / "temporary"
    directory.mkdir()
    directory.chmod(0o1777)

    result = permission_audit.check_permissions(directory)

    assert result["world_writable"] is True
    assert result["sticky_bit"] is True


def test_nonexistent_directory(tmp_path):
    directory = tmp_path / "does_not_exist"

    result = permission_audit.check_permissions(directory)

    assert result is None


def test_file_permissions_not_directory(tmp_path):
    file_path = tmp_path / "test.txt"
    file_path.write_text("test")
    file_path.chmod(0o666)

    result = permission_audit.check_permissions(file_path)

    assert result["is_directory"] is False
    assert result["world_writable"] is True


def test_check_permissions_permission_error(monkeypatch):
    class FakePath:
        def __str__(self):
            return "/restricted"

        def stat(self):
            raise PermissionError("Access denied")

    result = permission_audit.check_permissions(FakePath())

    assert result is None


def test_world_writable_directory_generates_high_finding():
    results = [
        {
            "path": "/example",
            "permissions": "0o777",
            "is_directory": True,
            "world_writable": True,
            "sticky_bit": False
        }
    ]

    findings = permission_audit.generate_permission_findings(results)

    assert len(findings) == 1
    assert findings[0]["severity"] == "HIGH"
    assert "/example" in findings[0]["description"]


def test_sticky_bit_directory_generates_no_finding():
    results = [
        {
            "path": "/tmp",
            "permissions": "0o1777",
            "is_directory": True,
            "world_writable": True,
            "sticky_bit": True
        }
    ]

    findings = permission_audit.generate_permission_findings(results)

    assert findings == []


def test_normal_directory_generates_no_finding():
    results = [
        {
            "path": "/etc",
            "permissions": "0o755",
            "is_directory": True,
            "world_writable": False,
            "sticky_bit": False
        }
    ]

    findings = permission_audit.generate_permission_findings(results)

    assert findings == []


def test_world_writable_file_generates_finding():
    results = [
        {
            "path": "/example/file.txt",
            "permissions": "0o666",
            "is_directory": False,
            "world_writable": True,
            "sticky_bit": False
        }
    ]

    findings = permission_audit.generate_permission_findings(results)

    assert len(findings) == 1
    assert findings[0]["severity"] == "HIGH"


def test_run_permission_audit_returns_expected_data(monkeypatch, tmp_path):
    safe_directory = tmp_path / "safe"
    safe_directory.mkdir()
    safe_directory.chmod(0o755)

    unsafe_directory = tmp_path / "unsafe"
    unsafe_directory.mkdir()
    unsafe_directory.chmod(0o777)

    monkeypatch.setattr(
        permission_audit,
        "TARGET_DIRECTORIES",
        [safe_directory, unsafe_directory]
    )

    result = permission_audit.run_permission_audit()

    assert result["directories_inspected"] == 2
    assert len(result["directory_details"]) == 2
    assert len(result["findings"]) == 1

    assert (
        result["directory_details"][0]["assessment"]
        == "Not world-writable."
    )

    assert (
        result["directory_details"][1]["assessment"]
        == "World-writable; investigate."
    )


def test_run_permission_audit_skips_inaccessible_path(monkeypatch):
    class FakePath:
        def __str__(self):
            return "/restricted"

        def stat(self):
            raise PermissionError("Access denied")

    monkeypatch.setattr(
        permission_audit,
        "TARGET_DIRECTORIES",
        [FakePath()]
    )

    result = permission_audit.run_permission_audit()

    assert result["directories_inspected"] == 0
    assert result["directory_details"] == []
    assert result["findings"] == []


def test_run_permission_audit_sticky_directory(monkeypatch, tmp_path):
    directory = tmp_path / "shared"
    directory.mkdir()
    directory.chmod(stat.S_ISVTX | 0o777)

    monkeypatch.setattr(
        permission_audit,
        "TARGET_DIRECTORIES",
        [directory]
    )

    result = permission_audit.run_permission_audit()

    assert result["directories_inspected"] == 1
    assert result["findings"] == []

    assert (
        result["directory_details"][0]["assessment"]
        == "World-writable with sticky bit."
    )
