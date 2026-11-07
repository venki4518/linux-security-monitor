from types import SimpleNamespace

from src import user_audit


def test_get_user_accounts(monkeypatch):
    fake_users = [
        SimpleNamespace(
            pw_name="root",
            pw_uid=0,
            pw_gid=0,
            pw_dir="/root",
            pw_shell="/bin/bash"
        ),
        SimpleNamespace(
            pw_name="venkatesh",
            pw_uid=1000,
            pw_gid=1000,
            pw_dir="/home/venkatesh",
            pw_shell="/bin/bash"
        )
    ]

    monkeypatch.setattr(
        user_audit.pwd,
        "getpwall",
        lambda: fake_users
    )

    accounts = user_audit.get_user_accounts()

    assert len(accounts) == 2
    assert accounts[0]["username"] == "root"
    assert accounts[0]["uid"] == 0
    assert accounts[1]["username"] == "venkatesh"
    assert accounts[1]["uid"] == 1000


def test_check_admin_users(monkeypatch, tmp_path):
    group_file = tmp_path / "group"
    group_file.write_text(
        "root:x:0:\n"
        "sudo:x:27:venkatesh,admin\n"
    )

    monkeypatch.setattr(
        user_audit,
        "Path",
        lambda _: group_file
    )

    admin_users = user_audit.check_admin_users()

    assert admin_users == ["venkatesh", "admin"]


def test_check_admin_users_empty(monkeypatch, tmp_path):
    group_file = tmp_path / "group"
    group_file.write_text("sudo:x:27:\n")

    monkeypatch.setattr(
        user_audit,
        "Path",
        lambda _: group_file
    )

    assert user_audit.check_admin_users() == []


def test_check_admin_users_permission_error(monkeypatch):
    class FakePath:
        def __init__(self, path):
            pass

        def read_text(self):
            raise PermissionError

    monkeypatch.setattr(
        user_audit,
        "Path",
        FakePath
    )

    assert user_audit.check_admin_users() == []


def test_unexpected_root_account_generates_high_finding():
    accounts = [
        {"username": "root", "uid": 0},
        {"username": "attacker", "uid": 0}
    ]

    findings = user_audit.generate_user_findings(
        accounts,
        []
    )

    assert len(findings) == 1
    assert findings[0]["severity"] == "HIGH"
    assert "attacker" in findings[0]["description"]


def test_sudo_members_generate_low_finding():
    findings = user_audit.generate_user_findings(
        [{"username": "root", "uid": 0}],
        ["venkatesh"]
    )

    assert len(findings) == 1
    assert findings[0]["severity"] == "LOW"
    assert "venkatesh" in findings[0]["description"]


def test_normal_accounts_generate_no_findings():
    accounts = [
        {"username": "root", "uid": 0},
        {"username": "venkatesh", "uid": 1000}
    ]

    findings = user_audit.generate_user_findings(
        accounts,
        []
    )

    assert findings == []


def test_run_user_audit_returns_expected_fields(monkeypatch):
    fake_accounts = [
        {
            "username": "root",
            "uid": 0,
            "gid": 0,
            "home": "/root",
            "shell": "/bin/bash"
        },
        {
            "username": "venkatesh",
            "uid": 1000,
            "gid": 1000,
            "home": "/home/venkatesh",
            "shell": "/bin/bash"
        }
    ]

    monkeypatch.setattr(
        user_audit,
        "get_user_accounts",
        lambda: fake_accounts
    )

    monkeypatch.setattr(
        user_audit,
        "check_admin_users",
        lambda: ["venkatesh"]
    )

    result = user_audit.run_user_audit()

    assert result["total_accounts"] == 2
    assert result["accounts"] == fake_accounts
    assert result["sudo_group_members"] == ["venkatesh"]
    assert len(result["findings"]) == 1
