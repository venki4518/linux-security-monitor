
from src import main as main_module


def test_main_runs_all_audits(monkeypatch):
    calls = []

    system_data = {"hostname": "test-machine"}
    user_data = {"findings": []}
    log_data = {"findings": []}
    permission_data = {"findings": []}
    service_data = {"findings": []}
    network_data = {"findings": []}

    monkeypatch.setattr(
        main_module,
        "run_system_audit",
        lambda: calls.append("system") or system_data
    )

    monkeypatch.setattr(
        main_module,
        "run_user_audit",
        lambda: calls.append("users") or user_data
    )

    monkeypatch.setattr(
        main_module,
        "run_log_analysis",
        lambda: calls.append("logs") or log_data
    )

    monkeypatch.setattr(
        main_module,
        "run_permission_audit",
        lambda: calls.append("permissions") or permission_data
    )

    monkeypatch.setattr(
        main_module,
        "run_service_audit",
        lambda: calls.append("services") or service_data
    )

    monkeypatch.setattr(
        main_module,
        "run_network_audit",
        lambda: calls.append("network") or network_data
    )

    report_calls = []

    monkeypatch.setattr(
        main_module,
        "generate_report",
        lambda *args: report_calls.append(args)
    )

    monkeypatch.setattr(
        main_module.AlertEngine,
        "display_findings",
        lambda self: None
    )

    main_module.main()

    assert calls == [
        "system",
        "users",
        "logs",
        "permissions",
        "services",
        "network"
    ]

    assert len(report_calls) == 1


def test_main_passes_all_audit_data_to_report(monkeypatch):
    system_data = {"hostname": "test-machine"}
    user_data = {"findings": []}
    log_data = {"findings": []}
    permission_data = {"findings": []}
    service_data = {"findings": []}
    network_data = {"findings": []}

    monkeypatch.setattr(
        main_module,
        "run_system_audit",
        lambda: system_data
    )

    monkeypatch.setattr(
        main_module,
        "run_user_audit",
        lambda: user_data
    )

    monkeypatch.setattr(
        main_module,
        "run_log_analysis",
        lambda: log_data
    )

    monkeypatch.setattr(
        main_module,
        "run_permission_audit",
        lambda: permission_data
    )

    monkeypatch.setattr(
        main_module,
        "run_service_audit",
        lambda: service_data
    )

    monkeypatch.setattr(
        main_module,
        "run_network_audit",
        lambda: network_data
    )

    report_calls = []

    monkeypatch.setattr(
        main_module,
        "generate_report",
        lambda *args: report_calls.append(args)
    )

    monkeypatch.setattr(
        main_module.AlertEngine,
        "display_findings",
        lambda self: None
    )

    main_module.main()

    assert len(report_calls) == 1

    received_system, received_users, received_audits, received_engine = (
        report_calls[0]
    )

    assert received_system == system_data
    assert received_users == user_data

    assert received_audits["authentication_logs"] == log_data
    assert received_audits["permissions"] == permission_data
    assert received_audits["services"] == service_data
    assert received_audits["network"] == network_data


def test_main_collects_findings_from_all_audits(monkeypatch):
    findings = [
        {
            "title": "Test finding",
            "description": "Test security issue",
            "severity": "HIGH",
            "category": "Test"
        }
    ]

    monkeypatch.setattr(
        main_module,
        "run_system_audit",
        lambda: {}
    )

    monkeypatch.setattr(
        main_module,
        "run_user_audit",
        lambda: {"findings": findings}
    )

    monkeypatch.setattr(
        main_module,
        "run_log_analysis",
        lambda: {"findings": findings}
    )

    monkeypatch.setattr(
        main_module,
        "run_permission_audit",
        lambda: {"findings": findings}
    )

    monkeypatch.setattr(
        main_module,
        "run_service_audit",
        lambda: {"findings": findings}
    )

    monkeypatch.setattr(
        main_module,
        "run_network_audit",
        lambda: {"findings": findings}
    )

    report_calls = []

    monkeypatch.setattr(
        main_module,
        "generate_report",
        lambda *args: report_calls.append(args)
    )

    monkeypatch.setattr(
        main_module.AlertEngine,
        "display_findings",
        lambda self: None
    )

    main_module.main()

    received_engine = report_calls[0][3]

    assert received_engine.get_summary()["total"] == 5
    assert received_engine.get_summary()["high"] == 5
