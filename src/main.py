
from src.system_audit import run_system_audit
from src.user_audit import run_user_audit
from src.log_analyzer import run_log_analysis
from src.permission_audit import run_permission_audit
from src.service_audit import run_service_audit
from src.network_audit import run_network_audit

from src.alert_engine import AlertEngine
from src.report_generator import generate_report


def main():

    alert_engine = AlertEngine()

    print("=" * 65)
    print("       LINUX SECURITY MONITORING SYSTEM")
    print("=" * 65)

    print("\n[1] SYSTEM AUDIT")
    system_data = run_system_audit()

    print("\n[2] USER SECURITY AUDIT")
    user_data = run_user_audit()

    if user_data["findings"]:
        alert_engine.add_findings(user_data["findings"])

    print("\n[3] AUTHENTICATION LOG ANALYSIS")
    log_data = run_log_analysis()

    if log_data["findings"]:
        alert_engine.add_findings(log_data["findings"])

    print("\n[4] FILE PERMISSION AUDIT")
    permission_data = run_permission_audit()

    if permission_data["findings"]:
        alert_engine.add_findings(permission_data["findings"])

    print("\n[5] SERVICE AUDIT")
    service_data = run_service_audit()

    if service_data["findings"]:
        alert_engine.add_findings(service_data["findings"])

    print("\n[6] NETWORK AUDIT")
    network_data = run_network_audit()

    if network_data["findings"]:
        alert_engine.add_findings(network_data["findings"])

    print("\n[7] SECURITY ALERT SUMMARY")
    alert_engine.display_findings()

    print("\nALERT SUMMARY")
    print(alert_engine.get_summary())

    audit_data = {
        "authentication_logs": log_data,
        "permissions": permission_data,
        "services": service_data,
        "network": network_data
    }

    report_path = generate_report(
        system_data,
        user_data,
        audit_data,
        alert_engine
    )

    print("\n" + "=" * 65)
    print("       SECURITY MONITORING COMPLETED")
    print("=" * 65)

    return report_path


if __name__ == "__main__":
    main()
