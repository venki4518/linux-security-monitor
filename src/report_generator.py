import json
from datetime import datetime, timezone
from pathlib import Path


REPORT_DIRECTORY = Path(__file__).resolve().parent.parent / "reports"


def generate_report(system_data, user_data, audit_data, alert_engine):
    """Generate and save a JSON security monitoring report."""

    REPORT_DIRECTORY.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(timezone.utc)

    report = {
        "project": "Linux Security Monitoring System",
        "scan_timestamp": timestamp.isoformat(),
        "system": system_data,
        "audits": {
            "users": user_data,
            "other_audits": audit_data
        },
        "security_summary": alert_engine.get_summary(),
        "findings": alert_engine.findings
    }

    filename = (
        "security_report_"
        + timestamp.strftime("%Y%m%d_%H%M%S")
        + ".json"
    )

    report_path = REPORT_DIRECTORY / filename

    with report_path.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=4)

    print("\nJSON SECURITY REPORT GENERATED")
    print(f"Report location: {report_path}")

    return report_path
