from datetime import datetime


class AlertEngine:
    """Creates and manages security findings."""

    def __init__(self):
        self.findings = []

    def add_finding(self, title, description, severity, category):

        severity = severity.upper()

        if severity not in ["LOW", "MEDIUM", "HIGH"]:
            raise ValueError("Invalid severity level")

        finding = {
            "timestamp": datetime.now().astimezone().isoformat(
                timespec="seconds"
            ),
            "title": title,
            "description": description,
            "severity": severity,
            "category": category
        }

        self.findings.append(finding)

    def add_findings(self, findings):
        """Add multiple structured findings."""

        for finding in findings:
            self.add_finding(
                title=finding["title"],
                description=finding["description"],
                severity=finding["severity"],
                category=finding["category"]
            )

    def display_findings(self):

        print("\n" + "=" * 65)
        print("                 SECURITY FINDINGS")
        print("=" * 65)

        if not self.findings:
            print("No security findings recorded.")
            return

        for number, finding in enumerate(self.findings, start=1):

            print(f"\nFinding #{number}")
            print(f"Title       : {finding['title']}")
            print(f"Description : {finding['description']}")
            print(f"Severity    : {finding['severity']}")
            print(f"Category    : {finding['category']}")
            print(f"Timestamp   : {finding['timestamp']}")

    def get_summary(self):

        return {
            "total": len(self.findings),
            "high": sum(
                f["severity"] == "HIGH" for f in self.findings
            ),
            "medium": sum(
                f["severity"] == "MEDIUM" for f in self.findings
            ),
            "low": sum(
                f["severity"] == "LOW" for f in self.findings
            )
        }
