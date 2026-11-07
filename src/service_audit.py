import subprocess


def run_command(command):
    """Execute a Linux command safely."""

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False
        )

        if result.returncode != 0:
            print(f"Command returned code: {result.returncode}")
            if result.stderr:
                print(result.stderr.strip())

        return result.stdout

    except FileNotFoundError:
        print(f"Command not found: {command[0]}")
        return ""


def get_running_services():
    output = run_command([
        "systemctl", "list-units",
        "--type=service", "--state=running",
        "--no-legend", "--no-pager"
    ])

    return [
        line.strip()
        for line in output.splitlines()
        if line.strip() and line.split()[0].endswith(".service")
    ]


def get_failed_services():
    output = run_command([
        "systemctl", "--failed",
        "--no-legend", "--no-pager"
    ])

    return [
        line.strip()
        for line in output.splitlines()
        if line.strip() and line.split()[0].endswith(".service")
    ]


def get_enabled_services():
    output = run_command([
        "systemctl", "list-unit-files",
        "--type=service", "--state=enabled",
        "--no-legend", "--no-pager"
    ])

    return [
        line.strip()
        for line in output.splitlines()
        if line.strip() and line.split()[0].endswith(".service")
    ]


def generate_service_findings(failed):
    """Convert failed services into structured findings."""

    findings = []

    for service in failed:
        service_name = service.split()[0]

        findings.append({
            "title": "Failed system service detected",
            "description": (
                f"The service {service_name} is in a failed state. "
                "Investigate its logs and determine the cause."
            ),
            "severity": "MEDIUM",
            "category": "Service Monitoring"
        })

    return findings


def run_service_audit():
    """Run service audit and return evidence and findings."""

    print("=" * 55)
    print("          LINUX SERVICE SECURITY AUDIT")
    print("=" * 55)

    running = get_running_services()
    failed = get_failed_services()
    enabled = get_enabled_services()

    print(f"\nRunning services : {len(running)}")
    print(f"Failed services  : {len(failed)}")
    print(f"Enabled services : {len(enabled)}")

    print("\nRUNNING SERVICES")
    print("-" * 55)

    for service in running:
        print(service)

    print("\nFAILED SERVICES")
    print("-" * 55)

    if failed:
        for service in failed:
            print(f"INVESTIGATE: {service}")
    else:
        print("No failed services detected.")

    findings = generate_service_findings(failed)

    print(f"\nService security findings generated: {len(findings)}")
    print("\nSERVICE AUDIT COMPLETED")

    return {
        "running_services_count": len(running),
        "running_services": running,
        "failed_services_count": len(failed),
        "failed_services": failed,
        "enabled_services_count": len(enabled),
        "enabled_services": enabled,
        "findings": findings
    }


if __name__ == "__main__":
    run_service_audit()
