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

        return result.stdout

    except FileNotFoundError:
        print(f"Command not found: {command[0]}")
        return ""


def get_running_services():
    """Retrieve currently running services."""

    output = run_command([
        "systemctl",
        "list-units",
        "--type=service",
        "--state=running",
        "--no-legend",
        "--no-pager"
    ])

    return [line.strip() for line in output.splitlines() if line.strip()]


def get_failed_services():
    """Retrieve failed systemd services."""

    output = run_command([
        "systemctl",
        "--failed",
        "--no-legend",
        "--no-pager"
    ])

    return [line.strip() for line in output.splitlines() if line.strip()]


def get_enabled_services():
    """Retrieve enabled service definitions."""

    output = run_command([
        "systemctl",
        "list-unit-files",
        "--type=service",
        "--state=enabled",
        "--no-legend",
        "--no-pager"
    ])

    return [line.strip() for line in output.splitlines() if line.strip()]


def run_service_audit():

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

    print("\nSERVICE AUDIT COMPLETED")


if __name__ == "__main__":
    run_service_audit()
