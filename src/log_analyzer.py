from pathlib import Path
from collections import Counter
import re


AUTH_LOG = Path("/var/log/auth.log")


def read_auth_logs():
    """Read authentication logs safely."""

    try:
        return AUTH_LOG.read_text(
            encoding="utf-8",
            errors="replace"
        ).splitlines()

    except (PermissionError, FileNotFoundError) as error:
        print(f"Unable to read authentication log: {error}")
        return []


def analyze_logs(entries):
    """Identify authentication and sudo events."""

    results = {
        "failed_password": [],
        "authentication_failure": [],
        "invalid_user": [],
        "sudo_sessions": []
    }

    for line in entries:

        lower_line = line.lower()

        # Ignore grep commands recorded in the log
        if "command=/usr/bin/grep" in lower_line:
            continue

        if "failed password" in lower_line:
            results["failed_password"].append(line)

        if "authentication failure" in lower_line:
            results["authentication_failure"].append(line)

        if "invalid user" in lower_line:
            results["invalid_user"].append(line)

        if (
            "pam_unix(sudo:session): session opened" in lower_line
        ):
            results["sudo_sessions"].append(line)

    return results


def extract_ip_addresses(events):
    """Extract IPv4 addresses from event messages."""

    ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"

    addresses = []

    for event in events:
        matches = re.findall(ip_pattern, event)
        addresses.extend(matches)

    return Counter(addresses)


def display_report(results):

    print("\nAUTHENTICATION SECURITY REPORT")
    print("=" * 50)

    print(f"Failed passwords       : {len(results['failed_password'])}")
    print(
        f"Authentication failures: "
        f"{len(results['authentication_failure'])}"
    )
    print(f"Invalid user attempts  : {len(results['invalid_user'])}")
    print(f"Successful sudo sessions: {len(results['sudo_sessions'])}")

    failures = (
        results["failed_password"]
        + results["authentication_failure"]
        + results["invalid_user"]
    )

    print("\nSECURITY ASSESSMENT")
    print("-" * 50)

    if len(failures) >= 10:
        print("HIGH: Multiple authentication failures detected.")

    elif len(failures) >= 5:
        print("MEDIUM: Repeated authentication failures detected.")

    elif failures:
        print("LOW: Authentication failures detected.")

    else:
        print("No matching authentication failures detected.")

    if failures:
        print("\nSOURCE IP ADDRESS COUNTS")

        ip_counts = extract_ip_addresses(failures)

        if ip_counts:
            for ip, count in ip_counts.items():
                print(f"{ip}: {count} event(s)")
        else:
            print("No IPv4 addresses found in matching events.")

    print("\nNote: Findings require investigation before classifying an attack.")


def run_log_analysis():

    print("=" * 50)
    print("       LINUX AUTHENTICATION LOG ANALYZER")
    print("=" * 50)

    entries = read_auth_logs()

    if not entries:
        print("No log entries available.")
        return

    print(f"Total log entries read: {len(entries)}")

    results = analyze_logs(entries)

    display_report(results)

    print("\nLOG ANALYSIS COMPLETED")


if __name__ == "__main__":
    run_log_analysis()
