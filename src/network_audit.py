
import subprocess
import socket


def run_command(command):
    """Execute a Linux command safely and return its output."""
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
            timeout=10
        )

        if result.returncode != 0:
            return ""

        return result.stdout.strip()

    except (subprocess.TimeoutExpired, FileNotFoundError):
        return ""


def get_listening_ports():
    """Collect TCP and UDP listening sockets."""
    return run_command(["ss", "-tuln"])


def get_process_details():
    """Collect listening sockets with process information."""
    return run_command(["sudo", "ss", "-tulnp"])


def get_network_interfaces():
    """Collect network interface configuration."""
    return run_command(["ip", "addr"])


def get_routing_table():
    """Collect the Linux routing table."""
    return run_command(["ip", "route"])


def check_dns(domain="google.com"):
    """Check whether a domain can be resolved."""
    try:
        ip_address = socket.gethostbyname(domain)

        return {
            "domain": domain,
            "resolved": True,
            "ip_address": ip_address
        }

    except socket.gaierror:
        return {
            "domain": domain,
            "resolved": False,
            "ip_address": None
        }


def generate_network_findings(dns_result):
    """Generate a finding when DNS resolution fails."""
    findings = []

    if not dns_result["resolved"]:
        findings.append({
            "title": "DNS resolution failure",
            "description": (
                f"Unable to resolve {dns_result['domain']}. "
                "Investigate DNS configuration and network connectivity."
            ),
            "severity": "MEDIUM",
            "category": "Network"
        })

    return findings


def run_network_audit():
    """Run network checks and return structured audit evidence."""

    print("\n========== NETWORK SECURITY AUDIT ==========")

    listening_ports = get_listening_ports()
    process_details = get_process_details()
    interfaces = get_network_interfaces()
    routing_table = get_routing_table()
    dns_result = check_dns()

    findings = generate_network_findings(dns_result)

    print("\nLISTENING PORTS:")
    print(listening_ports or "Unable to retrieve listening ports.")

    print("\nPROCESS DETAILS:")
    print(process_details or "Process details unavailable.")

    print("\nNETWORK INTERFACES:")
    print(interfaces or "Unable to retrieve interfaces.")

    print("\nROUTING TABLE:")
    print(routing_table or "Unable to retrieve routing table.")

    print("\nDNS CHECK:")
    if dns_result["resolved"]:
        print(f"{dns_result['domain']} resolved to {dns_result['ip_address']}")
    else:
        print(f"DNS resolution failed for {dns_result['domain']}.")

    print(f"\nNetwork findings: {len(findings)}")

    return {
        "listening_ports": listening_ports,
        "process_details": process_details,
        "network_interfaces": interfaces,
        "routing_table": routing_table,
        "dns_check": dns_result,
        "findings": findings
    }
