import subprocess
import socket


def run_command(command):
    """Run a Linux command and return its output."""
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False
        )

        if result.returncode != 0:
            print(f"Command error: {command[0]}")
            return ""

        return result.stdout

    except FileNotFoundError:
        print(f"Command not found: {command[0]}")
        return ""


def get_listening_ports():
    return run_command(["ss", "-tuln"])


def get_process_details():
    return run_command(["sudo", "ss", "-tulnp"])


def get_network_interfaces():
    return run_command(["ip", "addr"])


def get_routing_table():
    return run_command(["ip", "route"])


def check_dns(domain="google.com"):
    try:
        ip_address = socket.gethostbyname(domain)
        return ip_address
    except socket.gaierror:
        return None


def run_network_audit():

    print("=" * 60)
    print("             NETWORK SECURITY AUDIT")
    print("=" * 60)

    print("\nLISTENING PORTS")
    print("-" * 60)
    print(get_listening_ports())

    print("\nPROCESS DETAILS")
    print("-" * 60)
    print(get_process_details())

    print("\nNETWORK INTERFACES")
    print("-" * 60)
    print(get_network_interfaces())

    print("\nROUTING TABLE")
    print("-" * 60)
    print(get_routing_table())

    print("\nDNS CHECK")
    print("-" * 60)

    dns_result = check_dns()

    if dns_result:
        print(f"google.com resolved to: {dns_result}")
    else:
        print("DNS resolution failed. Investigate connectivity.")

    print("\nNETWORK AUDIT COMPLETED")


if __name__ == "__main__":
    run_network_audit()
