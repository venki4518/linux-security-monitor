import platform
import getpass
import shutil
from pathlib import Path


def get_os_info():
    """Read Linux distribution information."""
    os_release = Path("/etc/os-release")

    if os_release.exists():
        for line in os_release.read_text().splitlines():
            if line.startswith("PRETTY_NAME="):
                return line.split("=", 1)[1].strip('"')

    return platform.system()


def get_uptime():
    """Get system uptime from Linux proc filesystem."""
    try:
        uptime_seconds = float(Path("/proc/uptime").read_text().split()[0])
        hours = int(uptime_seconds // 3600)
        minutes = int((uptime_seconds % 3600) // 60)
        return f"{hours} hours, {minutes} minutes"
    except (OSError, ValueError, IndexError):
        return "Unable to determine uptime"


def get_memory_info():
    """Read memory information from /proc/meminfo."""
    try:
        memory_data = Path("/proc/meminfo").read_text().splitlines()

        memory = {}
        for line in memory_data:
            key, value = line.split(":", 1)
            memory[key] = int(value.strip().split()[0])

        total = memory["MemTotal"]
        available = memory["MemAvailable"]
        used = total - available

        return {
            "total_mb": round(total / 1024, 2),
            "used_mb": round(used / 1024, 2),
            "available_mb": round(available / 1024, 2),
        }

    except (OSError, ValueError, KeyError, IndexError):
        return None


def run_system_audit():
    """Collect basic Linux system information."""

    print("=" * 50)
    print("       LINUX SYSTEM SECURITY AUDIT")
    print("=" * 50)

    print(f"Operating System : {get_os_info()}")
    print(f"Hostname         : {platform.node()}")
    print(f"Current User     : {getpass.getuser()}")
    print(f"Kernel Version   : {platform.release()}")
    print(f"Architecture     : {platform.machine()}")
    print(f"System Uptime    : {get_uptime()}")

    disk = shutil.disk_usage("/")

    print("\nDISK INFORMATION")
    print("-" * 50)
    print(f"Total Disk       : {disk.total / (1024**3):.2f} GB")
    print(f"Used Disk        : {disk.used / (1024**3):.2f} GB")
    print(f"Free Disk        : {disk.free / (1024**3):.2f} GB")

    memory = get_memory_info()

    print("\nMEMORY INFORMATION")
    print("-" * 50)

    if memory:
        print(f"Total Memory     : {memory['total_mb']} MB")
        print(f"Used Memory      : {memory['used_mb']} MB")
        print(f"Available Memory : {memory['available_mb']} MB")
    else:
        print("Memory information unavailable.")

    print("\n" + "=" * 50)
    print("SYSTEM AUDIT COMPLETED")
    print("=" * 50)


if __name__ == "__main__":
    run_system_audit()
