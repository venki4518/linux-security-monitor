from pathlib import Path
import stat


TARGET_DIRECTORIES = [
    Path("/etc"),
    Path("/etc/ssh"),
    Path("/var/log"),
    Path("/tmp")
]


def check_permissions(path):

    try:
        details = path.stat()

        permissions = stat.S_IMODE(details.st_mode)

        is_directory = stat.S_ISDIR(details.st_mode)
        is_world_writable = bool(permissions & stat.S_IWOTH)
        has_sticky_bit = bool(details.st_mode & stat.S_ISVTX)

        return {
            "path": str(path),
            "permissions": oct(permissions),
            "is_directory": is_directory,
            "world_writable": is_world_writable,
            "sticky_bit": has_sticky_bit
        }

    except OSError as error:
        print(f"Unable to inspect {path}: {error}")
        return None


def generate_permission_findings(results):
    """Convert permission audit results into security findings."""

    findings = []

    for result in results:

        if (
            result["world_writable"]
            and not (
                result["is_directory"]
                and result["sticky_bit"]
            )
        ):
            findings.append({
                "title": "World-writable directory detected",
                "description": (
                    f"{result['path']} has permissions "
                    f"{result['permissions']}. "
                    "Investigate whether unrestricted write access is required."
                ),
                "severity": "HIGH",
                "category": "File Permissions"
            })

    return findings


def run_permission_audit():
    """Run permission audit and return evidence and findings."""

    print("=" * 55)
    print("         LINUX FILE PERMISSION AUDIT")
    print("=" * 55)

    results = []

    for path in TARGET_DIRECTORIES:

        result = check_permissions(path)

        if result is None:
            continue

        results.append(result)

        print(f"\nPath: {result['path']}")
        print(f"Permissions: {result['permissions']}")

        if result["world_writable"]:

            if result["is_directory"] and result["sticky_bit"]:
                assessment = "World-writable with sticky bit."
            else:
                assessment = "World-writable; investigate."

        else:
            assessment = "Not world-writable."

        result["assessment"] = assessment

        print(f"Assessment: {assessment}")

    findings = generate_permission_findings(results)

    print("\nPERMISSION AUDIT SUMMARY")
    print("-" * 55)
    print(f"Directories inspected: {len(results)}")
    print(f"Potential findings: {len(findings)}")

    print("\nPERMISSION AUDIT COMPLETED")

    return {
        "directories_inspected": len(results),
        "directory_details": results,
        "findings": findings
    }


if __name__ == "__main__":
    run_permission_audit()
