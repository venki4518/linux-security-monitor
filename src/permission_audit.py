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


def run_permission_audit():

    print("=" * 55)
    print("         LINUX FILE PERMISSION AUDIT")
    print("=" * 55)

    findings = []

    for path in TARGET_DIRECTORIES:

        result = check_permissions(path)

        if result is None:
            continue

        print(f"\nPath: {result['path']}")
        print(f"Permissions: {result['permissions']}")

        if result["world_writable"]:

            if result["is_directory"] and result["sticky_bit"]:
                print("Assessment: World-writable with sticky bit.")
            else:
                print("Assessment: World-writable; investigate.")

                findings.append(result)

        else:
            print("Assessment: Not world-writable.")

    print("\nPERMISSION AUDIT SUMMARY")
    print("-" * 55)
    print(f"Directories inspected: {len(TARGET_DIRECTORIES)}")
    print(f"Potential findings: {len(findings)}")

    print("\nPERMISSION AUDIT COMPLETED")


if __name__ == "__main__":
    run_permission_audit()
