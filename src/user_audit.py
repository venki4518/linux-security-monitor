from pathlib import Path
import pwd


def get_user_accounts():
    """Collect local Linux user account information."""

    accounts = []

    for user in pwd.getpwall():
        accounts.append({
            "username": user.pw_name,
            "uid": user.pw_uid,
            "gid": user.pw_gid,
            "home": user.pw_dir,
            "shell": user.pw_shell
        })

    return accounts


def check_admin_users():
    """Identify users listed in the sudo group."""

    sudo_group_file = Path("/etc/group")
    admin_users = []

    try:
        for line in sudo_group_file.read_text().splitlines():
            if line.startswith("sudo:"):
                members = line.split(":")[3]
                admin_users = members.split(",") if members else []

    except PermissionError:
        print("Unable to read sudo group information.")

    return admin_users


def generate_user_findings(accounts, admin_users):
    """Generate structured user security findings."""

    findings = []

    unexpected_root_accounts = [
        account for account in accounts
        if account["uid"] == 0 and account["username"] != "root"
    ]

    if unexpected_root_accounts:
        usernames = ", ".join(
            account["username"]
            for account in unexpected_root_accounts
        )

        findings.append({
            "title": "Additional UID 0 accounts detected",
            "description": (
                f"Accounts other than root have UID 0: {usernames}. "
                "Verify whether these privileged accounts are authorized."
            ),
            "severity": "HIGH",
            "category": "User Security"
        })

    if admin_users:
        findings.append({
            "title": "Sudo group membership review",
            "description": (
                "Users with sudo group membership: "
                + ", ".join(admin_users)
                + ". Verify that each user requires administrative access."
            ),
            "severity": "LOW",
            "category": "Access Management"
        })

    return findings


def run_user_audit():
    """Run user audit and return account information and findings."""

    print("=" * 50)
    print("         LINUX USER ACCOUNT AUDIT")
    print("=" * 50)

    accounts = get_user_accounts()

    print(f"\nTotal accounts found: {len(accounts)}")

    print("\nUSER ACCOUNT DETAILS")
    print("-" * 50)

    for account in accounts:
        print(
            f"Username: {account['username']:<15} "
            f"UID: {account['uid']:<6} "
            f"Shell: {account['shell']}"
        )

    admin_users = check_admin_users()

    print("\nSUDO GROUP MEMBERS")
    print("-" * 50)

    if admin_users:
        for username in admin_users:
            print(username)
    else:
        print("No members listed in sudo group.")

    findings = generate_user_findings(accounts, admin_users)

    print(f"\nUser security findings generated: {len(findings)}")
    print("\nUSER ACCOUNT AUDIT COMPLETED")

    return {
        "total_accounts": len(accounts),
        "accounts": accounts,
        "sudo_group_members": admin_users,
        "findings": findings
    }


if __name__ == "__main__":
    run_user_audit()
