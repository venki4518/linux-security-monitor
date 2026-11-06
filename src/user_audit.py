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

    for line in sudo_group_file.read_text().splitlines():
        if line.startswith("sudo:"):
            members = line.split(":")[3]
            admin_users = members.split(",") if members else []

    return admin_users


def run_user_audit():

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

    print("\nUSER ACCOUNT AUDIT COMPLETED")


if __name__ == "__main__":
    run_user_audit()
