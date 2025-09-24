import os
import sqlite3
from datetime import datetime

# Use env var if provided; otherwise local file
DB = os.getenv("TTT_DB_PATH", "ttt_inventory.db")


def _audit(action: str, comment: str = "", user: str = "admin_tools"):
    """Write a row to logs if the table exists."""
    try:
        conn = sqlite3.connect(DB)
        cur = conn.cursor()
        # Ensure logs table exists; if not, skip silently
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='logs'")
        if not cur.fetchone():
            conn.close()
            return
        ts = datetime.now().isoformat(timespec="seconds")
        # logs schema expected: timestamp,user,sku,hub,action,qty,comment
        cur.execute(
            "INSERT INTO logs (timestamp,user,sku,hub,action,qty,comment) VALUES (?,?,?,?,?,?,?)",
            (ts, user, None, None, action, None, comment),
        )
        conn.commit()
        conn.close()
    except Exception:
        # Don't crash admin tool if logging fails
        pass


def _hash_password(new_password: str) -> str:
    """Prefer bcrypt; fallback to sha256 for legacy compatibility."""
    try:
        import bcrypt
        return bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()
    except Exception:
        import hashlib
        return hashlib.sha256(new_password.encode()).hexdigest()


def show_users():
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute("SELECT username, role, hub FROM users")
    rows = cur.fetchall()
    conn.close()
    print("\n👥 Current Users:")
    for r in rows:
        print(f" - {r[0]} ({r[1]}) — {r[2]}")
    print()


def delete_user(username):
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute("DELETE FROM users WHERE username = ?", (username,))
    conn.commit()
    conn.close()
    print(f"✅ Deleted user: {username}\n")


def reset_user_password(username, new_password):
    hashed = _hash_password(new_password)
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute("UPDATE users SET password = ? WHERE username = ?", (hashed, username))
    conn.commit()
    conn.close()
    print(f"🔐 Password reset for user: {username}")


if __name__ == "__main__":
    import argparse, getpass

    print("== TTT Admin Tools ==")
    parser = argparse.ArgumentParser(description="User admin for KISSInventory")
    parser.add_argument(
        "--db",
        default=os.getenv("TTT_DB_PATH", "ttt_inventory.db"),
        help="Path to SQLite DB",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list", help="List users")

    pdel = sub.add_parser("delete", help="Delete a user")
    pdel.add_argument("username")

    preset = sub.add_parser("reset", help="Reset a user's password")
    preset.add_argument("username")
    preset.add_argument("--password", help="New password (if omitted, prompt securely)")

    args = parser.parse_args()

    # Reassign DB path dynamically (no 'global' needed)
    DB = args.db

    if args.cmd == "list":
        show_users()
        _audit("admin_list_users")
    elif args.cmd == "delete":
        delete_user(args.username)
        _audit("admin_delete_user", comment=f"deleted={args.username}")
    elif args.cmd == "reset":
        pw = args.password or getpass.getpass("Enter new password: ")
        reset_user_password(args.username, pw)
        _audit("admin_reset_password", comment=f"username={args.username}")
