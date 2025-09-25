import os
import sqlite3
from datetime import datetime

DB = os.getenv("TTT_DB_PATH", "ttt_inventory.db")

def _audit(action: str, comment: str = "", user: str = "admin_tools"):
    try:
        conn = sqlite3.connect(DB); cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='logs'")
        if not cur.fetchone(): conn.close(); return
        ts = datetime.now().isoformat(timespec="seconds")
        cur.execute(
            "INSERT INTO logs (timestamp,user,sku,hub,action,qty,comment) VALUES (?,?,?,?,?,?,?)",
            (ts, user, None, None, action, None, comment),
        )
        conn.commit(); conn.close()
    except Exception:
        pass

def _hash_password(pw: str) -> str:
    try:
        import bcrypt
        return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()
    except Exception:
        import hashlib
        return hashlib.sha256(pw.encode()).hexdigest()

def show_users():
    conn = sqlite3.connect(DB); cur = conn.cursor()
    cur.execute("SELECT username, role, hub FROM users")
    rows = cur.fetchall(); conn.close()
    print("\n👥 Current Users:")
    for u,r,h in rows: print(f" - {u} ({r}) — {h}")
    print()

def delete_user(username: str):
    conn = sqlite3.connect(DB); cur = conn.cursor()
    cur.execute("DELETE FROM users WHERE username = ?", (username,))
    conn.commit(); conn.close()
    print(f"✅ Deleted user: {username}\n")

def reset_user_password(username: str, new_password: str):
    hashed = _hash_password(new_password)
    conn = sqlite3.connect(DB); cur = conn.cursor()
    cur.execute("UPDATE users SET password = ? WHERE username = ?", (hashed, username))
    conn.commit(); conn.close()
    print(f"🔐 Password reset for user: {username}")

from typing import Optional

def create_user(username: str, password: str, role: str, hub: Optional[str] = None):
    """Create a new user account."""
    hashed = _hash_password(password)
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute("CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password TEXT, role TEXT, hub TEXT)")
    try:
        cur.execute("INSERT INTO users (username,password,role,hub) VALUES (?,?,?,?)",
                    (username, hashed, role, hub))
        conn.commit()
        print(f"✅ Created user: {username} ({role}) — {hub or ''}")
    except sqlite3.IntegrityError:
        print(f"⚠️ User already exists: {username}")
    finally:
        conn.close()


if __name__ == "__main__":
    import argparse, getpass
    print("== TTT Admin Tools ==")
    parser = argparse.ArgumentParser(description="User admin for KISSInventory")
    parser.add_argument("--db", default=os.getenv("TTT_DB_PATH","ttt_inventory.db"), help="Path to SQLite DB")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list", help="List users")

    pdel = sub.add_parser("delete", help="Delete a user")
    pdel.add_argument("username")

    preset = sub.add_parser("reset", help="Reset a user's password")
    preset.add_argument("username")
    preset.add_argument("--password", help="New password (if omitted, prompt securely)")

    pcreate = sub.add_parser("create", help="Create a new user")
    pcreate.add_argument("username")
    pcreate.add_argument("password")
    pcreate.add_argument("role")
    pcreate.add_argument("--hub", default=None)

    args = parser.parse_args()
    DB = args.db  # no global needed

    if args.cmd == "list":
        show_users(); _audit("admin_list_users")
    elif args.cmd == "delete":
        delete_user(args.username); _audit("admin_delete_user", comment=f"deleted={args.username}")
    elif args.cmd == "reset":
        pw = args.password or getpass.getpass("Enter new password: ")
        reset_user_password(args.username, pw); _audit("admin_reset_password", comment=f"username={args.username}")
    elif args.cmd == "create":
        create_user(args.username, args.password, args.role, args.hub)
        _audit("admin_create_user", comment=f"username={args.username}|role={args.role}|hub={args.hub}")
