import sqlite3

DB = "ttt_inventory.db"

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
    import hashlib
    hashed = hashlib.sha256(new_password.encode()).hexdigest()
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute("UPDATE users SET password = ? WHERE username = ?", (hashed, username))
    conn.commit()
    conn.close()
    print(f"🔐 Password reset for user: {username}")

if __name__ == "__main__":
    print("== TTT Admin Tools ==")
    show_users()

    # EXAMPLES — Uncomment to use:
    delete_user("vendor")
    # reset_user_password("smooth", "retailpass")
