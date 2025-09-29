# ===== app.py — KISS Inventory =====
import os
from pathlib import Path
import sqlite3
from datetime import datetime, date, timedelta, timezone
from typing import Optional, Dict, List, Tuple

import streamlit as st
import pandas as pd

try:
    from zoneinfo import ZoneInfo  # py3.9+ backport
except Exception:
    ZoneInfo = None

# --- Config: DB path (env var or local file)
DB = Path(os.getenv("TTT_DB_PATH", Path(__file__).parent / "ttt_inventory.db"))
DB.parent.mkdir(parents=True, exist_ok=True)  # ensure folder exists

APP_VERSION = "v1.4.0-starter-pack-5"

# --- Time helpers -------------------------------------------------------------
ET_TZ = ZoneInfo("America/New_York") if ZoneInfo else None

def fmt_ts_et(ts_str: Optional[str]) -> str:
    """Format an ISO-ish timestamp string into ET 12-hour, e.g., 'Fri Sep 26, 2025 - 11:11 AM ET'."""
    if not ts_str:
        return "—"
    try:
        # Parse a few common shapes
        s = ts_str.replace("Z", "")
        if "." in s:
            s = s.split(".")[0]
        dt = datetime.fromisoformat(s)
    except Exception:
        try:
            dt = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
        except Exception:
            return ts_str
    # Assume naive = local server time; convert to ET
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    if ET_TZ:
        dt = dt.astimezone(ET_TZ)
    return dt.strftime("%a %b %d, %Y - %I:%M %p ET").lstrip("0").replace(" 0", " ")

# --- DB helpers ---------------------------------------------------------------
def connect():
    con = sqlite3.connect(str(DB))
    try:
        con.execute("PRAGMA foreign_keys=ON")
        con.execute("PRAGMA journal_mode=WAL")
        con.execute("PRAGMA synchronous=NORMAL")
    except Exception:
        pass
    return con

def query(sql: str, params: Tuple = (), fetch: bool = True, commit: bool = False):
    con = connect()
    cur = con.cursor()
    cur.execute(sql, params)
    rows = cur.fetchall() if fetch else None
    if commit:
        con.commit()
    con.close()
    return rows

def execmany(sql: str, rows: List[Tuple]):
    con = connect()
    cur = con.cursor()
    cur.executemany(sql, rows)
    con.commit()
    con.close()

def _now_iso():
    return datetime.now().isoformat(timespec="seconds")

# --- Safety: backup the SQLite DB before destructive operations
def backup_db() -> Optional[Path]:
    try:
        db_path = Path(DB)
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        backup = db_path.with_name(f"{db_path.stem}-{ts}{db_path.suffix}")
        import shutil
        shutil.copy2(db_path, backup)
        return backup
    except Exception:
        return None

# ===== section 2: auth (bcrypt + legacy), users table, seeding ================
try:
    import bcrypt
except Exception:
    bcrypt = None

def hash_password(pw: str) -> str:
    if bcrypt:
        return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()
    import hashlib
    return hashlib.sha256(pw.encode()).hexdigest()

def verify_password(plain: str, stored: str) -> bool:
    if stored and stored.startswith("$2"):
        if not bcrypt:
            return False
        try:
            return bcrypt.checkpw(plain.encode(), stored.encode())
        except Exception:
            return False
    import re, hashlib
    if re.fullmatch(r"[0-9a-f]{64}", stored or ""):
        return hashlib.sha256(plain.encode()).hexdigest() == stored
    return False

def ensure_users_schema_and_seed():
    con = connect(); cur = con.cursor()
    cur.execute("""CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        password TEXT,
        role TEXT,
        hub TEXT
    )""")
    # MIGRATION: add 'disabled' if missing
    cols = [r[1] for r in cur.execute("PRAGMA table_info(users)").fetchall()]
    if "disabled" not in cols:
        cur.execute("ALTER TABLE users ADD COLUMN disabled INTEGER DEFAULT 0")
        cur.execute("UPDATE users SET disabled=0 WHERE disabled IS NULL")
    # seed if empty
    n = cur.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    if n == 0:
        seed = [
            ("kevin",   hash_password("adminpass"),  "Admin",       "HQ",    0),
            ("fox",     hash_password("foxpass"),    "Hub Manager", "Hub 2", 0),
            ("smooth",  hash_password("retailpass"), "Retail",      "Retail",0),
            ("carmen",  hash_password("hub3pass"),   "Hub Manager", "Hub 3", 0),
            ("slo",     hash_password("hub1pass"),   "Hub Manager", "Hub 1", 0),
            ("angie",   hash_password("shipit"),     "Supplier",    None,    0),
        ]
        cur.executemany("INSERT INTO users (username,password,role,hub,disabled) VALUES (?,?,?,?,?)", seed)
    con.commit(); con.close()

ensure_users_schema_and_seed()

def is_admin(role: str) -> bool:
    return (role or "").lower() == "admin"

def get_role(username: str) -> Optional[str]:
    r = query("SELECT role FROM users WHERE username=?", (username,))
    return (r[0][0] if r else None)

def login(username: str, password: str):
    rows = query("SELECT username, password, role, hub, disabled FROM users WHERE username=?", (username,))
    if not rows:
        return None
    uname, stored_hash, role, hub, disabled = rows[0]
    if disabled:
        return None
    if verify_password(password, stored_hash):
        if bcrypt and stored_hash and not stored_hash.startswith("$2"):
            try:
                new_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
                query("UPDATE users SET password=? WHERE username=?", (new_hash, username), fetch=False, commit=True)
            except Exception:
                pass
        try:
            ensure_logs_schema()
            query(
                "INSERT INTO logs (timestamp,user,sku,hub,action,qty,comment) VALUES (?,?,?,?,?,?,?)",
                (_now_iso(), uname, None, hub, "login", None, f"role={role}"),
                fetch=False, commit=True
            )
        except Exception:
            pass
        return (uname, role, hub)
    return None

def logout():
    for k in ("auth_user", "logged_in"):
        if k in st.session_state:
            del st.session_state[k]

def last_login_for(username: str) -> Optional[str]:
    try:
        row = query(
            "SELECT timestamp FROM logs WHERE user=? AND action='login' ORDER BY id DESC LIMIT 1",
            (username,)
        )
        return fmt_ts_et(row[0][0]) if row else None
    except Exception:
        return None

def login_form():
    st.subheader("Log in")
    u = st.text_input("Username")
    p = st.text_input("Password", type="password")
    if st.button("Sign in"):
        user = login(u.strip(), p)
        if user:
            st.session_state["auth_user"] = user
            st.session_state["logged_in"] = True
            st.rerun()
        else:
            st.error("Invalid credentials or user disabled")

# ===== section 3: messaging core =============================================
def ensure_messages_schema():
    con = connect(); cur = con.cursor()
    cur.execute("""CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        sender TEXT,
        recipient TEXT,
        subject TEXT,
        body TEXT,
        thread_id TEXT,
        msg_type TEXT,
        read_at TEXT,
        hub TEXT,
        shipped_count INTEGER,
        shipped_range_start TEXT,
        shipped_range_end TEXT,
        paid_count INTEGER,
        meta TEXT
    )""")
    have = [r[1] for r in cur.execute("PRAGMA table_info(messages)").fetchall()]
    required = {
        "recipient":"TEXT","subject":"TEXT","body":"TEXT",
        "thread_id":"TEXT","msg_type":"TEXT","read_at":"TEXT","hub":"TEXT",
        "shipped_count":"INTEGER","shipped_range_start":"TEXT","shipped_range_end":"TEXT",
        "paid_count":"INTEGER","meta":"TEXT"
    }
    for col, coltype in required.items():
        if col not in have:
            cur.execute(f"ALTER TABLE messages ADD COLUMN {col} {coltype}")
    con.commit(); con.close()

def unread_count(username: str) -> int:
    try:
        ensure_messages_schema()
        row = query("SELECT COUNT(*) FROM messages WHERE recipient=? AND read_at IS NULL", (username,))
        return int(row[0][0]) if row else 0
    except Exception:
        return 0

def _guard_message_send(sender: str, recipient: str) -> None:
    s_role = (get_role(sender) or "").lower()
    r_role = (get_role(recipient) or "").lower()
    if s_role != "admin" and r_role != "admin":
        raise ValueError("Only Admins (HQ) can be messaged by non-admin users.")

def send_message(sender: str, recipient: str, subject: str, body: str,
                 msg_type: str="message", thread_id: Optional[str]=None, hub: Optional[str]=None,
                 shipped_count: Optional[int]=None, range_start: Optional[str]=None, range_end: Optional[str]=None,
                 paid_count: Optional[int]=None, meta: Optional[str]=None):
    import uuid
    ensure_messages_schema()
    _guard_message_send(sender, recipient)
    if not thread_id:
        thread_id = str(uuid.uuid4())
    query("""INSERT INTO messages (timestamp,sender,recipient,subject,body,thread_id,msg_type,read_at,hub,
                                   shipped_count,shipped_range_start,shipped_range_end,paid_count,meta)
             VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
          (_now_iso(), sender, recipient, subject, body, thread_id, msg_type, None, hub,
           shipped_count, range_start, range_end, paid_count, meta),
          fetch=False, commit=True)
    try:
        ensure_logs_schema()
        query("INSERT INTO logs (timestamp,user,sku,hub,action,qty,comment) VALUES (?,?,?,?,?,?,?)",
              (_now_iso(), sender, None, hub, "message_sent", None,
               f"to={recipient}|type={msg_type}|thread={thread_id}"),
              fetch=False, commit=True)
    except Exception:
        pass
    return thread_id

def mark_thread_read(username: str, thread_id: str):
    query("UPDATE messages SET read_at=? WHERE recipient=? AND thread_id=? AND read_at IS NULL",
          (_now_iso(), username, thread_id), fetch=False, commit=True)

def get_inbox(username: str, only_unread: bool=False):
    ensure_messages_schema()
    sql = "SELECT id,timestamp,sender,recipient,subject,body,thread_id,msg_type,read_at,hub,shipped_count,shipped_range_start,shipped_range_end,paid_count FROM messages WHERE recipient=?"
    if only_unread:
        sql += " AND read_at IS NULL"
    sql += " ORDER BY timestamp DESC"
    return query(sql, (username,))

def get_sent(username: str):
    ensure_messages_schema()
    return query("SELECT id,timestamp,sender,recipient,subject,body,thread_id,msg_type,read_at,hub,shipped_count,shipped_range_start,shipped_range_end,paid_count FROM messages WHERE sender=? ORDER BY timestamp DESC",
                 (username,))

def get_thread(thread_id: str):
    ensure_messages_schema()
    return query("SELECT id,timestamp,sender,recipient,subject,body,thread_id,msg_type,read_at,hub,shipped_count,shipped_range_start,shipped_range_end,paid_count FROM messages WHERE thread_id=? ORDER BY timestamp ASC",
                 (thread_id,))

def shipments_count_for(hub: str, start: str, end: str) -> int:
    try:
        rows = query("SELECT COUNT(*) FROM shipments WHERE hub=? AND date(date) BETWEEN date(?) AND date(?)",
                     (hub, start, end))
        return int(rows[0][0]) if rows else 0
    except Exception:
        return 0

# ===== section 4: messaging UI page ==========================================
def messaging_page(current_user: str, role: str, hub: Optional[str]):
    st.header("💬 Messages")
    top = st.columns([3,1])
    with top[0]:
        st.caption(f"Logged in as **{current_user}** ({role}{' — '+hub if hub else ''})")
        last = last_login_for(current_user)
        if last:
            st.caption(f"Last sign-in: {last}")
    with top[1]:
        st.metric("Unread", unread_count(current_user))

    is_admin_user = is_admin(role)

    # Tabs: Admin gets Inbox/Sent/Compose/Drop-offs/Reports; others get Inbox/Compose/Drop-offs/Reports
    if is_admin_user:
        tabs = st.tabs(["📥 Inbox","📤 Sent","✍️ Compose","📮 Drop-offs","📊 Reports"])
    else:
        tabs = st.tabs(["📥 Inbox","📨 Message HQ","📮 Drop-offs","📊 Reports"])

    # --- inbox ---
    with tabs[0]:
        c = st.columns([1,2])
        if c[0].button("Mark all read"):
            inbox_all = get_inbox(current_user, only_unread=True)
            tids = {r[6] for r in inbox_all}
            for tid in tids:
                mark_thread_read(current_user, tid)
            st.rerun()
        show_unread = c[1].checkbox("Show only unread", value=False)

        inbox = get_inbox(current_user, only_unread=show_unread)
        if not inbox:
            st.info("No messages.")
        else:
            threads: Dict[str, list] = {}
            for r in inbox:
                threads.setdefault(r[6], []).append(r)
            for tid, items in list(threads.items())[:200]:
                latest = items[0]
                unread = any(it[8] is None and it[3]==current_user for it in items)
                label = f"{'🔵 ' if unread else ''}{latest[2]} • {latest[4]} • {fmt_ts_et(latest[1])}"
                with st.expander(label, expanded=False):
                    for it in items[::-1]:
                        _id, ts, snd, rcp, sub, body, _t, mtype, r_at, _hub, scnt, rs, re_, pcnt = it
                        badge = "✉️"
                        if mtype=="shipped_report": badge="🟣 Shipped"
                        elif mtype=="paid_notice": badge="🟢 Paid"
                        elif mtype=="dropoff_report": badge="🟠 Drop-off"
                        st.markdown(f"**{snd} → {rcp}** · _{fmt_ts_et(ts)}_ · {badge}")
                        st.write(body)
                        if scnt is not None and (mtype in ("shipped_report","dropoff_report")):
                            if rs and re_:
                                st.caption(f"Count: {scnt} ({rs} → {re_})")
                        if pcnt is not None: st.caption(f"Paid: {pcnt}")
                        st.divider()
                    cols = st.columns([1,2,2])
                    if cols[0].button("Mark read", key=f"mr_{tid}"):
                        mark_thread_read(current_user, tid); st.rerun()
                    reply = cols[1].text_input("Reply", key=f"r_{tid}")
                    if cols[1].button("Send", key=f"s_{tid}") and reply.strip():
                        to = latest[2] if latest[2]!=current_user else latest[3]
                        try:
                            send_message(current_user, to, subject=latest[4], body=reply, msg_type="message", thread_id=tid, hub=hub)
                            # Auto-mark read on reply
                            mark_thread_read(current_user, tid)
                            st.success("Reply sent."); st.rerun()
                        except ValueError as e:
                            st.error(str(e))
                    if is_admin_user:
                        paid = cols[2].number_input("Paid count", min_value=0, step=1, key=f"pc_{tid}")
                        if cols[2].button("Send paid notice", key=f"p_{tid}"):
                            to = latest[2] if latest[2]!=current_user else latest[3]
                            try:
                                send_message(current_user, to, subject=f"[PAID] {latest[4]}", body=f"Paid for {int(paid)} orders.",
                                             msg_type="paid_notice", thread_id=tid, hub=hub, paid_count=int(paid))
                                mark_thread_read(current_user, tid)
                                st.success("Paid notice sent."); st.rerun()
                            except ValueError as e:
                                st.error(str(e))

    # --- sent (admins only) ---
    if is_admin_user:
        with tabs[1]:
            sent = get_sent(current_user)
            if not sent:
                st.info("No sent messages.")
            else:
                df = pd.DataFrame(
                    sent,
                    columns=["id","timestamp","sender","recipient","subject","body","thread_id","msg_type","read_at","hub","shipped_count","range_start","range_end","paid_count"]
                )
                if not df.empty:
                    df["timestamp"] = df["timestamp"].map(fmt_ts_et)
                st.dataframe(df, use_container_width=True, height=400)

    # --- compose / message HQ ---
    compose_tab = tabs[2] if is_admin_user else tabs[1]
    with compose_tab:
        users = query("SELECT username, role, hub FROM users WHERE disabled=0 ORDER BY username")
        if is_admin_user:
            mode = st.radio("Send to…", ["User","Role","Hub"], horizontal=True)
            if mode=="User":
                recips = [st.selectbox("Recipient", [u[0] for u in users])]
            elif mode=="Role":
                role_sel = st.selectbox("Role", sorted({u[1] for u in users}))
                recips = [u[0] for u in users if u[1]==role_sel]
            else:
                hub_sel = st.selectbox("Hub", sorted({u[2] for u in users if u[2]}))
                recips = [u[0] for u in users if u[2]==hub_sel]
        else:
            admins = [u[0] for u in users if (u[1] or "").lower()=="admin"]
            if not admins:
                st.warning("No HQ users found. Ask an admin to create an Admin user.")
                recips = []
            else:
                st.caption("This message will be sent to **HQ (all Admins)**.")
                recips = admins

        subject = st.text_input("Subject")
        body = st.text_area("Message")
        if st.button("Send message"):
            if not recips:
                st.warning("No recipients.")
            else:
                ok = 0; err = 0
                for r in recips:
                    try:
                        send_message(current_user, r, subject, body, hub=hub)
                        ok += 1
                    except ValueError:
                        err += 1
                if ok:
                    st.success(f"Sent to {ok} user(s).")
                if err:
                    st.error(f"{err} message(s) blocked by policy.")

    # --- Drop-offs tab (simple) ---
    with tabs[3 if is_admin_user else 2]:
        if is_admin_user:
            st.info("Drop-off reports/receipts are submitted by hubs. Review receipts under Admin → Receipts.")
        else:
            import datetime as dt
            st.subheader("📮 Post Office Drop-off")
            rs = st.date_input("Date", value=dt.date.today(), key="dropoff_date")
            drop = st.number_input("Orders dropped off", min_value=0, step=1, key="dropoff_cnt")
            note = st.text_input("Note (optional)", key="dropoff_note")
            # Optional receipt upload (photo)
            rec = st.file_uploader("Upload receipt photo (optional)", type=["jpg","jpeg","png"], accept_multiple_files=False)
            rec_path_text = None
            if st.button("Send drop-off report"):
                if not hub:
                    st.warning("Your user has no hub assigned.")
                else:
                    # Save upload if provided
                    if rec is not None:
                        p = _dropoff_dir() / f"{current_user}_{hub}_{datetime.now().strftime('%Y%m%d-%I%M%S%p')}.jpg"
                        p.write_bytes(rec.getbuffer())
                        rec_path_text = str(p)
                    admins = [u[0] for u in query("SELECT username, role FROM users WHERE LOWER(role)='admin'")]
                    subj = f"[DROPOFF] {hub} {rs.isoformat()} — {int(drop)} orders"
                    body = (note or f"{hub}: dropped off {int(drop)} orders on {rs.isoformat()}")
                    if rec_path_text:
                        body += f"\nReceipt: {rec_path_text}"
                    for adm in admins:
                        try:
                            send_message(current_user, adm, subject=subj, body=body,
                                         msg_type="dropoff_report", hub=hub, shipped_count=int(drop),
                                         range_start=rs.isoformat(), range_end=rs.isoformat())
                        except ValueError:
                            pass
                    st.success(f"Reported {int(drop)} orders dropped off.")

    # --- Reports tab (KISS) ---
    with tabs[-1]:
        if is_admin_user:
            st.subheader("Admin reports")
            days = st.slider("Lookback days", min_value=7, max_value=180, value=30, step=1)
            # Top 5 SKUs across all hubs
            rows = query("""
                SELECT sku, SUM(quantity) as total
                FROM inventory
                GROUP BY sku
                ORDER BY total DESC
                LIMIT 5
            """)
            df = pd.DataFrame(rows, columns=["SKU","Qty"])
            st.markdown("**Top 5 SKUs (by on-hand)**")
            if df.empty: st.info("No data"); 
            else: st.dataframe(df, use_container_width=True, height=200)

            # Drop-offs count by hub (messages of type dropoff_report)
            rows = query("""
                SELECT hub, COALESCE(SUM(shipped_count),0) as dropoffs
                FROM messages
                WHERE msg_type='dropoff_report' AND date(timestamp) >= date('now', ?)
                GROUP BY hub
                ORDER BY dropoffs DESC
            """, (f"-{days} days",))
            df2 = pd.DataFrame(rows, columns=["Hub","Drop-offs"])
            st.markdown("**Drop-offs (last {} days)**".format(days))
            if df2.empty: st.info("No data"); 
            else: st.dataframe(df2, use_container_width=True, height=220)
        else:
            st.subheader("Hub reports")
            if not hub:
                st.info("Your user has no hub assigned.")
            else:
                # Top 5 SKUs at my hub
                rows = query("""
                    SELECT sku, quantity
                    FROM inventory
                    WHERE hub=?
                    ORDER BY quantity DESC
                    LIMIT 5
                """, (hub,))
                df = pd.DataFrame(rows, columns=["SKU","Qty"])
                st.markdown("**Top 5 SKUs (by on-hand)**")
                if df.empty: st.info("No data"); 
                else: st.dataframe(df, use_container_width=True, height=200)

                # My drop-offs total
                rows = query("""
                    SELECT COALESCE(SUM(shipped_count),0)
                    FROM messages
                    WHERE msg_type='dropoff_report' AND hub=?
                """, (hub,))
                total = int(rows[0][0]) if rows else 0
                st.metric("Total drop-offs (all time)", total)

# ===== section 5: main UI, schemas, admin/hub/supplier pages ==================
def ensure_logs_schema():
    con = connect(); cur = con.cursor()
    cur.execute("""CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        user TEXT,
        sku TEXT,
        hub TEXT,
        action TEXT,
        qty INTEGER,
        comment TEXT
    )""")
    con.commit(); con.close()

def ensure_shipments_schema():
    con = connect(); cur = con.cursor()
    cur.execute("""CREATE TABLE IF NOT EXISTS shipments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        supplier TEXT,
        tracking TEXT,
        carrier TEXT,
        hub TEXT,
        skus TEXT,
        date TEXT,
        status TEXT,
        received_at TEXT,
        received_by TEXT
    )""")
    have = [r[1] for r in cur.execute("PRAGMA table_info(shipments)").fetchall()]
    for col, typ in {
        "supplier":"TEXT","tracking":"TEXT","carrier":"TEXT","hub":"TEXT","skus":"TEXT",
        "date":"TEXT","status":"TEXT","received_at":"TEXT","received_by":"TEXT"
    }.items():
        if col not in have:
            cur.execute(f"ALTER TABLE shipments ADD COLUMN {col} {typ}")
    con.commit(); con.close()

def _table_exists(name: str) -> bool:
    con = connect(); cur = con.cursor()
    cur.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,))
    ok = cur.fetchone() is not None
    con.close()
    return ok

def create_indices():
    con = connect(); cur = con.cursor()
    try:
        if _table_exists("inventory"):
            cur.execute("CREATE INDEX IF NOT EXISTS idx_inventory_hub_qty ON inventory(hub, quantity)")
        if _table_exists("messages"):
            cur.execute("CREATE INDEX IF NOT EXISTS idx_messages_recipient_read ON messages(recipient, read_at)")
        if _table_exists("logs"):
            cur.execute("CREATE INDEX IF NOT EXISTS idx_logs_ts ON logs(timestamp)")
        if _table_exists("shipments"):
            cur.execute("CREATE INDEX IF NOT EXISTS idx_shipments_hub_date ON shipments(hub, date)")
        con.commit()
    finally:
        con.close()

ensure_logs_schema()
ensure_shipments_schema()
create_indices()  # first attempt (guarded)

# --- Home helpers (admin/hub) -------------------------------------------------
ADMIN_LOW_STOCK = 5
LOW_STOCK_THRESHOLD = 5

def users_table():
    rows = query("SELECT username, role, hub, disabled FROM users ORDER BY username")
    df = pd.DataFrame(rows, columns=["username","role","hub","disabled"])
    st.dataframe(df, use_container_width=True, height=300)

def logs_table_filtered():
    st.subheader("🧾 Logs")
    c1, c2, c3, c4, c5 = st.columns(5)
    with c1: d1 = st.date_input("From", value=date.today()-timedelta(days=7))
    with c2: d2 = st.date_input("To", value=date.today())
    with c3: u = st.text_input("User")
    with c4: h = st.text_input("Hub")
    with c5: a = st.text_input("Action")
    sql = "SELECT timestamp,user,action,comment,hub,sku,qty FROM logs WHERE date(timestamp) BETWEEN date(?) AND date(?)"
    params: List = [d1.isoformat(), d2.isoformat()]
    if u: sql += " AND user=?"; params.append(u)
    if h: sql += " AND hub=?"; params.append(h)
    if a: sql += " AND action=?"; params.append(a)
    sql += " ORDER BY timestamp DESC LIMIT 5000"
    rows = query(sql, tuple(params))
    df = pd.DataFrame(rows, columns=["timestamp","user","action","comment","hub","sku","qty"])
    if not df.empty:
        df["timestamp"] = df["timestamp"].map(fmt_ts_et)
    st.dataframe(df, use_container_width=True, height=380)
    st.download_button("Export logs.csv", df.to_csv(index=False).encode("utf-8"),
                       "logs.csv", "text/csv")

def restore_csv_tool():
    st.subheader("🛟 Restore from CSV (safe)")
    st.caption("Preview → Schema check → Requires confirmation → Makes a DB backup first.")
    tbl = st.selectbox("Target table", ["users","inventory","sku_info","shipments","logs","messages"])
    file = st.file_uploader("Choose CSV", type=["csv"], accept_multiple_files=False, key=f"up_{tbl}")
    if not file:
        return
    try:
        df = pd.read_csv(file)
    except Exception as e:
        st.error(f"Could not read CSV: {e}")
        return

    st.write("Preview (first 10 rows):")
    st.dataframe(df.head(10), use_container_width=True)

    # Schema check
    try:
        conn_v = connect(); cur_v = conn_v.cursor()
        pragma = cur_v.execute(f"PRAGMA table_info({tbl})").fetchall()
        table_cols = [r[1] for r in pragma]
        conn_v.close()
    except Exception as e:
        st.error(f"Could not read schema for '{tbl}': {e}")
        table_cols = list(df.columns)

    missing = [c for c in table_cols if c not in df.columns]
    extra   = [c for c in df.columns if c not in table_cols]
    if missing:
        st.warning(f"CSV missing expected columns for '{tbl}': {missing}")
    if extra:
        st.info(f"CSV has extra columns not in '{tbl}': {extra}")

    confirm = st.checkbox("I understand this will overwrite existing rows for matching primary keys.")
    if st.button("Apply Restore"):
        if not confirm:
            st.warning("Please confirm overwrite to proceed.")
            return
        bkp = backup_db()
        if bkp:
            st.caption(f"Database backed up to: `{bkp}`")
        try:
            conn = connect(); cur = conn.cursor()
            conn.execute("BEGIN")
            cols = [c for c in df.columns if c in table_cols] if table_cols else list(df.columns)
            placeholders = ",".join(["?"]*len(cols))
            colnames = ",".join(cols)
            for _, row in df.iterrows():
                values = tuple(row[c] for c in cols)
                cur.execute(f"INSERT OR REPLACE INTO {tbl} ({colnames}) VALUES ({placeholders})", values)
            conn.commit(); conn.close()
            st.success(f"Restored {len(df)} rows into '{tbl}'.")
        except Exception as e:
            try: conn.rollback()
            except Exception: pass
            st.error(f"Restore failed and was rolled back: {e}")

def list_backups(limit: int = 50) -> List[Path]:
    p = Path(DB).with_name(f"{Path(DB).stem}-*{Path(DB).suffix}")
    return sorted(Path(DB).parent.glob(p.name), reverse=True)[:limit]

# --- Admin Overview -----------------------------------------------------------
def _admin_kpis() -> Dict[str, int]:
    tqty = query("SELECT COALESCE(SUM(quantity),0) FROM inventory")
    total_qty = int(tqty[0][0]) if tqty else 0
    tsku = query("SELECT COUNT(DISTINCT sku) FROM inventory")
    total_skus = int(tsku[0][0]) if tsku else 0
    hubs = query("SELECT COUNT(DISTINCT hub) FROM inventory WHERE hub IS NOT NULL")
    hubs_count = int(hubs[0][0]) if hubs else 0
    low = query("SELECT COUNT(*) FROM (SELECT sku, hub FROM inventory WHERE quantity<=?)", (ADMIN_LOW_STOCK,))
    low_count = int(low[0][0]) if low else 0
    return dict(total_skus=total_skus, total_qty=total_qty, hubs=hubs_count, low=low_count)

def _hubs_overview_df() -> pd.DataFrame:
    rows = query("""
        SELECT i.hub,
               COUNT(DISTINCT i.sku) AS skus,
               COALESCE(SUM(i.quantity),0) AS on_hand,
               SUM(CASE WHEN i.quantity<=? THEN 1 ELSE 0 END) AS low_skus
        FROM inventory i
        WHERE i.hub IS NOT NULL
        GROUP BY i.hub
        ORDER BY i.hub
    """, (ADMIN_LOW_STOCK,))
    return pd.DataFrame(rows, columns=["Hub","SKUs","On hand","Low (≤{})".format(ADMIN_LOW_STOCK)])

def _low_stock_all_df() -> pd.DataFrame:
    rows = query("""
        SELECT hub, sku, quantity
        FROM inventory
        WHERE quantity<=?
        ORDER BY quantity ASC, hub, sku
    """, (ADMIN_LOW_STOCK,))
    return pd.DataFrame(rows, columns=["Hub","SKU","Qty"])

def _shipments_overview_df(days: int = 30) -> pd.DataFrame:
    rows = query("""
        SELECT hub, date, supplier, tracking, carrier, status
        FROM shipments
        WHERE date(date) >= date('now', ?)
        ORDER BY date(date) DESC, hub
    """, (f"-{days} days",))
    return pd.DataFrame(rows, columns=["Hub","Date","Supplier","Tracking","Carrier","Status"])

def admin_home_page():
    st.subheader("Admin Overview")
    k = _admin_kpis()
    kcols = st.columns(4)
    kcols[0].metric("Total SKUs", k["total_skus"])
    kcols[1].metric("On-hand pieces", k["total_qty"])
    kcols[2].metric("Hubs", k["hubs"])
    kcols[3].metric(f"Low-stock SKUs (≤{ADMIN_LOW_STOCK})", k["low"])

    st.divider()
    t1, t2 = st.tabs(["🏬 Hubs overview", "⚠️ Low stock (all hubs)"])

    with t1:
        dfh = _hubs_overview_df()
        if dfh is None or dfh.empty:
            st.info("No hub data yet.")
        else:
            st.dataframe(dfh, use_container_width=True, hide_index=True)

    with t2:
        dfl = _low_stock_all_df()
        if dfl is None or dfl.empty:
            st.success("No low-stock items across hubs.")
        else:
            st.dataframe(dfl, use_container_width=True, height=320)
            st.download_button(
                "Export low_stock_all.csv",
                dfl.to_csv(index=False).encode("utf-8"),
                "low_stock_all.csv",
                "text/csv",
            )

    st.divider()
    st.subheader("📦 Shipments (last 30 days)")
    dfs = _shipments_overview_df(30)
    if dfs is None or dfs.empty:
        st.info("No shipments in the last 30 days.")
    else:
        st.dataframe(dfs, use_container_width=True, height=300)

    st.divider()
    st.subheader("👥 Users (enable/disable)")
    rows = query("SELECT username, role, hub, disabled FROM users ORDER BY username")
    for uname, role, uhb, dis in rows:
        cols = st.columns([3,2,2,2,2])
        cols[0].markdown(f"**{uname}**")
        cols[1].markdown(role or "—")
        cols[2].markdown(uhb or "—")
        cols[3].markdown("Disabled" if dis else "Active")
        if cols[4].button("Enable" if dis else "Disable", key=f"ud_{uname}"):
            query("UPDATE users SET disabled=? WHERE username=?", (0 if dis else 1, uname), fetch=False, commit=True)
            st.rerun()

# --- Admin: Catalog helpers + Receipts ---------------------------------------
def _get_all_skus() -> List[Tuple[str, str]]:
    rows = query("SELECT sku, COALESCE(assigned_hubs,'') FROM sku_info ORDER BY sku")
    return [(r[0], r[1]) for r in rows]

def _merge_assignments(old_csv: str, to_add: List[str]) -> str:
    old = [h.strip() for h in (old_csv or "").split(",") if h and h.strip()]
    merged = sorted(set(old + [h for h in to_add if h]))
    return ",".join(merged)

def add_or_assign_sku_to_hubs(sku: str, hubs: List[str]):
    sku = (sku or "").strip()
    hubs = [h.strip() for h in hubs if h and h.strip()]
    if not sku or not hubs:
        return False, "SKU and hubs are required."
    rows = query("SELECT assigned_hubs FROM sku_info WHERE sku=?", (sku,))
    if rows:
        new_csv = _merge_assignments(rows[0][0], hubs)
        query("UPDATE sku_info SET assigned_hubs=?, product_name=? WHERE sku=?",
              (new_csv, sku, sku), fetch=False, commit=True)
    else:
        query("INSERT INTO sku_info (sku, product_name, assigned_hubs) VALUES (?,?,?)",
              (sku, sku, ",".join(sorted(set(hubs)))), fetch=False, commit=True)
    for h in hubs:
        query("INSERT OR IGNORE INTO inventory (sku, hub, quantity) VALUES (?,?,?)",
              (sku, h, 0), fetch=False, commit=True)
    try:
        query("INSERT INTO logs (timestamp,user,sku,hub,action,qty,comment) VALUES (?,?,?,?,?,?,?)",
              (_now_iso(), "admin", sku, None, "catalog_assign", None, f"hubs={hubs}"),
              fetch=False, commit=True)
    except Exception:
        pass
    return True, f"SKU '{sku}' assigned to: {', '.join(hubs)}"

# Receipts helpers/viewer
def _dropoff_dir() -> Path:
    base = Path(__file__).parent
    d = base / "data" / "uploads" / "dropoffs"
    d.mkdir(parents=True, exist_ok=True)
    return d

def _display_receipt(path_str: str):
    p = Path(path_str)
    if not p.is_file():
        p = Path(__file__).parent / path_str.lstrip("/")
    if not p.is_file():
        st.error(f"Not found: {path_str}")
        return
    st.image(str(p), caption=p.name, use_container_width=True)
    try:
        with open(p, "rb") as f:
            st.download_button("Download image", f.read(), file_name=p.name, mime="image/jpeg", key=f"dl_{p.name}")
    except Exception as e:
        st.error(f"Could not read {p.name}: {e}")

def admin_logs_page(role: str):
    if not is_admin(role):
        st.error("Unauthorized."); return
    st.header("🧾 Logs")
    logs_table_filtered()

def admin_page(role: str):
    if not is_admin(role):
        st.error("Unauthorized."); return
    st.header("🛠️ Admin")
    tabs = st.tabs(["🏷️ Catalog", "💽 Backups", "📥 CSV Restore", "🧾 Receipts"])

    # --- Catalog tab ---
    with tabs[0]:
        st.subheader("Catalog (Add / Assign SKUs)")
        hubs_known = _hubs_list()
        extra_hubs = set()
        for _, ah in _get_all_skus():
            if ah:
                extra_hubs.update([x.strip() for x in ah.split(",") if x.strip()])
        hubs_all = sorted(set(hubs_known) | extra_hubs)

        colm = st.columns(2)

        with colm[0]:
            st.markdown("**Add new SKU & assign to hubs**")
            new_sku = st.text_input("New SKU name", placeholder="e.g., Ocean Teal Solid")
            hubs_sel_new = st.multiselect("Assign to hubs", hubs_all, placeholder="Pick one or more hubs")
            if st.button("Create & assign"):
                ok, msg = add_or_assign_sku_to_hubs(new_sku, hubs_sel_new)
                st.success(msg) if ok else st.error(msg)

        with colm[1]:
            st.markdown("**Assign existing SKU to more hubs**")
            f = st.text_input("Filter SKUs", "", placeholder="type to filter…")
            all_skus = [s for s, _ in _get_all_skus()]
            if f:
                all_skus = [s for s in all_skus if f.lower() in s.lower()]
            sku_pick = st.selectbox("Existing SKU", options=all_skus)
            hubs_sel_more = st.multiselect("Add hubs", hubs_all, placeholder="Pick hubs to add")
            if st.button("Assign to hubs"):
                ok, msg = add_or_assign_sku_to_hubs(sku_pick, hubs_sel_more)
                st.success(msg) if ok else st.error(msg)

        st.divider()
        st.caption("Note: Assigning an SKU to a hub creates a zero-qty row in **inventory**. Adjust quantities on the Inventory page.")

    # --- Backups tab ---
    with tabs[1]:
        st.subheader("Back up & Restore SQLite DB")
        col = st.columns(3)
        with col[0]:
            try:
                with open(DB, "rb") as f:
                    st.download_button("Download live DB", f.read(), file_name=Path(DB).name, mime="application/octet-stream")
            except Exception as e:
                st.error(f"Could not read DB: {e}")
        with col[1]:
            if st.button("Create backup now"):
                b = backup_db()
                if b:
                    st.success(f"Backup created: {b.name}")
                else:
                    st.error("Backup failed.")
        with col[2]:
            up = st.file_uploader("Restore from backup (.db)", type=["db"], accept_multiple_files=False, key="db_restore")
            if up is not None:
                tmp_path = Path(DB).with_suffix(".upload.tmp")
                try:
                    tmp_path.write_bytes(up.getbuffer())
                    b = backup_db()
                    import shutil
                    shutil.copy2(tmp_path, DB)
                    st.success(f"Restored from upload. Previous DB backed up to: {b.name if b else 'unknown (backup failed)'}")
                    st.caption("Please refresh the page.")
                except Exception as e:
                    st.error(f"Restore failed: {e}")
                finally:
                    try:
                        tmp_path.unlink(missing_ok=True)
                    except Exception:
                        pass

        st.markdown("### Recent backups")
        bks = list_backups()
        if not bks:
            st.info("No backups found yet.")
        else:
            for b in bks:
                cols = st.columns([4,1])
                with cols[0]:
                    st.caption(b.name)
                with cols[1]:
                    try:
                        with open(b, "rb") as f:
                            st.download_button("Download", f.read(), file_name=b.name, mime="application/octet-stream", key=f"d_{b.name}")
                    except Exception as e:
                        st.error(f"Could not read backup {b.name}: {e}")

    # --- CSV Restore tab ---
    with tabs[2]:
        restore_csv_tool()

    # --- Receipts tab ---
    with tabs[3]:
        st.subheader("Drop-off Receipts")
        receipt_dir = _dropoff_dir()
        files = sorted(receipt_dir.glob("*.jpg")) + sorted(receipt_dir.glob("*.png")) + sorted(receipt_dir.glob("*.jpeg"))
        if not files:
            st.info("No receipts found yet.")
        else:
            cols = st.columns([2,2,2])
            f_text = cols[0].text_input("Filter by file name", "")
            f_hub  = cols[1].text_input("Filter by hub (e.g., Hub 3)", "")
            f_user = cols[2].text_input("Filter by user (e.g., carmen)", "")

            def _match(p: Path) -> bool:
                name = p.name
                if f_text and f_text.lower() not in name.lower():
                    return False
                parts = name.rsplit(".", 1)[0].split("_")
                user = parts[0] if parts else ""
                hub  = "_".join(parts[1:-1]) if len(parts) >= 3 else ""
                if f_hub and f_hub.lower() not in hub.lower():
                    return False
                if f_user and f_user.lower() not in user.lower():
                    return False
                return True

            shown = [p for p in files if _match(p)]
            if not shown:
                st.warning("No receipts match your filters.")
            else:
                for p in shown[:200]:
                    with st.expander(p.name, expanded=False):
                        _display_receipt(str(p))

# --- Hub Home (dashboard) -----------------------------------------------------
def _hub_kpis(hub: str) -> Dict[str, int]:
    tq = query("SELECT COALESCE(SUM(quantity),0) FROM inventory WHERE hub=?", (hub,))
    total_qty = int(tq[0][0]) if tq else 0
    sk = query("SELECT COUNT(*) FROM (SELECT sku FROM inventory WHERE hub=? AND quantity>0)", (hub,))
    skus_stocked = int(sk[0][0]) if sk else 0
    ls = query("SELECT COUNT(*) FROM inventory WHERE hub=? AND quantity<=?", (hub, LOW_STOCK_THRESHOLD))
    low_count = int(ls[0][0]) if ls else 0
    today = date.today()
    week_start = today - timedelta(days=today.weekday())
    week_end = week_start + timedelta(days=6)
    sw = query("SELECT COUNT(*) FROM shipments WHERE hub=? AND date(date) BETWEEN date(?) AND date(?)",
               (hub, week_start.isoformat(), week_end.isoformat()))
    ship_week = int(sw[0][0]) if sw else 0
    return dict(skus=skus_stocked, qty=total_qty, low=low_count, ship_week=ship_week)

def _low_stock_df(hub: str) -> pd.DataFrame:
    rows = query("""
        SELECT i.sku, i.quantity
        FROM inventory i
        WHERE i.hub=? AND i.quantity<=?
        ORDER BY i.quantity ASC, i.sku
        """, (hub, LOW_STOCK_THRESHOLD))
    return pd.DataFrame(rows, columns=["SKU","Qty"])

def _recent_shipments_df(hub: str, days: int = 90) -> pd.DataFrame:
    rows = query("""
        SELECT id, date, supplier, tracking, carrier, status
        FROM shipments
        WHERE hub=? AND date(date) >= date('now', ?)
        ORDER BY date(date) DESC
        """, (hub, f"-{days} days"))
    return pd.DataFrame(rows, columns=["ID","Date","Supplier","Tracking","Carrier","Status"])

def hub_home_page(username: str, hub: Optional[str]):
    if not hub:
        st.info("No hub assigned to your user yet.")
        return
    st.subheader(f"{hub} — Dashboard")
    k = _hub_kpis(hub)
    kcols = st.columns(4)
    kcols[0].metric("SKUs stocked", k["skus"])
    kcols[1].metric("On-hand pieces", k["qty"])
    kcols[2].metric(f"Low stock (≤{LOW_STOCK_THRESHOLD})", k["low"])
    kcols[3].metric("Shipments this week", k["ship_week"])

    st.divider()
    st.subheader("⚠️ Low stock")
    ldf = _low_stock_df(hub)
    if ldf.empty:
        st.success("No low-stock SKUs.")
    else:
        st.dataframe(ldf, use_container_width=True, height=260)
        st.download_button("Export low_stock.csv", ldf.to_csv(index=False).encode("utf-8"), "low_stock.csv", "text/csv")

    st.divider()
    st.subheader("📦 Incoming Shipments")
    sdf = _recent_shipments_df(hub, days=90)
    if sdf.empty:
        st.info("No recent shipments.")
    else:
        st.dataframe(sdf, use_container_width=True, height=260)
        open_rows = query("SELECT id, tracking, carrier, skus, status FROM shipments WHERE hub=? AND status IN ('Created','In Transit') ORDER BY id DESC", (hub,))
        if open_rows:
            st.caption("Open shipments (confirm to auto-IN inventory):")
            for sid, trk, car, skus_str, status in open_rows[:50]:
                cols = st.columns([3,2,2,2,2])
                cols[0].markdown(f"**#{sid}** · {status}")
                cols[1].markdown(f"Carrier: {car or '—'}")
                cols[2].markdown(f"Tracking: {trk or '—'}")
                if cols[3].button("Mark In Transit", key=f"mit_{sid}"):
                    query("UPDATE shipments SET status=?, date=? WHERE id=?", ("In Transit", _now_iso(), sid), fetch=False, commit=True)
                    st.success(f"Shipment #{sid} marked In Transit."); st.rerun()
                if cols[4].button("Confirm Received", key=f"rcv_{sid}"):
                    ok, msg = _confirm_receive_shipment(sid, hub, username)
                    if ok:
                        st.success(msg); st.rerun()
                    else:
                        st.error(msg)

# --- Supplier Home ------------------------------------------------------------
CARRIERS = ["UPS", "USPS", "FedEx", "DHL", "Other…"]

def _parse_items(s: str) -> Tuple[bool, List[Tuple[str,int]], str]:
    if not s or not s.strip():
        return False, [], "Items are required. Format: SKU|QTY;SKU|QTY"
    items: List[Tuple[str,int]] = []
    parts = [p for p in s.replace("\n",";").split(";") if p.strip()]
    for p in parts:
        if "|" not in p:
            return False, [], f"Bad item '{p}'. Use SKU|QTY."
        sku, qty = p.split("|", 1)
        sku = sku.strip()
        try:
            q = int(str(qty).strip())
        except:
            return False, [], f"Quantity must be an integer for '{sku}'."
        if q <= 0:
            return False, [], f"Quantity must be > 0 for '{sku}'."
        items.append((sku, q))
    return True, items, ""

def _all_catalog_skus() -> List[str]:
    rows = query("SELECT sku FROM sku_info ORDER BY sku")
    return [r[0] for r in rows]

def _ensure_sku_in_catalog(sku: str, hub: Optional[str]):
    sku = (sku or "").strip()
    if not sku:
        return
    query("INSERT OR IGNORE INTO sku_info (sku, product_name, assigned_hubs) VALUES (?,?,?)",
          (sku, sku, hub or ""), fetch=False, commit=True)
    rows = query("SELECT assigned_hubs FROM sku_info WHERE sku=?", (sku,))
    if rows:
        hubs = (rows[0][0] or "").split(",") if rows[0][0] else []
        hubs = [h.strip() for h in hubs if h and h.strip()]
        if hub and hub not in hubs:
            hubs.append(hub)
            query("UPDATE sku_info SET assigned_hubs=? WHERE sku=?", (",".join(sorted(set(hubs))), sku),
                  fetch=False, commit=True)
    if hub:
        query("INSERT OR IGNORE INTO inventory (sku, hub, quantity) VALUES (?,?,?)",
              (sku, hub, 0), fetch=False, commit=True)

def supplier_home_page(username: str):
    st.subheader("Supplier — Create Shipment")
    hubs = [h[0] for h in query("SELECT DISTINCT hub FROM inventory WHERE hub IS NOT NULL ORDER BY hub")]
    if not hubs:
        st.info("No hubs configured yet.")
        return

    hub_sel = st.selectbox("Hub", hubs)

    car_sel = st.selectbox("Carrier", CARRIERS, index=0)
    car_text = ""
    if car_sel == "Other…":
        car_text = st.text_input("Carrier (other)")
    trk = st.text_input("Tracking (optional)")

    st.markdown("### Items")
    filter_text = st.text_input("Filter SKUs", "", placeholder="Type to narrow the list…")
    catalog = _all_catalog_skus()
    shown = [s for s in catalog if filter_text.lower() in s.lower()] if filter_text else catalog

    selected: List[Tuple[str,int]] = []
    if not shown:
        st.info("No SKUs match that filter.")
    else:
        st.caption("Tick SKUs and enter quantities. Only checked items with qty > 0 will be included.")
        for sku in shown:
            cols = st.columns([6,2])
            checked = cols[0].checkbox(sku, key=f"sup_cb_{sku}")
            qty_val = cols[1].number_input("Qty", min_value=1, step=1, value=1, key=f"sup_qty_{sku}")
            if checked:
                selected.append((sku, int(qty_val)))

    with st.expander("➕ Add new color / SKU (optional)", expanded=False):
        new_sku = st.text_input("New color / SKU name", placeholder="e.g., Ocean Teal Solid")
        new_qty = st.number_input("Qty (for the new SKU)", min_value=0, step=1, value=0)

    preview_items = list(selected)
    if (new_sku or "").strip() and new_qty > 0:
        preview_items.append((new_sku.strip(), int(new_qty)))

    if preview_items:
        total_lines = len(preview_items)
        total_units = sum(q for _, q in preview_items)
        st.caption(f"Preview: {total_lines} SKU(s), {total_units} total units")

    if st.button("Create shipment"):
        if not preview_items:
            st.warning("Please select at least one SKU with qty.")
        else:
            if (new_sku or "").strip() and new_qty > 0:
                _ensure_sku_in_catalog(new_sku.strip(), hub_sel)
            for sku, _q in selected:
                _ensure_sku_in_catalog(sku, hub_sel)
            items_str = ";".join([f"{sku}|{qty}" for sku, qty in preview_items])
            carrier_final = car_text.strip() if car_sel == "Other…" else car_sel
            query("""INSERT INTO shipments (supplier, tracking, carrier, hub, skus, date, status)
                     VALUES (?,?,?,?,?,?,?)""",
                  (username, trk.strip() or None, carrier_final or None, hub_sel, items_str, _now_iso(), "Created"),
                  fetch=False, commit=True)
            st.success("Shipment created.")
            st.rerun()

    st.divider()
    st.subheader("My Shipments (last 90 days)")
    rows = query("""SELECT id, date, hub, carrier, tracking, status, skus
                    FROM shipments
                    WHERE supplier=? AND date(date) >= date('now','-90 days')
                    ORDER BY id DESC""", (username,))
    if not rows:
        st.info("No shipments yet.")
    else:
        for (sid, sdate, shub, scar, strk, sst, sskus) in rows[:200]:
            st.markdown(f"**#{sid}** · {fmt_ts_et(sdate)} · Hub: {shub} · Status: {sst}")
            c = st.columns([2,3,3,2,2])
            with c[0]:
                st.caption(f"Items: {sskus}")
            with c[1]:
                if sst != "Received":
                    curr = scar or ""
                    choices = CARRIERS + ["(keep)"]
                    default_idx = choices.index("(keep)") if curr not in CARRIERS else CARRIERS.index(curr)
                    new_car_sel = st.selectbox("Carrier", choices, index=default_idx, key=f"csel_{sid}")
                    new_car = curr
                    if new_car_sel == "Other…":
                        new_car = st.text_input("Carrier (other)", value=curr, key=f"coth_{sid}")
                    elif new_car_sel == "(keep)":
                        new_car = curr
                    else:
                        new_car = new_car_sel
                    if st.button("Save carrier", key=f"csave_{sid}"):
                        query("UPDATE shipments SET carrier=? WHERE id=?", (new_car.strip() or None, sid), fetch=False, commit=True)
                        try:
                            query("INSERT INTO logs (timestamp,user,sku,hub,action,qty,comment) VALUES (?,?,?,?,?,?,?)",
                                  (_now_iso(), username, None, shub, "update_carrier", None, f"shipment #{sid} → {new_car}"),
                                  fetch=False, commit=True)
                        except Exception:
                            pass
                        st.success("Carrier updated."); st.rerun()
                else:
                    st.caption(f"Carrier: {scar or '—'}")
            with c[2]:
                if sst != "Received":
                    new_trk = st.text_input("Tracking", value=strk or "", key=f"trk_{sid}")
                    if st.button("Save tracking", key=f"tsave_{sid}"):
                        if len(new_trk.strip()) == 0:
                            st.error("Tracking cannot be blank once editing.")
                        elif len(new_trk.strip()) > 100 or "\n" in new_trk:
                            st.error("Tracking is too long or invalid.")
                        else:
                            query("UPDATE shipments SET tracking=? WHERE id=?", (new_trk.strip(), sid), fetch=False, commit=True)
                            try:
                                query("INSERT INTO logs (timestamp,user,sku,hub,action,qty,comment) VALUES (?,?,?,?,?,?,?)",
                                      (_now_iso(), username, None, shub, "update_tracking", None, f"shipment #{sid} → {new_trk.strip()}"),
                                      fetch=False, commit=True)
                            except Exception:
                                pass
                            st.success("Tracking updated."); st.rerun()
                else:
                    st.caption(f"Tracking: {strk or '—'}")
            with c[3]:
                if sst != "Received" and st.button("Mark In Transit", key=f"sup_mit_{sid}"):
                    query("UPDATE shipments SET status=?, date=? WHERE id=?", ("In Transit", _now_iso(), sid), fetch=False, commit=True)
                    st.success("Marked In Transit."); st.rerun()
            with c[4]:
                st.caption(" ")

# --- Shipment receive (hub) ---------------------------------------------------
def _confirm_receive_shipment(sid: int, hub: str, username: str) -> Tuple[bool,str]:
    row = query("SELECT status, skus, tracking, carrier FROM shipments WHERE id=? AND hub=?", (sid, hub))
    if not row:
        return False, "Shipment not found for your hub."
    status, skus_str, tracking, carrier = row[0]
    if status == "Received":
        return False, "Shipment already received."
    ok, items, err = _parse_items(skus_str or "")
    if not ok:
        return False, f"Could not parse items: {err}"

    for sku, qty in items:
        sku_norm = sku.strip()
        r = query("SELECT quantity FROM inventory WHERE sku=? AND hub=?", (sku_norm, hub))
        current = int(r[0][0]) if r else 0
        new_qty = current + qty
        query("""
            INSERT INTO inventory (sku, hub, quantity) VALUES (?,?,?)
            ON CONFLICT(sku, hub) DO UPDATE SET quantity=excluded.quantity
        """, (sku_norm, hub, new_qty), fetch=False, commit=True)
        query("INSERT OR IGNORE INTO sku_info (sku, product_name, assigned_hubs) VALUES (?,?,?)",
              (sku_norm, sku_norm, hub), fetch=False, commit=True)
        try:
            query("INSERT INTO logs (timestamp,user,sku,hub,action,qty,comment) VALUES (?,?,?,?,?,?,?)",
                  (_now_iso(), username, sku_norm, hub, "IN", qty, f"from shipment #{sid} tracking={tracking or ''} carrier={carrier or ''}"),
                  fetch=False, commit=True)
        except Exception:
            pass

    query("UPDATE shipments SET status='Received', received_at=?, received_by=? WHERE id=?",
          (_now_iso(), username, sid), fetch=False, commit=True)

    admins = [u[0] for u in query("SELECT username FROM users WHERE LOWER(role)='admin'")]
    subj = f"[RECEIVED] Hub {hub} shipment #{sid}"
    body = f"Hub {hub} received shipment #{sid}. Tracking={tracking or '—'}"
    for adm in admins:
        try:
            send_message(username, adm, subject=subj, body=body, msg_type="message", hub=hub)
        except ValueError:
            pass

    return True, f"Shipment #{sid} received and inventory updated."

# --- SKU & Inventory Schemas + Seeding ---------------------------------------
import io as _io

def ensure_sku_inventory_schemas():
    con = connect(); cur = con.cursor()
    cur.execute("""CREATE TABLE IF NOT EXISTS sku_info (
        sku TEXT PRIMARY KEY,
        product_name TEXT,
        assigned_hubs TEXT
    )""")
    cur.execute("""CREATE TABLE IF NOT EXISTS inventory (
        sku TEXT,
        hub TEXT,
        quantity INTEGER,
        PRIMARY KEY (sku, hub)
    )""")
    cur.execute("""CREATE TABLE IF NOT EXISTS count_confirmations (
        username TEXT,
        hub TEXT,
        confirmed_at TEXT
    )""")
    con.commit(); con.close()

def _seed_all_skus():
    hub_assignments = {
        "Hub 1": ["All American Stripes","Carolina Blue and White Stripes","Navy and Silver Stripes",
                  "Black and Hot Pink Stripes","Bubble Gum and White Stripes","White and Ice Blue Stripes",
                  "Imperial Purple and White Stripes","Hot Pink and White Stripes","Rainbow Stripes",
                  "Twilight Pop","Juicy Purple","Lovely Lilac","Black","Black and White Stripes"],
        "Hub 2": ["Black and Yellow Stripes","Orange and Black Stripes","Black and Purple Stripes",
                  "Black and Orange Stripes","Electric Blue and White Stripes","Blossom Breeze","Candy Cane Stripes",
                  "Plum Solid","Patriots (Custom)","Snow Angel (Custom)","Cranberry Frost (Custom)","Witchy Vibes",
                  "White and Green Stripes","Black Solid","Black and White Stripes"],
        "Hub 3": ["Black and Grey Stripes","Black and Green Stripes","Smoke Grey and Black Stripes",
                  "Black and Red Stripes","Black and Purple","Dark Cherry and White Stripes","Black and Multicolor Stripes",
                  "Puerto Rican (Custom)","Seahawks (Custom)","PCH (Custom)","Valentine Socks","Rainbow Stripes",
                  "Thin Black Socks","Thin Black and White Stripes","Smoke Grey Solid","Cherry Solid",
                  "Brown Solid","Wheat and White Stripes","Black Solid","Black and White Stripes"]
    }
    retail_skus = [
        "Black Solid","Bubblegum","Tan Solid","Hot Pink Solid","Brown Solid","Dark Cherry Solid",
        "Winter White Solid","Coral Orange","Navy Solid","Electric Blue Solid","Celtic Green",
        "Cherry Solid","Smoke Grey Solid","Chartreuse Green","Lovely Lilac","Carolina Blue Solid",
        "Juicy Purple","Green & Red Spaced Stripes","Winter Green Stripes","Midnight Frost Stripes",
        "Witchy Vibes Stripes","Light Purple & White Spaced Stripes","Peppermint Stripes",
        "Red & Black Spaced Stripes","Gothic Chic Stripes","Sugar Rush Stripes","Emerald Onyx Stripes",
        "Pumpkin Spice Stripes","Pink & White Spaced Stripes","All American Stripes",
        "Candy Cane Stripes","Blossom Breeze","White and Ice Blue Stripes","Christmas Festive Stripes",
        "White w/ Black stripes","Navy w/ White stripes","Cyan w/ White stripes",
        "Celtic Green and White Stripes","Twilight Pop","Black and Multicolor Stripes",
        "Black w/ Pink stripes","Black and Yellow Stripes","BHM","Solar Glow","Navy and Silver Stripes",
        "Cherry and White Stripes","Wheat and White Stripes","Brown w/ White stripes",
        "White and Green Stripes","Coral w/ White stripes","Imperial Purple and White Stripes",
        "Carolina Blue and White Stripes","Smoke Grey and White Stripes","Black w/ White stripes",
        "Bubble Gum and White Stripes","Dark Cherry and White Stripes","Hot Pink w/ White stripes",
        "Orange and Black Stripes","Black and Orange Stripes","Black w/Red stripes",
        "Smoke Grey w/Black Stripes","Royal Blue solid","Black w/Grey stripes","Black w/Purple stripes",
        "Black w/Rainbow Stripes","Black and Green Stripes","Heart Socks","Shamrock Socks",
        "Plum Solid","Pumpkin Solid","PCH","Cranberry Frost","Snowy Angel","Pats","Seahawks",
        "Black solid (THN)","White solid (THN)","Black w/ White stripes (THN)","Yellow (THN)",
        "Black w/Red stripes (THN)","Black w/Pink stripes (THN)","Hot Pink w/White stripes (THN)",
        "Black Solid (SHORT)","White Solid (SHORT)","Black and White Stripes (SHORT)"
    ]
    all_skus = set(retail_skus)
    for hub_list in hub_assignments.values():
        all_skus.update(hub_list)
    for sku in sorted(all_skus):
        assigned = [h for h, skus in hub_assignments.items() if sku in skus]
        if sku in retail_skus:
            assigned.append("Retail")
        assigned = sorted(set(assigned))
        query("INSERT OR REPLACE INTO sku_info (sku, product_name, assigned_hubs) VALUES (?,?,?)",
              (sku, sku, ",".join(assigned)), fetch=False, commit=True)
        for h in assigned:
            query("INSERT OR IGNORE INTO inventory (sku, hub, quantity) VALUES (?,?,?)",
                  (sku, h, 0), fetch=False, commit=True)

def seed_sku_inventory_if_empty():
    rows = query("SELECT COUNT(*) FROM sku_info")
    if rows and rows[0][0] == 0:
        _seed_all_skus()

ensure_sku_inventory_schemas()
seed_sku_inventory_if_empty()
create_indices()  # run again now that tables exist

# ===== Section 7: Inventory (clean Hubs UI + list + IN/OUT + transfer + count)
def _hub_stats() -> pd.DataFrame:
    rows = query("""
        SELECT hub, COUNT(DISTINCT sku) AS sku_count, COALESCE(SUM(quantity), 0) AS total_qty
        FROM inventory
        GROUP BY hub
        ORDER BY hub
    """)
    return pd.DataFrame(rows, columns=["hub", "sku_count", "total_qty"])

def _hubs_list() -> List[str]:
    rows = query("""
        SELECT hub FROM (
          SELECT DISTINCT hub FROM users WHERE hub IS NOT NULL
          UNION
          SELECT DISTINCT hub FROM inventory WHERE hub IS NOT NULL
        )
        WHERE TRIM(hub) <> ''
        ORDER BY hub
    """)
    return [r[0] for r in rows]

def _hub_options_for(role: str, user_hub: Optional[str]) -> List[str]:
    hubs = _hubs_list()
    if (role or "").lower() == "admin":
        return (["All hubs"] + hubs) if hubs else ["All hubs"]
    if user_hub and user_hub in hubs:
        return [user_hub]
    return hubs[:1] if hubs else []

def _format_hub_option(opt: str, stats: Dict[str, Tuple[int, int]]) -> str:
    if opt == "All hubs":
        total_skus = sum(v[0] for v in stats.values()) if stats else 0
        total_qty  = sum(v[1] for v in stats.values()) if stats else 0
        return f"All hubs — {total_skus} SKUs · {total_qty} pcs"
    if opt in stats:
        skus, qty = stats[opt]
        return f"{opt} — {skus} SKUs · {qty} pcs"
    return opt

def render_hub_selector(username: str, role: str, user_hub: Optional[str]) -> Tuple[Optional[str], str]:
    stats_df = _hub_stats()
    stats = {r.hub: (int(r.sku_count), int(r.total_qty)) for _, r in stats_df.iterrows()}
    opts = _hub_options_for(role, user_hub)
    if not opts:
        st.warning("No hubs yet. Add inventory or assign a hub to your user.")
        return (None, "No hub")
    index = 0
    if user_hub and user_hub in opts:
        index = opts.index(user_hub)
    nice_opts = [_format_hub_option(o, stats) for o in opts]
    with st.container():
        c1, c2 = st.columns([1, 6])
        with c1: st.caption("Hub")
        with c2:
            sel_nice = st.radio("Choose hub", nice_opts, index=index, horizontal=True, label_visibility="collapsed")
    raw = opts[nice_opts.index(sel_nice)]
    selected_hub = None if raw == "All hubs" else raw

    if selected_hub:
        skus, qty = stats.get(selected_hub, (0, 0))
        chip = f"{selected_hub} · {skus} SKUs · {qty} pcs"
    else:
        tot_skus = sum(v[0] for v in stats.values()); tot_qty  = sum(v[1] for v in stats.values())
        chip = f"All hubs · {tot_skus} SKUs · {tot_qty} pcs"
    st.markdown(
        f"""<div style="display:inline-block;padding:.35rem .6rem;border-radius:999px;background:#1f2937;color:#e5e7eb;font-size:0.85rem;margin-bottom:.5rem;">{chip}</div>""",
        unsafe_allow_html=True,
    )
    with st.expander("Hub overview", expanded=False):
        if stats_df.empty:
            st.info("No inventory yet.")
        else:
            st.dataframe(stats_df.rename(columns={"hub":"Hub","sku_count":"SKUs","total_qty":"On hand"}),
                         use_container_width=True, hide_index=True)
    return (selected_hub, raw)

def _inventory_df_for(role: str, selected_hub: Optional[str]) -> pd.DataFrame:
    if (role or "").lower() == "admin" and selected_hub is None:
        rows = query("SELECT sku, hub, quantity FROM inventory ORDER BY hub, sku")
    else:
        rows = query("SELECT sku, hub, quantity FROM inventory WHERE hub=? ORDER BY sku", (selected_hub,))
    return pd.DataFrame(rows, columns=["SKU", "Hub", "Qty"])

def _skus_for_scope(selected_hub: Optional[str], admin_all: bool) -> List[str]:
    if admin_all:
        rows = query("SELECT DISTINCT sku FROM inventory ORDER BY sku")
    else:
        rows = query("SELECT DISTINCT sku FROM inventory WHERE hub=? ORDER BY sku", (selected_hub,))
    return [r[0] for r in rows]

def inventory_page(username: str, role: str, user_hub: Optional[str]):
    if (role or "").lower() == "supplier":
        st.info("Suppliers do not have access to Inventory. Use Home to create shipments.")
        return

    st.header("📦 Inventory")
    selected_hub, _ = render_hub_selector(username, role, user_hub)
    is_admin_user = is_admin(role)
    admin_all = is_admin_user and selected_hub is None

    df = _inventory_df_for(role, selected_hub if not admin_all else None)
    with st.container():
        colf = st.columns([2,1,1])
        with colf[0]:
            ftext = st.text_input("Filter by SKU", "", placeholder="Type to filter…")
        if ftext:
            df = df[df["SKU"].str.contains(ftext, case=False, na=False)]
        st.dataframe(df, use_container_width=True, height=380)
        st.download_button("Export inventory.csv", df.to_csv(index=False).encode("utf-8"), "inventory.csv", "text/csv")

    if is_admin_user:
        with st.expander("Totals by SKU (Admin)", expanded=False):
            totals = df.groupby("SKU", as_index=False)["Qty"].sum().sort_values("SKU")
            st.dataframe(totals, use_container_width=True, height=320)
            st.download_button("Export totals.csv", totals.to_csv(index=False).encode("utf-8"), "inventory_totals.csv", "text/csv")

    st.divider()
    st.subheader("Quick Adjust (IN / OUT)")
    with st.form("inout_form", clear_on_submit=False):
        c1, c2, c3, c4 = st.columns([3,1,1,3])
        skus = _skus_for_scope(selected_hub, admin_all)
        with c1:
            sel_sku = st.selectbox("SKU", options=skus, index=0 if skus else None, placeholder="Select a SKU")
        with c2:
            action = st.selectbox("Action", ["IN", "OUT"])
        with c3:
            qty = st.number_input("Qty", min_value=1, step=1, value=1)
        with c4:
            if admin_all:
                hubs = _hubs_list()
                sel_hub_for_txn = st.selectbox("Hub", options=hubs, index=0 if hubs else None, placeholder="Choose hub")
            else:
                sel_hub_for_txn = selected_hub
                st.text_input("Hub", value=sel_hub_for_txn or "", disabled=True)
        comment = st.text_input("Comment (optional)", "")
        submitted = st.form_submit_button("Submit")

    if submitted:
        if not sel_sku:
            st.warning("Pick a SKU."); return
        if not sel_hub_for_txn:
            st.warning("Pick a hub."); return
        row = query("SELECT quantity FROM inventory WHERE sku=? AND hub=?", (sel_sku, sel_hub_for_txn))
        current = int(row[0][0]) if row else 0
        if action == "OUT" and qty > current:
            st.warning(f"Not enough stock to remove {qty}. Current: {current}"); return
        new_qty = current + qty if action == "IN" else current - qty
        query("""
            INSERT INTO inventory (sku, hub, quantity) VALUES (?, ?, ?)
            ON CONFLICT(sku, hub) DO UPDATE SET quantity=excluded.quantity
        """, (sel_sku, sel_hub_for_txn, new_qty), fetch=False, commit=True)
        try:
            query("INSERT INTO logs (timestamp,user,sku,hub,action,qty,comment) VALUES (?,?,?,?,?,?,?)",
                  (_now_iso(), username, sel_sku, sel_hub_for_txn, action, qty, comment),
                  fetch=False, commit=True)
        except Exception:
            pass
        st.success(f"Updated {sel_sku} @ {sel_hub_for_txn}: {action} {qty} → New Qty {new_qty}")
        st.rerun()

    if is_admin_user:
        st.divider()
        with st.expander("🔁 Transfer between hubs (Admin)", expanded=False):
            hubs_all = _hubs_list()
            tcols = st.columns(5)
            src = tcols[0].selectbox("From hub", hubs_all, key="t_src")
            dst = tcols[1].selectbox("To hub", [h for h in hubs_all if h != src], key="t_dst")
            sku_t = tcols[2].selectbox("SKU", [r[0] for r in query("SELECT DISTINCT sku FROM inventory ORDER BY sku")], key="t_sku")
            qty_t = tcols[3].number_input("Qty", min_value=1, step=1, value=1, key="t_qty")
            note_t = tcols[4].text_input("Note", key="t_note")
            if st.button("Execute transfer"):
                src_row = query("SELECT quantity FROM inventory WHERE sku=? AND hub=?", (sku_t, src))
                src_qty = int(src_row[0][0]) if src_row else 0
                if qty_t > src_qty:
                    st.error(f"Not enough at source ({src_qty}).")
                else:
                    query("""
                        INSERT INTO inventory (sku, hub, quantity) VALUES (?, ?, ?)
                        ON CONFLICT(sku, hub) DO UPDATE SET quantity=excluded.quantity
                    """, (sku_t, src, src_qty - qty_t), fetch=False, commit=True)
                    dst_row = query("SELECT quantity FROM inventory WHERE sku=? AND hub=?", (sku_t, dst))
                    dst_qty = int(dst_row[0][0]) if dst_row else 0
                    query("""
                        INSERT INTO inventory (sku, hub, quantity) VALUES (?, ?, ?)
                        ON CONFLICT(sku, hub) DO UPDATE SET quantity=excluded.quantity
                    """, (sku_t, dst, dst_qty + qty_t), fetch=False, commit=True)
                    try:
                        query("INSERT INTO logs (timestamp,user,sku,hub,action,qty,comment) VALUES (?,?,?,?,?,?,?)",
                              (_now_iso(), username, sku_t, src, "OUT", qty_t, f"transfer to {dst} | {note_t}"),
                              fetch=False, commit=True)
                        query("INSERT INTO logs (timestamp,user,sku,hub,action,qty,comment) VALUES (?,?,?,?,?,?,?)",
                              (_now_iso(), username, sku_t, dst, "IN", qty_t, f"transfer from {src} | {note_t}"),
                              fetch=False, commit=True)
                    except Exception:
                        pass
                    st.success(f"Transferred {qty_t} of {sku_t}: {src} → {dst}")
                    st.rerun()

    with st.expander("🧮 Cycle Count (Lite)", expanded=False):
        cc_cols = st.columns(4)
        cc_hub = selected_hub if not admin_all else cc_cols[0].selectbox("Hub", _hubs_list())
        cc_sku = cc_cols[1].selectbox("SKU", _skus_for_scope(cc_hub, False) if cc_hub else [])
        current_row = query("SELECT quantity FROM inventory WHERE sku=? AND hub=?", (cc_sku, cc_hub)) if cc_hub and cc_sku else [(0,)]
        current_qty = int(current_row[0][0]) if current_row else 0
        cc_cols[2].metric("Current", current_qty)
        counted = cc_cols[3].number_input("Counted qty", min_value=0, step=1, value=current_qty)
        reason = st.text_input("Reason (optional)")
        if st.button("Apply count"):
            if not cc_hub or not cc_sku:
                st.warning("Select hub and SKU."); 
            else:
                query("""
                    INSERT INTO inventory (sku, hub, quantity) VALUES (?, ?, ?)
                    ON CONFLICT(sku, hub) DO UPDATE SET quantity=excluded.quantity
                """, (cc_sku, cc_hub, int(counted)), fetch=False, commit=True)
                variance = int(counted) - current_qty
                try:
                    query("INSERT INTO logs (timestamp,user,sku,hub,action,qty,comment) VALUES (?,?,?,?,?,?,?)",
                          (_now_iso(), username, cc_sku, cc_hub, "COUNT_ADJUST", variance, reason or ""),
                          fetch=False, commit=True)
                except Exception:
                    pass
                st.success(f"Count applied. Variance: {variance:+d}")
                st.rerun()

# --- Main app -----------------------------------------------------------------
def main():
    st.set_page_config(page_title="KISS Inventory", layout="wide")
    st.sidebar.caption("ET")
    st.sidebar.caption(fmt_ts_et(_now_iso()))
    st.sidebar.caption(f" {APP_VERSION}")

    st.title("KISS Inventory")
    st.caption("Keep It Simple Socks — Inventory & Ops")

    # auth gate
    user = st.session_state.get("auth_user")
    if not user:
        login_form()
        st.stop()

    username, role, hub = user
    coltop = st.columns([3,1])
    with coltop[0]:
        st.success(f"Welcome, **{username}** ({role}{' — '+hub if hub else ''})")
        last = last_login_for(username)
        if last:
            st.caption(f"Last sign-in: {last}")
    with coltop[1]:
        if st.button("Log out"):
            logout(); st.rerun()

    # Sidebar nav based on role
    unread = unread_count(username)
    msgs_label = f"Messages 📬 ({unread})" if unread else "Messages 📬"

    nav_items = ["Home", msgs_label]
    if (role or "").lower() != "supplier":
        nav_items.insert(1, "Inventory")
    if is_admin(role):
        nav_items += ["Logs", "Admin"]

    nav = st.sidebar.radio("Navigate", nav_items, index=0)

    if nav == "Inventory":
        inventory_page(username, role, hub); st.stop()
    if nav == msgs_label:
        messaging_page(username, role, hub); st.stop()
    if nav == "Logs" and is_admin(role):
        admin_logs_page(role); st.stop()
    if nav == "Admin" and is_admin(role):
        admin_page(role); st.stop()

    # Homes
    if is_admin(role):
        admin_home_page()
    elif (role or "").lower() == "supplier":
        supplier_home_page(username)
    else:
        hub_home_page(username, hub)

# Make sure this is at the very end of app.py, not inside any function
if __name__ == "__main__":
    main()
