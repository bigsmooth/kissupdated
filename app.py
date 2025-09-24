import streamlit as st
import sqlite3
import pandas as pd
from datetime import datetime
from pathlib import Path
import hashlib
import io

# --- Language Translations (English/Chinese) ---
if "lang" not in st.session_state:
    st.session_state["lang"] = "en"
lang = st.sidebar.selectbox("🌐 Language", ["English", "中文"], index=0 if st.session_state["lang"]=="en" else 1)
st.session_state["lang"] = "en" if lang=="English" else "zh"

translations = {
    "en": {
        "supplier_shipments": "🚚 Supplier Shipments",
        "add_skus": "Add one or more SKUs for this shipment.",
        "tracking_number": "Tracking Number",
        "carrier": "Carrier Name",
        "destination_hub": "Destination Hub",
        "shipping_date": "Shipping Date",
        "sku": "SKU",
        "qty": "Qty",
        "remove": "Remove",
        "add_another_sku": "Add Another SKU",
        "create_new_sku": "➕ Create New SKU",
        "new_sku_name": "New SKU Name",
        "add_sku": "Add SKU",
        "submit_shipment": "Submit Shipment",
        "shipment_submitted": "Shipment submitted successfully!",
        "fill_out_required": "Please fill out all required fields and SKUs.",
        "your_shipments": "📦 Your Shipments",
        "no_shipments": "You have not submitted any shipments yet.",
        "incoming_shipments": "📦 Incoming Shipments to Your Hub",
        "mark_received": "Mark Shipment as Received",
        "confirm_receipt": "Confirm receipt of shipment",
        "delete_shipment": "Delete Shipment",
        "confirm_delete": "Confirm delete shipment",
        "shipment_deleted": "Shipment deleted.",
        "shipment_confirmed": "Shipment confirmed received and inventory updated.",
        "restock_orders": "🔄 Restock Orders",
        "create_user": "➕ Create User",
        "user_created": "User created successfully!",
        "select_user": "Select User",
        "remove_user": "Remove User",
        "confirm_remove_user": "Really remove",
        "user_removed": "User removed.",
        "backup": "🗄️ Backup Database",
        "restore": "🔄 Restore Database",
        "download_backup": "Download Backup CSV",
        "upload_csv": "Upload CSV for Restore",
        "count_confirmed": "Count confirmed.",
        "refresh": "Refresh",
        "update_inventory": "Update Inventory",
        "select_sku": "Select SKU",
        "action": "Action",
        "quantity": "Quantity",
        "optional_comment": "Optional Comment",
        "submit_update": "Submit Update",
        "bulk_update": "Bulk Inventory Update",
        "adjust_quantity": "Adjust Quantity (+IN / -OUT)",
        "comment": "Comment",
        "apply_updates": "Apply All Updates",
        "sku_exists": "SKU already exists!",
        "enter_sku_name": "Please enter a SKU name.",
        "create_sku": "Create SKU",
        "upload_skus": "Upload SKUs from CSV",
        "assign_skus": "Assign SKUs to Hubs",
        "select_sku_assign": "Select SKU to Assign",
        "assign_to_hubs": "Assign to Hubs",
        "update_assignments": "Update Assignments",
        "assignment_updated": "SKU assignment updated!",
        "manage_users": "Manage Users",
        "username": "Username",
        "role": "Role",
        "hub": "Hub",
        "send_message": "Send Message",
        "to": "To",
        "subject": "Subject",
        "message": "Message",
        "send": "Send",
        "your_threads": "Your Threads",
        "reply": "Reply",
        "send_reply": "Send Reply",
        "only_reply_hq": "Only reply to HQ is allowed.",
        "activity_logs": "Activity Logs",
        "filter_logs": "Filter logs",
        "inventory_count_mode": "Inventory Count Mode",
        "confirmed_counts": "Confirmed Counts",
        "export_inventory": "Export Inventory",
    },
    "zh": {
        "supplier_shipments": "🚚 供应商发货",
        "add_skus": "为此发货添加一个或多个SKU。",
        "tracking_number": "追踪号码",
        "carrier": "承运人名称",
        "destination_hub": "目的中心",
        "shipping_date": "发货日期",
        "sku": "SKU",
        "qty": "数量",
        "remove": "移除",
        "add_another_sku": "添加另一个SKU",
        "create_new_sku": "➕ 新建SKU",
        "new_sku_name": "新SKU名称",
        "add_sku": "添加SKU",
        "submit_shipment": "提交发货",
        "shipment_submitted": "发货已成功提交！",
        "fill_out_required": "请填写所有必填字段和SKU。",
        "your_shipments": "📦 您的发货记录",
        "no_shipments": "您还没有提交任何发货。",
        "incoming_shipments": "📦 您中心的待发货记录",
        "mark_received": "标记发货为已收到",
        "confirm_receipt": "确认收货",
        "delete_shipment": "删除发货",
        "confirm_delete": "确认删除发货",
        "shipment_deleted": "发货已删除。",
        "shipment_confirmed": "发货已确认收到，库存已更新。",
        "restock_orders": "🔄 补货订单",
        "create_user": "➕ 创建用户",
        "user_created": "用户创建成功！",
        "select_user": "选择用户",
        "remove_user": "删除用户",
        "confirm_remove_user": "确认删除",
        "user_removed": "用户已删除。",
        "backup": "🗄️ 数据库备份",
        "restore": "🔄 数据库恢复",
        "download_backup": "下载备份CSV",
        "upload_csv": "上传CSV以恢复",
        "count_confirmed": "库存盘点已确认。",
        "refresh": "刷新",
        "update_inventory": "更新库存",
        "select_sku": "选择SKU",
        "action": "操作",
        "quantity": "数量",
        "optional_comment": "可选备注",
        "submit_update": "提交更新",
        "bulk_update": "批量库存更新",
        "adjust_quantity": "调整数量（+入库 / -出库）",
        "comment": "备注",
        "apply_updates": "应用所有更新",
        "sku_exists": "SKU已存在！",
        "enter_sku_name": "请输入SKU名称。",
        "create_sku": "创建SKU",
        "upload_skus": "从CSV上传SKU",
        "assign_skus": "分配SKU到仓库",
        "select_sku_assign": "选择要分配的SKU",
        "assign_to_hubs": "分配到仓库",
        "update_assignments": "更新分配",
        "assignment_updated": "SKU分配已更新！",
        "manage_users": "管理用户",
        "username": "用户名",
        "role": "角色",
        "hub": "仓库",
        "send_message": "发送消息",
        "to": "收件人",
        "subject": "主题",
        "message": "消息",
        "send": "发送",
        "your_threads": "您的会话",
        "reply": "回复",
        "send_reply": "发送回复",
        "only_reply_hq": "只能回复总部。",
        "activity_logs": "活动日志",
        "filter_logs": "筛选日志",
        "inventory_count_mode": "库存盘点模式",
        "confirmed_counts": "已确认盘点",
        "export_inventory": "导出库存",
    }
}

def T(key): return translations[st.session_state["lang"]].get(key, key)
import os
DB = Path(os.getenv("TTT_DB_PATH", Path(__file__).parent / "ttt_inventory.db"))

# --- Safety: backup the SQLite DB before destructive operations ---
from datetime import datetime
import shutil
def backup_db() -> Path:
    try:
        db_path = Path(DB)
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        backup = db_path.with_name(f"{db_path.stem}-{ts}{db_path.suffix}")
        shutil.copy2(db_path, backup)
        return backup
    except Exception as e:
        return None



# --- Password hashing helpers (bcrypt with SHA-256 fallback for legacy rows) ---
try:
    import bcrypt
except Exception:
    bcrypt = None

def hash_password(pw: str) -> str:
    """
    Preferred hash: bcrypt. Fallback to sha256 hex if bcrypt unavailable.
    """
    if bcrypt:
        return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()
    import hashlib
    return hashlib.sha256(pw.encode()).hexdigest()

def verify_password(plain: str, stored: str) -> bool:
    """
    Accept both bcrypt hashes and legacy sha256 hex. If sha256 matches and bcrypt is available,
    upgrade the row to bcrypt at next successful login (done in login()).
    """
    if stored and stored.startswith("$2b$"):
        if not bcrypt:
            return False
        try:
            return bcrypt.checkpw(plain.encode(), stored.encode())
        except Exception:
            return False
    # legacy sha256 hex (64 chars, hex)
    import re, hashlib
    if re.fullmatch(r"[0-9a-f]{64}", stored):
        return hashlib.sha256(plain.encode()).hexdigest() == stored
    # unknown format
    return False
def query(sql, params=(), fetch=True, commit=True):
    with sqlite3.connect(DB) as conn:
        cur = conn.cursor()
        cur.execute(sql, params)
        if commit: conn.commit()
        return cur.fetchall() if fetch else None    

# --- Seed Data (SKUs & Users) ---
def seed_all_skus():
    hub_assignments = {
        "Hub 1": ["All American Stripes", "Carolina Blue and White Stripes", "Navy and Silver Stripes",
                  "Black and Hot Pink Stripes", "Bubble Gum and White Stripes", "White and Ice Blue Stripes",
                  "Imperial Purple and White Stripes", "Hot Pink and White Stripes", "Rainbow Stripes",
                  "Twilight Pop", "Juicy Purple", "Lovely Lilac", "Black", "Black and White Stripes"],
        "Hub 2": ["Black and Yellow Stripes", "Orange and Black Stripes", "Black and Purple Stripes",
                  "Black and Orange Stripes", "Electric Blue and White Stripes", "Blossom Breeze", "Candy Cane Stripes",
                  "Plum Solid", "Patriots (Custom)", "Snow Angel (Custom)", "Cranberry Frost (Custom)", "Witchy Vibes",
                  "White and Green Stripes", "Black Solid", "Black and White Stripes"],
        "Hub 3": ["Black and Grey Stripes", "Black and Green Stripes", "Smoke Grey and Black Stripes",
                  "Black and Red Stripes", "Black and Purple", "Dark Cherry and White Stripes", "Black and Multicolor Stripes",
                  "Puerto Rican (Custom)", "Seahawks (Custom)", "PCH (Custom)", "Valentine Socks",
                  "Rainbow Stripes", "Thin Black Socks", "Thin Black and White Stripes", "Smoke Grey Solid", "Cherry Solid",
                  "Brown Solid", "Wheat and White Stripes", "Black Solid", "Black and White Stripes"]
    }
    retail_skus = [
        "Black Solid", "Bubblegum", "Tan Solid", "Hot Pink Solid", "Brown Solid", "Dark Cherry Solid",
        "Winter White Solid", "Coral Orange", "Navy Solid", "Electric Blue Solid", "Celtic Green",
        "Cherry Solid", "Smoke Grey Solid", "Chartreuse Green", "Lovely Lilac", "Carolina Blue Solid",
        "Juicy Purple", "Green & Red Spaced Stripes", "Winter Green Stripes", "Midnight Frost Stripes",
        "Witchy Vibes Stripes", "Light Purple & White Spaced Stripes", "Peppermint Stripes",
        "Red & Black Spaced Stripes", "Gothic Chic Stripes", "Sugar Rush Stripes", "Emerald Onyx Stripes",
        "Pumpkin Spice Stripes", "Pink & White Spaced Stripes", "All American Stripes",
        "Candy Cane Stripes", "Blossom Breeze", "White and Ice Blue Stripes", "Christmas Festive Stripes",
        "White w/ Black stripes", "Navy w/ White stripes", "Cyan w/ White stripes",
        "Celtic Green and White Stripes", "Twilight Pop", "Black and Multicolor Stripes",
        "Black w/ Pink stripes", "Black and Yellow Stripes", "BHM", "Solar Glow", "Navy and Silver Stripes",
        "Cherry and White Stripes", "Wheat and White Stripes", "Brown w/ White stripes",
        "White and Green Stripes", "Coral w/ White stripes", "Imperial Purple and White Stripes",
        "Carolina Blue and White Stripes", "Smoke Grey and White Stripes", "Black w/ White stripes",
        "Bubble Gum and White Stripes", "Dark Cherry and White Stripes", "Hot Pink w/ White stripes",
        "Orange and Black Stripes", "Black and Orange Stripes", "Black w/Red stripes",
        "Smoke Grey w/Black Stripes", "Royal Blue solid", "Black w/Grey stripes", "Black w/Purple stripes",
        "Black w/Rainbow Stripes", "Black and Green Stripes", "Heart Socks", "Shamrock Socks",
        "Plum Solid", "Pumpkin Solid", "PCH", "Cranberry Frost", "Snowy Angel", "Pats", "Seahawks",
        "Black solid (THN)", "White solid (THN)", "Black w/ White stripes (THN)", "Yellow (THN)",
        "Black w/Red stripes (THN)", "Black w/Pink stripes (THN)", "Hot Pink w/White stripes (THN)",
        "Black Solid (SHORT)", "White Solid (SHORT)", "Black and White Stripes (SHORT)"
    ]
    all_skus = set(retail_skus)
    for hub_list in hub_assignments.values():
        all_skus.update(hub_list)
    for sku in sorted(all_skus):
        assigned = [hub for hub, skus in hub_assignments.items() if sku in skus]
        if sku in retail_skus:
            assigned.append("Retail")
        query(
            "INSERT OR REPLACE INTO sku_info (sku, product_name, assigned_hubs) VALUES (?, ?, ?)",
            (sku, sku, ",".join(sorted(set(assigned)))),
            fetch=False,
            commit=True
        )
        for h in assigned:
            query(
                "INSERT OR IGNORE INTO inventory (sku, hub, quantity) VALUES (?, ?, ?)",
                (sku, h, 0),
                fetch=False,
                commit=True
            )

def seed_users():
    users = [
        ("kevin", "Admin", "HQ", "adminpass"),
        ("fox", "Hub Manager", "Hub 2", "foxpass"),
        ("smooth", "Retail", "Retail", "retailpass"),
        ("carmen", "Hub Manager", "Hub 3", "hub3pass"),
        ("slo", "Hub Manager", "Hub 1", "hub1pass"),
        ("angie", "Supplier", "", "shipit")
    ]
    for u, r, h, p in users:
        pw = hash_password(p)
        query(
            "INSERT OR IGNORE INTO users (username, password, role, hub) VALUES (?, ?, ?, ?)",
            (u, pw, r, h),
            fetch=False,
            commit=True
        )

def create_tables():
    query("""CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        password TEXT,
        role TEXT,
        hub TEXT)""", fetch=False, commit=True)
    query("""CREATE TABLE IF NOT EXISTS inventory (
        sku TEXT,
        hub TEXT,
        quantity INTEGER,
        PRIMARY KEY (sku, hub))""", fetch=False, commit=True)
    query("""CREATE TABLE IF NOT EXISTS logs (
        timestamp TEXT,
        user TEXT,
        sku TEXT,
        hub TEXT,
        action TEXT,
        qty INTEGER,
        comment TEXT)""", fetch=False, commit=True)
    query("""CREATE TABLE IF NOT EXISTS sku_info (
        sku TEXT PRIMARY KEY,
        product_name TEXT,
        assigned_hubs TEXT)""", fetch=False, commit=True)
    query("""CREATE TABLE IF NOT EXISTS shipments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        supplier TEXT,
        tracking TEXT,
        carrier TEXT,
        hub TEXT,
        skus TEXT,
        date TEXT,
        status TEXT)""", fetch=False, commit=True)
    query("""CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender TEXT,
        receiver TEXT,
        message TEXT,
        thread TEXT,
        timestamp TEXT)""", fetch=False, commit=True)
    query("""CREATE TABLE IF NOT EXISTS count_confirmations (
        username TEXT,
        hub TEXT,
        confirmed_at TEXT)""", fetch=False, commit=True)

def setup_db():
    create_tables()
    existing = query("SELECT sku FROM sku_info LIMIT 1")
    if not existing: seed_all_skus()
    seed_users()

if not DB.exists():
    setup_db()
else:
    create_tables()
    seed_users()

def login(username, password):
    # fetch stored hash
    row = query("SELECT username, password, role, hub FROM users WHERE username=?", (username,))
    if not row:
        return None
    uname, stored_hash, role, hub = row[0]
    if verify_password(password, stored_hash):
        # Upgrade legacy sha256 to bcrypt transparently
        if bcrypt and (not stored_hash.startswith("$2b$")):
            try:
                new_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
                query("UPDATE users SET password=? WHERE username=?", (new_hash, username), fetch=False, commit=True)
            except Exception:
                pass
        return (uname, role, hub)
    return None

def count_unread(username):
    threads = query("SELECT DISTINCT thread FROM messages WHERE receiver=?", (username,))
    unread = 0
    for t in threads:
        last_msg = query(
            "SELECT sender FROM messages WHERE thread=? ORDER BY timestamp DESC LIMIT 1",
            (t[0],)
        )
        if last_msg and last_msg[0][0] != username:
            unread += 1
    return unread

# --- Login Screen ---
if "user" not in st.session_state:
    st.sidebar.title("🔐 Login")
    u = st.sidebar.text_input("Username", key="login_user")
    p = st.sidebar.text_input("Password", type="password", key="login_pw")
    if st.sidebar.button("Login", key="login_btn"):
        user = login(u, p)
        if user:
            st.session_state.user = user
            st.rerun()
        else:
            st.sidebar.error("Invalid credentials")
    st.stop()

username, role, hub = st.session_state.user
unread = count_unread(username)
st.sidebar.success(f"Welcome, {username} ({role})")
st.sidebar.markdown(f"📨 **Unread Threads: {unread}**")
if st.sidebar.button("🚪 Logout", key=f"logout_btn_{username}"):
    del st.session_state.user
    st.rerun()

# --- Define ALL menus and logic exactly as in your latest working code, using unique keys for every Streamlit element. ---

menus = {
    "Admin": [
        "Inventory", "Logs", "Shipments", "Messages", "Count", "Assign SKUs",
        "Create SKU", "Upload SKUs", "User Access", "Create User",
        "Backup", "Restore", "Google Sheets"
    ],
    "Hub Manager": [
        "Inventory", "Update Stock", "Bulk Update", "Messages", "Count", "Incoming Shipments", "Google Sheets"
    ],
    "Retail": [
        "Inventory", "Update Stock", "Bulk Update", "Messages", "Count", "Google Sheets"
    ],
    "Supplier": [
        "Shipments"
    ]
}

menu = st.sidebar.radio("Menu", menus[role], key="menu_radio")


# --- User Access ---
if menu == "User Access" and role == "Admin":
    st.header(T("manage_users"))
    users = query("SELECT username, role, hub FROM users")
    df_users = pd.DataFrame(users, columns=[T("username"), T("role"), T("hub")])
    st.dataframe(df_users, use_container_width=True, key="user_access_df")

    st.subheader(T("remove_user"))
    user_list = [u[0] for u in query("SELECT username FROM users WHERE username != ?", (username,))]
    selected_user = st.selectbox(T("select_user"), user_list, key="remove_user_select")
    if st.button(T("remove_user"), key="btn_remove_user"):
        st.session_state['confirm_remove_user'] = selected_user

    if st.session_state.get('confirm_remove_user') == selected_user:
        if st.button(f"{T('confirm_remove_user')} {selected_user}?", key="btn_confirm_remove"):
            query("DELETE FROM users WHERE username=?", (selected_user,), fetch=False, commit=True)
            st.success(f"✅ {T('user_removed')}")
            st.session_state.pop('confirm_remove_user')
            st.rerun()

# --- Create SKU ---
if menu == "Create SKU" and role == "Admin":
    st.header(T("create_new_sku"))
    new_sku = st.text_input(T("new_sku_name"), key="create_sku_name")
    hubs = st.multiselect(T("assign_to_hubs"), ["Hub 1", "Hub 2", "Hub 3", "Retail"], key="create_sku_hubs")
    if st.button(T("create_sku"), key="btn_create_sku"):
        if not new_sku.strip():
            st.warning(T("enter_sku_name"))
        elif not hubs:
            st.warning("❗ Please assign at least one hub.")
        else:
            exists = query("SELECT sku FROM sku_info WHERE sku=?", (new_sku.strip(),))
            if exists:
                st.warning(T("sku_exists"))
            else:
                hubs_str = ",".join(hubs)
                query(
                    "INSERT INTO sku_info (sku, product_name, assigned_hubs) VALUES (?, ?, ?)",
                    (new_sku.strip(), new_sku.strip(), hubs_str),
                    fetch=False,
                    commit=True
                )
                for h in hubs:
                    query(
                        "INSERT OR IGNORE INTO inventory (sku, hub, quantity) VALUES (?, ?, ?)",
                        (new_sku.strip(), h, 0),
                        fetch=False,
                        commit=True
                    )
                st.success(f"✅ SKU '{new_sku}' created and assigned!")
                st.rerun()

# --- Upload SKUs ---
if menu == "Upload SKUs" and role == "Admin":
    st.header(T("upload_skus"))
    uploaded_file = st.file_uploader(T("upload_csv"), type="csv", key="upload_sku_file")
    if uploaded_file is not None:
        try:
            df = pd.read_csv(uploaded_file)
            if df.empty:
                st.warning("CSV is empty.")
            else:
                inserted_count = 0
                for _, row in df.iterrows():
                    sku = str(row['sku']).strip()
                    product_name = str(row.get('product_name', sku)).strip()
                    assigned_hubs = str(row.get('assigned_hubs', 'Retail')).strip()
                    if sku:
                        query(
                            "INSERT OR IGNORE INTO sku_info (sku, product_name, assigned_hubs) VALUES (?, ?, ?)",
                            (sku, product_name, assigned_hubs),
                            fetch=False,
                            commit=True
                        )
                        for h in assigned_hubs.split(","):
                            query(
                                "INSERT OR IGNORE INTO inventory (sku, hub, quantity) VALUES (?, ?, ?)",
                                (sku, h.strip(), 0),
                                fetch=False,
                                commit=True
                            )
                        inserted_count += 1
                st.success(f"Uploaded {inserted_count} SKUs!")
                st.rerun()
        except Exception as e:
            st.error(f"Upload error: {e}")

# --- Assign SKUs ---
if menu == "Assign SKUs" and role == "Admin":
    st.header(T("assign_skus"))
    skus = [s[0] for s in query("SELECT sku FROM sku_info")]
    sku_choice = st.selectbox(T("select_sku_assign"), skus, key="assign_sku_select")
    hubs = ["Hub 1", "Hub 2", "Hub 3", "Retail"]
    assigned = query("SELECT assigned_hubs FROM sku_info WHERE sku=?", (sku_choice,))
    current = assigned[0][0].split(",") if assigned and assigned[0][0] else []
    new_hubs = st.multiselect(T("assign_to_hubs"), hubs, default=current, key="assign_hubs_multiselect")
    if st.button(T("update_assignments"), key="btn_update_assignments"):
        combined = ",".join(new_hubs)
        query("UPDATE sku_info SET assigned_hubs=? WHERE sku=?", (combined, sku_choice), fetch=False, commit=True)
        for h in new_hubs:
            query(
                "INSERT OR IGNORE INTO inventory (sku, hub, quantity) VALUES (?, ?, ?)",
                (sku_choice, h, 0),
                fetch=False,
                commit=True
            )
        st.success(T("assignment_updated"))
        st.rerun()

# --- Create User ---
if menu == "Create User" and role == "Admin":
    st.header(T("create_user"))
    new_username = st.text_input(T("username"), key="create_user_name")
    new_password = st.text_input(T("password"), type="password", key="create_user_pw")
    new_role = st.selectbox(T("role"), ["Admin", "Hub Manager", "Retail", "Supplier"], key="create_user_role")
    if new_role == "Hub Manager":
        new_hub = st.selectbox(T("hub"), ["Hub 1", "Hub 2", "Hub 3"], key="create_user_hub")
    elif new_role == "Retail":
        new_hub = "Retail"
    else:
        new_hub = ""
    if st.button(T("create_user"), key="btn_create_user"):
        if not new_username.strip() or not new_password.strip():
            st.warning("Please enter both username and password.")
        else:
            hashed_pw = hashlib.sha256(new_password.encode()).hexdigest()
            exists = query("SELECT username FROM users WHERE username=?", (new_username.strip(),))
            if exists:
                st.warning("User already exists!")
            else:
                query(
                    "INSERT INTO users (username, password, role, hub) VALUES (?, ?, ?, ?)",
                    (new_username.strip(), hashed_pw, new_role, new_hub),
                    fetch=False,
                    commit=True
                )
                st.success(f"✅ User '{new_username.strip()}' created successfully!")
                st.rerun()

# --- Backup ---
if menu == "Backup" and role == "Admin":
    st.header(T("backup"))
    st.write("Download CSV backups for all main tables.")
    tables = ["users", "inventory", "logs", "sku_info", "shipments", "messages", "count_confirmations"]
    for table in tables:
        rows = query(f"SELECT * FROM {table}")
        if not rows:
            st.info(f"No data in table '{table}' to backup.")
            continue
        cols_info = query(f"PRAGMA table_info({table})", fetch=True)
        columns = [col[1] for col in cols_info]
        df = pd.DataFrame(rows, columns=columns)
        csv_buffer = io.StringIO()
        df.to_csv(csv_buffer, index=False)
        csv_data = csv_buffer.getvalue()
        st.download_button(f"{T('download_backup')} '{table}'", csv_data, file_name=f"{table}_backup.csv", mime="text/csv", key=f"download_{table}")

# --- Restore ---
if menu == "Restore" and role == "Admin":
    st.header(T("restore"))
    st.write("Upload CSV files to restore data to tables. Upload one table at a time.")
    tables = ["users", "inventory", "logs", "sku_info", "shipments", "messages", "count_confirmations"]
    for tbl in tables:
        with st.expander(f"Restore '{tbl}'"):
            uploaded_file = st.file_uploader(f"Upload CSV for '{tbl}'", type="csv", key=f"restore_upload_{tbl}")
            if uploaded_file is not None:
                try:
                    df = pd.read_csv(uploaded_file)
                    if df.empty:
                        st.warning("Uploaded CSV is empty.")
                        continue
                    df.columns = df.columns.str.strip().str.lower()
                    df.rename(columns={"qty": "quantity"}, inplace=True)
                    allowed_columns = [col[1] for col in query(f"PRAGMA table_info({tbl})")]
                    df = df[[col for col in df.columns if col in allowed_columns]]
                    cols = ", ".join(df.columns)
                    placeholders = ", ".join(["?"] * len(df.columns))
                    inserted_count = 0
                    for _, row in df.iterrows():
                        values = tuple(row[col] for col in df.columns)
                        query(
                            f"INSERT OR REPLACE INTO {tbl} ({cols}) VALUES ({placeholders})",
                            values,
                            fetch=False,
                            commit=True
                        )
                        inserted_count += 1
                    st.success(f"Restored {inserted_count} records into '{tbl}'!")
                except Exception as e:
                    st.error(f"Error restoring table '{tbl}': {e}")

# (Other menus—Inventory, Update Stock, Bulk Update, Logs, Messages, etc.—remain as in the original script above, and use unique keys on every Streamlit element.)

# --- Inventory ---
if menu == "Inventory":
    st.header(T("export_inventory"))
    if role == "Admin":
        rows = query("SELECT sku, hub, quantity FROM inventory ORDER BY hub")
    else:
        rows = query("SELECT sku, hub, quantity FROM inventory WHERE hub=?", (hub,))
    df = pd.DataFrame(rows, columns=[T("sku"), T("hub"), T("qty")])
    df['Status'] = df[T("qty")].apply(lambda x: "🟥 Low" if x < 10 else "✅ OK")
    sku_filter = st.text_input(T("select_sku"), key="filter_by_sku")
    if sku_filter:
        df = df[df[T("sku")].str.contains(sku_filter, case=False)]
    st.dataframe(df, use_container_width=True, key="inventory_df")
    buff = io.StringIO()
    df.to_csv(buff, index=False)
    st.download_button(T("export_inventory"), buff.getvalue(), "inventory.csv", "text/csv", key="export_inventory_btn")

# --- Update Stock ---
if menu == "Update Stock":
    st.header(T("update_inventory"))
    options = query("SELECT sku FROM sku_info WHERE assigned_hubs LIKE ?", (f"%{hub}%",))
    sku_list = [o[0] for o in options]
    sku = st.selectbox(T("select_sku"), sku_list, key="update_sku_select")
    action = st.radio(T("action"), ["IN", "OUT"], key="update_action_radio")
    qty = st.number_input(T("quantity"), min_value=1, step=1, key="update_qty")
    comment = st.text_input(T("optional_comment"), key="update_comment")
    if st.button(T("submit_update"), key="btn_update_stock"):
        record = query("SELECT quantity FROM inventory WHERE sku=? AND hub=?", (sku, hub))
        current = record[0][0] if record else 0
        if action == "OUT" and qty > current:
            st.warning("❌ Not enough stock to remove that amount!")
        else:
            new_qty = current + qty if action == "IN" else current - qty
            query(
                """INSERT INTO inventory (sku, hub, quantity) VALUES (?, ?, ?)
                   ON CONFLICT(sku, hub) DO UPDATE SET quantity=excluded.quantity""",
                (sku, hub, new_qty),
                fetch=False,
                commit=True
            )
            query(
                "INSERT INTO logs VALUES (?, ?, ?, ?, ?, ?, ?)",
                (datetime.now().isoformat(), username, sku, hub, action, qty, comment),
                fetch=False,
                commit=True
            )
            st.success(
                f"✅ Inventory updated!  \n**SKU:** {sku}  \n**Hub:** {hub}  \n**Action:** {action}  \n**Qty:** {qty}  \n**New Qty:** {new_qty}"
            )
            st.rerun()

# --- Bulk Update ---
if menu == "Bulk Update":
    st.header(T("bulk_update"))
    rows = query("SELECT sku, quantity FROM inventory WHERE hub=?", (hub,))
    df = pd.DataFrame(rows, columns=[T("sku"), T("qty")])

    with st.form("bulk_update_form"):
        st.info("Enter a positive number for IN, negative for OUT. Leave blank to skip. Comments optional.", icon="ℹ️")
        update_data = []
        for idx, row in df.iterrows():
            with st.expander(f"{row[T('sku')]} (Current: {row[T('qty')]})", expanded=False):
                adj = st.text_input(
                    T("adjust_quantity"), 
                    value="", 
                    key=f"adj_{idx}_{row[T('sku')]}",
                    placeholder="+5 or -3"
                )
                comment = st.text_input(
                    T("comment"), 
                    value="", 
                    key=f"comm_{idx}_{row[T('sku')]}",
                    placeholder="Optional"
                )
                update_data.append((row[T("sku")], adj, comment))
        submitted = st.form_submit_button(T("apply_updates"))

    if submitted:
        errors = []
        results = []
        big_change = False
        any_change = False
        for sku, adj, comment in update_data:
            try:
                n = int(adj.strip()) if adj.strip() else 0
            except:
                n = 0
            if n == 0:
                continue
            any_change = True
            if abs(n) >= 10:
                big_change = True
            record = query("SELECT quantity FROM inventory WHERE sku=? AND hub=?", (sku, hub))
            current = record[0][0] if record else 0
            new_qty = current + n
            if new_qty < 0:
                errors.append(f"❌ Not enough '{sku}' (Now: {current}, Tried: {n})")
                continue
            action = "IN" if n > 0 else "OUT"
            query(
                """INSERT INTO inventory (sku, hub, quantity) VALUES (?, ?, ?)
                   ON CONFLICT(sku, hub) DO UPDATE SET quantity=excluded.quantity""",
                (sku, hub, new_qty),
                fetch=False,
                commit=True
            )
            query(
                "INSERT INTO logs VALUES (?, ?, ?, ?, ?, ?, ?)",
                (datetime.now().isoformat(), username, sku, hub, action, abs(n), comment),
                fetch=False,
                commit=True
            )
            results.append(f"{sku}: {action} {abs(n)} (Now: {new_qty})")

        if not any_change:
            st.info("No changes submitted.")
        else:
            if errors:
                st.warning("Some updates failed:\n" + "\n".join(errors))
            if results:
                st.success("✅ Bulk update complete!\n\n" + "\n".join(results))
                logs = query("SELECT timestamp, sku, action, qty, comment FROM logs WHERE hub=? ORDER BY timestamp DESC LIMIT 3", (hub,))
                if logs:
                    st.markdown("#### Last 3 Inventory Actions:")
                    st.table(pd.DataFrame(logs, columns=["Time", "SKU", "Action", "Qty", "Comment"]))
            if big_change:
                st.balloons()
        st.rerun()

# --- Logs ---
if menu == "Logs":
    st.header(T("activity_logs"))
    logs = query("SELECT * FROM logs ORDER BY timestamp DESC")
    df = pd.DataFrame(logs, columns=["Time", "User", "SKU", "Hub", "Action", "Qty", "Comment"])
    search = st.text_input(T("filter_logs"), placeholder="Type keyword, SKU, user, action...", key="log_search")
    if search:
        df = df[df.apply(lambda row: search.lower() in row.astype(str).str.lower().to_string(), axis=1)]
    st.dataframe(df, use_container_width=True, key="logs_df")
    buff = io.BytesIO()
    df.to_csv(buff, index=False)
    st.download_button("📥 Download CSV of Logs", buff.getvalue(), "logs.csv", "text/csv", key="download_logs_btn")

# --- Count Mode ---
if menu == "Count":
    st.header(T("inventory_count_mode"))
    q = "SELECT sku, hub, quantity FROM inventory"
    f = ()
    if role != "Admin":
        q += " WHERE hub=?"
        f = (hub,)
    data = query(q, f)
    df = pd.DataFrame(data, columns=[T("sku"), T("hub"), T("qty")])
    df['Status'] = df[T("qty")].apply(lambda x: "🟥 Low" if x < 10 else "✅ OK")
    st.dataframe(df, use_container_width=True, key="count_df")
    if role != "Admin":
        if st.button(T("count_confirmed"), key="btn_count_confirm"):
            query("INSERT INTO count_confirmations (username, hub, confirmed_at) VALUES (?, ?, ?)",
                  (username, hub, datetime.now().isoformat()), fetch=False, commit=True)
            st.success(T("count_confirmed"))
            st.info(T("refresh"))
        if st.button(T("refresh"), key="btn_refresh_count"):
            st.rerun()
    if role == "Admin":
        confirms = query("SELECT * FROM count_confirmations ORDER BY confirmed_at DESC")
        df_confirm = pd.DataFrame(confirms, columns=[T("username"), T("hub"), "Time"])
        st.subheader(T("confirmed_counts"))
        st.dataframe(df_confirm, use_container_width=True, key="confirm_counts_df")
        if st.button(T("refresh"), key="btn_refresh_confirmations"):
            st.rerun()

# --- Google Sheets ---
if menu == "Google Sheets" and role in ["Admin", "Hub Manager", "Retail"]:
    st.header("📊 Google Sheets Inventory Reference")
    sheet_url = "https://docs.google.com/spreadsheets/d/e/2PACX-1vSg2Hyk9x4Uaz2kkBh2PkoKJlnpth6evjHKX9m0FfuxXK28c6HSWYpTaYjYCzI2f5Y0bKm6YUhSCoa9/pubhtml?gid=1829911536&single=true"
    st.markdown(f'<iframe src="{sheet_url}" width="100%" height="600"></iframe>', unsafe_allow_html=True)
    st.markdown(f"[Open Google Sheets in new tab]({sheet_url})")


# --- Messages ---
if menu == "Messages":
    st.header("📢 Internal Messaging")
    if role == "Admin":
        users = [u[0] for u in query("SELECT username FROM users WHERE username != ?", (username,))]
        to_label = T("to")
        subject_placeholder = T("subject")
    else:
        users = [u[0] for u in query("SELECT username FROM users WHERE role='Admin'")]
        to_label = T("to")
        subject_placeholder = T("subject")
    st.subheader(T("send_message"))
    recipient = st.selectbox(to_label, users, key="message_recipient")
    thread = st.text_input(T("subject"), placeholder=subject_placeholder, key="message_subject")
    msg = st.text_area(T("message"), placeholder="Type your message here…", key="message_body")
    if st.button(T("send"), key="btn_send_message"):
        auto_thread = thread.strip() if thread.strip() else f"{username}-{recipient}"
        query(
            "INSERT INTO messages (sender, receiver, message, thread, timestamp) VALUES (?, ?, ?, ?, ?)",
            (username, recipient, msg, auto_thread, datetime.now().isoformat()),
            fetch=False,
            commit=True
        )
        st.success("✅ Message sent!")
        st.rerun()

    st.markdown("---")
    st.subheader(T("your_threads"))
    threads = query("SELECT DISTINCT thread FROM messages WHERE sender=? OR receiver=? ORDER BY timestamp DESC", (username, username))
    for t in threads:
        thread_msgs = query("SELECT timestamp, sender, message FROM messages WHERE thread=? ORDER BY timestamp", (t[0],))
        last_msg = thread_msgs[-1] if thread_msgs else None
        last_from = last_msg[1] if last_msg else ""
        unread = last_from != username
        label = f"🧵 {t[0]}"
        if unread:
            label = f"**🔵 {label}**"
        with st.expander(label):
            for m in thread_msgs:
                st.markdown(f"**{m[1]}** ({m[0]}): {m[2]}")
            reply = st.text_input(T("reply"), key=f"reply_input_{t[0]}", placeholder="Type your reply here…")
            if st.button(T("send_reply"), key=f"reply_btn_{t[0]}"):
                last_receiver = [m[1] for m in reversed(thread_msgs) if m[1] != username]
                reply_to = last_receiver[0] if last_receiver else users[0]
                if role == "Admin" or reply_to in users:
                    query(
                        "INSERT INTO messages (sender, receiver, message, thread, timestamp) VALUES (?, ?, ?, ?, ?)",
                        (username, reply_to, reply, t[0], datetime.now().isoformat()),
                        fetch=False,
                        commit=True
                    )
                    st.rerun()
                else:
                    st.warning(T("only_reply_hq"))

# --- Shipments ---
if menu == "Shipments":
    st.header(T("supplier_shipments"))
    if role == "Supplier":
        tracking = st.text_input(T("tracking_number"), key="supplier_tracking")
        carrier = st.text_input(T("carrier"), key="supplier_carrier")
        hub_dest = st.selectbox(T("destination_hub"), ["Hub 1", "Hub 2", "Hub 3", "Retail"], key="supplier_dest_hub")
        date = st.date_input(T("shipping_date"), value=datetime.today(), key="supplier_ship_date")
        if "supplier_skus" not in st.session_state:
            st.session_state["supplier_skus"] = [{"sku": "", "qty": 1}]
        supplier_skus = st.session_state["supplier_skus"]
        all_sku_options = [s[0] for s in query("SELECT sku FROM sku_info")]
        for i, entry in enumerate(supplier_skus):
            cols = st.columns([4, 2, 1])
            with cols[0]:
                entry["sku"] = st.selectbox(f"{T('sku')} {i+1}", all_sku_options, index=all_sku_options.index(entry["sku"]) if entry["sku"] in all_sku_options else 0, key=f"supp_sku_{i}")
            with cols[1]:
                entry["qty"] = st.number_input(f"{T('qty')} {i+1}", min_value=1, step=1, key=f"supp_qty_{i}", value=entry["qty"])
            with cols[2]:
                if st.button(T("remove"), key=f"rmv_sku_{i}"):
                    supplier_skus.pop(i)
                    st.rerun()
        if st.button(T("add_another_sku"), key="btn_add_another_sku"):
            supplier_skus.append({"sku": "", "qty": 1})
            st.rerun()
        st.markdown("---")
        with st.expander(T("create_new_sku")):
            new_sku = st.text_input(T("new_sku_name"), key="supplier_new_sku")
            if st.button(T("add_sku"), key="supplier_add_sku"):
                if new_sku.strip():
                    query(
                        "INSERT OR IGNORE INTO sku_info (sku, product_name, assigned_hubs) VALUES (?, ?, ?)",
                        (new_sku.strip(), new_sku.strip(), "Hub 1,Hub 2,Hub 3,Retail"),
                        fetch=False,
                        commit=True
                    )
                    st.success(f"SKU '{new_sku.strip()}' added.")
                    st.rerun()
                else:
                    st.warning(T("enter_sku_name"))
        submitted = st.button(T("submit_shipment"), key="submit_supplier_shipment")
        if submitted:
            if tracking and carrier and all(e["sku"] for e in supplier_skus):
                skus_str = ", ".join([f"{e['sku']} x {e['qty']}" for e in supplier_skus if e["sku"]])
                query(
                    "INSERT INTO shipments (supplier, tracking, carrier, hub, skus, date, status) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (username, tracking.strip(), carrier.strip(), hub_dest, skus_str, str(date), "Pending"),
                    fetch=False,
                    commit=True
                )
                st.success(T("shipment_submitted"))
                st.session_state["supplier_skus"] = [{"sku": "", "qty": 1}]
                st.rerun()
            else:
                st.error(T("fill_out_required"))
        filter_text = st.text_input("Filter Shipments (Tracking, Carrier, or Hub):", key="supplier_filter_ship").lower()
        my_shipments = query("SELECT * FROM shipments WHERE supplier=? AND status!='Deleted' ORDER BY id DESC", (username,))
        st.markdown("### " + T("your_shipments"))
        if my_shipments:
            df_my = pd.DataFrame(my_shipments, columns=["ID", "Supplier", "Tracking", "Carrier", "Hub", "SKUs", "Date", "Status"])
            if filter_text:
                df_my = df_my[
                    df_my["Tracking"].str.lower().str.contains(filter_text) |
                    df_my["Carrier"].str.lower().str.contains(filter_text) |
                    df_my["Hub"].str.lower().str.contains(filter_text)
                ]
            for idx, row in df_my.iterrows():
                with st.expander(f"Shipment ID {row['ID']} - Status: {row['Status']}"):
                    st.write(f"Tracking: {row['Tracking']}")
                    st.write(f"Carrier: {row['Carrier']}")
                    st.write(f"Hub: {row['Hub']}")
                    st.write(f"SKUs: {row['SKUs']}")
                    st.write(f"Date: {row['Date']}")
                    if row['Status'] == "Pending":
                        if st.button(f"Delete Shipment {row['ID']}", key=f"supp_delete_{row['ID']}"):
                            query("UPDATE shipments SET status='Deleted' WHERE id=?", (row['ID'],), fetch=False, commit=True)
                            st.success(f"Shipment {row['ID']} deleted.")
                            st.rerun()
        else:
            st.info(T("no_shipments"))
    else:
        # Admin/manager/retail: view all shipments except Deleted, mark as received
        rows = query("SELECT * FROM shipments WHERE status!='Deleted' ORDER BY id DESC")
        df = pd.DataFrame(rows, columns=["ID", "Supplier", "Tracking", "Carrier", "Hub", "SKUs", "Date", "Status"])
        st.dataframe(df, use_container_width=True, key="all_shipments_df")
        pending = df[df["Status"] == "Pending"]
        if not pending.empty:
            st.subheader(T("mark_received"))
            to_confirm = st.selectbox("Select Pending Shipment", pending["ID"].tolist(), key="admin_confirm_ship")
            confirm = st.checkbox(T("confirm_receipt"), key="admin_confirm_checkbox")
            if st.button(T("mark_received"), key="btn_admin_confirm_receive"):
                if confirm:
                    record = df[df["ID"] == to_confirm].iloc[0]
                    sku_list = [s.strip() for s in record["SKUs"].split(",") if s.strip()]
                    for sku in sku_list:
                        if " x " in sku:
                            name, qty = sku.rsplit(" x ", 1)
                            try:
                                qty = int(qty)
                            except:
                                qty = 1
                        else:
                            name = sku
                            qty = 1
                        current = query("SELECT quantity FROM inventory WHERE sku=? AND hub=?", (name, record["Hub"]))
                        curr_qty = current[0][0] if current else 0
                        new_qty = curr_qty + qty
                        query(
                            "INSERT INTO inventory (sku, hub, quantity) VALUES (?, ?, ?) ON CONFLICT(sku, hub) DO UPDATE SET quantity=?",
                            (name, record["Hub"], new_qty, new_qty),
                            fetch=False,
                            commit=True
                        )
                        query(
                            "INSERT INTO logs VALUES (?, ?, ?, ?, ?, ?, ?)",
                            (datetime.now().isoformat(), username, name, record["Hub"], "IN", qty, f"Shipment {record['ID']}"),
                            fetch=False,
                            commit=True
                        )
                    query("UPDATE shipments SET status='Received' WHERE id=?", (to_confirm,), fetch=False, commit=True)
                    st.success(T("shipment_confirmed"))
                    st.rerun()
        # Admin delete shipment option
        if role == "Admin":
            st.markdown("---")
            st.subheader(T("delete_shipment"))
            delete_id = st.selectbox("Select Shipment to Delete", df["ID"].tolist(), key="admin_delete_ship_id")
            confirm_del = st.checkbox(T("confirm_delete"), key="admin_confirm_delete_checkbox")
            if st.button(T("delete_shipment"), key="btn_admin_delete_shipment"):
                if confirm_del:
                    query("UPDATE shipments SET status='Deleted' WHERE id=?", (delete_id,), fetch=False, commit=True)
                    st.success(T("shipment_deleted"))
                    st.rerun()

# --- Incoming Shipments for Hub Managers ---
if menu == "Incoming Shipments" and role == "Hub Manager":
    st.header(T("incoming_shipments"))
    incoming = query("SELECT * FROM shipments WHERE hub=? AND status='Pending' ORDER BY date DESC", (hub,))
    if incoming:
        df_in = pd.DataFrame(incoming, columns=["ID", "Supplier", "Tracking", "Carrier", "Hub", "SKUs", "Date", "Status"])
        for idx, row in df_in.iterrows():
            with st.expander(f"Shipment ID {row['ID']} from {row['Supplier']}"):
                st.write(f"Tracking: {row['Tracking']}")
                st.write(f"Carrier: {row['Carrier']}")
                st.write(f"SKUs: {row['SKUs']}")
                st.write(f"Date: {row['Date']}")
                confirm = st.checkbox(f"{T('mark_received')} {row['ID']}", key=f"hubman_confirm_{row['ID']}")
                if confirm:
                    sku_list = [s.strip() for s in row["SKUs"].split(",") if s.strip()]
                    for sku in sku_list:
                        if " x " in sku:
                            name, qty = sku.rsplit(" x ", 1)
                            try:
                                qty = int(qty)
                            except:
                                qty = 1
                        else:
                            name = sku
                            qty = 1
                        current = query("SELECT quantity FROM inventory WHERE sku=? AND hub=?", (name, hub))
                        curr_qty = current[0][0] if current else 0
                        new_qty = curr_qty + qty
                        query(
                            "INSERT INTO inventory (sku, hub, quantity) VALUES (?, ?, ?) ON CONFLICT(sku, hub) DO UPDATE SET quantity=?",
                            (name, hub, new_qty, new_qty),
                            fetch=False,
                            commit=True
                        )
                        query(
                            "INSERT INTO logs VALUES (?, ?, ?, ?, ?, ?, ?)",
                            (datetime.now().isoformat(), username, name, hub, "IN", qty, f"Shipment {row['ID']}"),
                            fetch=False,
                            commit=True
                        )
                    query("UPDATE shipments SET status='Received' WHERE id=?", (row['ID'],), fetch=False, commit=True)
                    st.success(T("shipment_confirmed"))
                    st.rerun()
    else:
        st.info("No pending shipments for your hub.")





