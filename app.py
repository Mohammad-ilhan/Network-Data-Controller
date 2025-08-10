# app.py
import streamlit as st
import threading, time, subprocess, os, sqlite3, hashlib, ctypes, re
from collections import defaultdict
from datetime import datetime
import pandas as pd

# --------------------------------------------------------------
# PAGE CONFIG & CUSTOM STYLING
# --------------------------------------------------------------
st.set_page_config(page_title="Per-Device Data Control (Hotspot)", layout="wide")

page_bg_css = """
<style>
[data-testid="stAppViewContainer"] {
    background: linear-gradient(135deg, #0f2027, #203a43, #2c5364);
    color: white;
}
[data-testid="stSidebar"] {
    background: linear-gradient(180deg, #2c5364, #203a43);
    color: white;
}
/* Remove gray border from sidebar */
section[data-testid="stSidebar"] {
    border-right: none;
}
h1, h2, h3, h4 {
    color: #fdfdfd;
}
[data-testid="stDataFrame"] {
    background-color: white !important;
}
input, textarea {
    background-color: #f7f7f7 !important;
}
</style>
"""
st.markdown(page_bg_css, unsafe_allow_html=True)

# ------------------- PROJECT HEADING --------------------------
st.markdown(
    "<h1 style='text-align: center; color: #00eaff; margin-bottom:0.2em;'>🌐 Per‑Device Data Control Dashboard</h1>",
    unsafe_allow_html=True
)
st.markdown(
    "<h3 style='text-align: center; color: #a8f7ff;'>Monitor, Set Quotas & Control Your Network Devices in Real‑Time</h3>",
    unsafe_allow_html=True
)

# ------------------- SIDEBAR BRANDING ------------------------
# ICON
st.sidebar.image(
    "https://img.icons8.com/color/96/000000/network.png",
    use_column_width="always"
)
# WELCOME
st.sidebar.markdown("### Welcome!")
st.sidebar.info(
    """
    Easily set usage quotas, monitor per-device network usage, and block/unblock devices in real time.
    """
)
st.sidebar.markdown("---")
# QUICK INSTRUCTIONS
st.sidebar.markdown(
    """
    - 👤 **Logged in as:** `{}`  
    - 🎛️ *Select your network interface*  
    - 💡 *Use controls to set quotas or block devices*
    """.format(st.session_state.get('username', 'Visitor'))
)
# QUICK LINKS
st.sidebar.markdown("---")
st.sidebar.markdown("#### Quick Links")
st.sidebar.markdown(
    """
    [FAQ](#)  &nbsp; | &nbsp; [Docs](#)  &nbsp; | &nbsp; [Contact](#)
    """
)
st.sidebar.markdown("---")
# SESSION/APP INFO
st.sidebar.caption(
    f"App version 1.0 &nbsp;|&nbsp; Session: {datetime.now().strftime('%H:%M')}"
)
logout_clicked = st.sidebar.button("Logout", key="sidebar_logout")

# --------------------------------------------------------------
# CONFIG
# --------------------------------------------------------------
DB_PATH = "hotspot.db"
db_lock = threading.Lock()
usage_bytes = defaultdict(int)

# --------------------------------------------------------------
# DATABASE INIT
# --------------------------------------------------------------
conn = sqlite3.connect(DB_PATH, check_same_thread=False)
cur = conn.cursor()
with db_lock:
    cur.execute("""CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        password_hash TEXT)""")
    cur.execute("""CREATE TABLE IF NOT EXISTS usage (
        ip TEXT,
        mac TEXT,
        bytes INTEGER,
        timestamp TEXT)""")
    cur.execute("""CREATE TABLE IF NOT EXISTS quotas (
        ip TEXT PRIMARY KEY,
        quota_mb INTEGER,
        blocked INTEGER DEFAULT 0)""")
    conn.commit()

# --------------------------------------------------------------
# HELPERS
# --------------------------------------------------------------
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def add_default_admin():
    with db_lock:
        cur.execute("SELECT 1 FROM users WHERE username='admin'")
        if not cur.fetchone():
            cur.execute("INSERT INTO users VALUES (?, ?)",
                        ("admin", hash_password("admin123")))
            conn.commit()
add_default_admin()

def is_admin():
    if os.name != "nt":
        return True
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def running_in_cloud():
    return os.environ.get("STREAMLIT_RUNTIME") == "streamlit"

def safe_rerun():
    st.rerun()

IPV4_REGEX = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
def valid_ipv4(ip: str) -> bool:
    if not IPV4_REGEX.match(ip):
        return False
    parts = ip.split('.')
    return all(0 <= int(part) <= 255 for part in parts)

# --------------------------------------------------------------
# FIREWALL CONTROL (Windows Only)
# --------------------------------------------------------------
def add_block_rule(ip):
    rule_name = f"HotspotBlock_{ip}"
    if os.name == "nt":
        cmd = [
            "powershell",
            "-Command",
            f"New-NetFirewallRule -DisplayName '{rule_name}' "
            f"-Direction Outbound -RemoteAddress {ip} -Action Block -Enabled True -Profile Any"
        ]
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=False)

def remove_block_rule(ip):
    if os.name == "nt":
        rule_name = f"HotspotBlock_{ip}"
        cmd = ["powershell", "-Command",
               f"Get-NetFirewallRule -DisplayName '{rule_name}' | Remove-NetFirewallRule"]
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=False)

# --------------------------------------------------------------
# TRAFFIC CAPTURE OR SIMULATION
# --------------------------------------------------------------
SIMULATION_MODE = False
try:
    from scapy.all import sniff, conf, get_if_list
    from scapy.layers.inet import IP
except ImportError:
    SIMULATION_MODE = True
    get_if_list = lambda: ["Simulation Mode Only"]

def persist_usage_snapshot():
    with db_lock:
        for ip, total in usage_bytes.items():
            cur.execute("INSERT INTO usage VALUES (?, ?, ?, ?)",
                        (ip, "", total, datetime.utcnow().isoformat()))
        conn.commit()

def packet_handler(pkt):
    try:
        if pkt.haslayer(IP):
            src = pkt[IP].src
            usage_bytes[src] += len(pkt)
    except:
        pass

def start_sniff(iface):
    conf.sniff_promisc = True
    sniff(prn=packet_handler, store=False, iface=iface)

def simulation_thread():
    ips = ["192.168.0.101", "192.168.0.102", "192.168.0.103"]
    while True:
        for ip in ips:
            usage_bytes[ip] += 1024 * (1 + int(time.time()) % 5)
        time.sleep(1)

def enforcement_loop():
    while True:
        with db_lock:
            rows = cur.execute("SELECT ip, quota_mb, blocked FROM quotas").fetchall()
        for ip, quota_mb, blocked in rows:
            used_mb = usage_bytes.get(ip, 0) / (1024*1024)
            if quota_mb is not None and used_mb >= quota_mb and not blocked:
                add_block_rule(ip)
                with db_lock:
                    cur.execute("UPDATE quotas SET blocked=1 WHERE ip=?", (ip,))
                    conn.commit()
            elif quota_mb is not None and used_mb < quota_mb and blocked:
                remove_block_rule(ip)
                with db_lock:
                    cur.execute("UPDATE quotas SET blocked=0 WHERE ip=?", (ip,))
                    conn.commit()
        persist_usage_snapshot()
        time.sleep(5)

# --------------------------------------------------------------
# UI FUNCTIONS
# --------------------------------------------------------------
def login_screen():
    st.title("🔒 Per-Device Data Control — Login")
    u = st.text_input("Username")
    p = st.text_input("Password", type="password")
    if st.button("Login"):
        with db_lock:
            user = cur.execute("SELECT 1 FROM users WHERE username=? AND password_hash=?",
                               (u, hash_password(p))).fetchone()
        if user:
            st.session_state.logged_in = True
            st.session_state.username = u
            safe_rerun()
        else:
            st.error("❌ Invalid credentials")

def main_ui():
    # LOGOUT from sidebar (for global behavior)
    if logout_clicked or st.session_state.get("force_logout", False):
        st.session_state.logged_in = False
        st.session_state.username = None
        st.session_state.force_logout = False
        safe_rerun()

    is_cloud = running_in_cloud()
    is_local_windows_admin = (os.name == "nt" and is_admin())

    if not is_cloud and not is_local_windows_admin:
        st.info("Running without administrative privileges → Simulation Mode only.")

    # ---- MAIN PANEL UI ----
    st.header("🌐 Network Interface Selection")
    try:
        interfaces = get_if_list()
    except Exception:
        interfaces = ["(No interfaces found)"]

    iface = st.selectbox(
        "Select network interface",
        interfaces,
        help="Choose the interface for live capture. If simulation, only dummy options are available."
    )

    mode_text = "Simulation" if SIMULATION_MODE or is_cloud or not is_local_windows_admin else f"Live capture on: {iface}"
    st.markdown(f"#### Mode: `{mode_text}`")
    if SIMULATION_MODE or is_cloud or not is_local_windows_admin:
        st.info("Simulation mode is active. Live network capture and firewall control are disabled.")

    st.header("📊 Live Devices & Usage")
    def build_df():
        table = []
        for ip, b in usage_bytes.items():
            used_mb = round(b / (1024*1024), 3)
            with db_lock:
                q = cur.execute("SELECT quota_mb, blocked FROM quotas WHERE ip=?", (ip,)).fetchone()
            quota = q[0] if q else None
            blocked = bool(q[1]) if q else False
            table.append({"IP": ip, "Used (MB)": used_mb, "Quota (MB)": quota, "Blocked": blocked})
        return pd.DataFrame(table, columns=["IP", "Used (MB)", "Quota (MB)", "Blocked"])

    st.dataframe(build_df(), height=320)
    if st.button("🔄 Refresh usage data"):
        safe_rerun()

    st.header("🎛️ Set Quota")
    with st.form("quota_form"):
        ip = st.text_input("Device IP", help="Enter a valid IPv4 address (e.g. 192.168.0.101)")
        quota_mb = st.number_input("Quota (MB)", min_value=1, value=100, help="Max allowed MB for the device")
        submit = st.form_submit_button("Save Quota")
        if submit:
            if not valid_ipv4(ip):
                st.error("⚠️ Invalid IP address format!")
            else:
                with db_lock:
                    cur.execute("""INSERT OR REPLACE INTO quotas(ip, quota_mb, blocked)
                                   VALUES (?, ?, COALESCE((SELECT blocked FROM quotas WHERE ip=?),0))""",
                                (ip, int(quota_mb), ip))
                    conn.commit()
                st.success(f"✅ Quota set for {ip} to {quota_mb} MB")

    with st.expander("Manual Block / Unblock Controls"):
        m_ip = st.text_input("IP to block/unblock", key="manual_block_ip", help="Specify IP to manually block or unblock")
        col1, col2 = st.columns(2)
        with col1:
            if st.button("Block Now"):
                if not valid_ipv4(m_ip):
                    st.error("⚠️ Invalid IP address format!")
                else:
                    add_block_rule(m_ip)
                    with db_lock:
                        cur.execute("""INSERT OR REPLACE INTO quotas
                                       (ip, quota_mb, blocked) VALUES (?, COALESCE((SELECT quota_mb FROM quotas WHERE ip=?), NULL), 1)""",
                                    (m_ip, m_ip))
                        conn.commit()
                    st.warning(f"🚫 {m_ip} has been blocked.")
        with col2:
            if st.button("Unblock Now"):
                if not valid_ipv4(m_ip):
                    st.error("⚠️ Invalid IP address format!")
                else:
                    remove_block_rule(m_ip)
                    with db_lock:
                        cur.execute("UPDATE quotas SET blocked=0 WHERE ip=?", (m_ip,))
                        conn.commit()
                    st.success(f"✔️ {m_ip} has been unblocked.")

    with st.expander("📜 Usage History / Logs"):
        with db_lock:
            rows = cur.execute("SELECT ip, bytes, timestamp FROM usage ORDER BY timestamp DESC LIMIT 200").fetchall()
        if rows:
            hist = pd.DataFrame(rows, columns=["IP", "Bytes", "Timestamp"])
            hist["MB"] = (hist["Bytes"]/(1024*1024)).round(3)
            st.dataframe(hist)
        else:
            st.info("No usage history available yet.")

# --------------------------------------------------------------
# SESSION & THREAD START
# --------------------------------------------------------------
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
    st.session_state.username = None
if not st.session_state.logged_in:
    login_screen()
    st.stop()

if "threads_started" not in st.session_state:
    if SIMULATION_MODE or running_in_cloud() or not (os.name == "nt" and is_admin()):
        threading.Thread(target=simulation_thread, daemon=True).start()
    else:
        try:
            iface_list = get_if_list()
            if iface_list:
                threading.Thread(target=start_sniff, args=(iface_list[0],), daemon=True).start()
            else:
                threading.Thread(target=simulation_thread, daemon=True).start()
        except:
            threading.Thread(target=simulation_thread, daemon=True).start()
    threading.Thread(target=enforcement_loop, daemon=True).start()
    st.session_state.threads_started = True

main_ui()
