import streamlit as st
import pandas as pd
import time
import os
import threading
import requests
import streamlit.components.v1 as components
from datetime import datetime
from typing import List, Tuple, Optional

# --- CONFIGURATION ---
st.set_page_config(layout="wide", page_title="Control Hub: Swarm Command")

# --- 1. IMPORTS & SETUP ---
@st.cache_resource
def get_backend_modules():
    try:
        import control_hub as ch
        return ch
    except ImportError:
        return None

CH = get_backend_modules()

if CH is None:
    st.error("CRITICAL ERROR: Could not import 'control_hub.py'.")
    st.stop()

FILE_MANAGER_UI = CH.FileManager()

# --- 2. SESSION STATE HISTORY ---
# We use this to build graphs for DATTOWER since the agent doesn't send history
if 'swarm_history' not in st.session_state:
    st.session_state['swarm_history'] = {} 

# --- 3. LIFECYCLE MANAGEMENT ---
@st.cache_resource
def ensure_background_threads_running():
    if not os.path.isdir(CH.DUPLICATE_SCAN_PATH):
        st.error(f"Invalid Scan Path: {CH.DUPLICATE_SCAN_PATH}")
        return False

    current_threads = {t.name for t in threading.enumerate()}
    
    # Spawn all required threads
    tasks = [
        ("MonitorThread", CH.monitor_thread_target, (CH.SystemMonitor(),)),
        ("ScannerThread", CH.scanner_thread_target, (CH.FileManager(), CH.DUPLICATE_SCAN_PATH)),
        ("NetworkThread", CH.NetworkManager(CH.SnapshotManager()).start_loop, None),
        ("ArpWatchdogThread", CH.ArpWatchdog().start_loop, None)
    ]

    for name, target, args in tasks:
        if name not in current_threads:
            print(f"STREAMLIT: Spawning {name}...")
            t = threading.Thread(target=target, args=args if args else (), daemon=True, name=name)
            t.start()
    return True

ensure_background_threads_running()

# --- 4. DATA FETCHING ---
def fetch_swarm_data():
    """Gets data from the local API Bus."""
    try:
        # We connect to localhost because this script runs ON the server
        response = requests.get("http://127.0.0.1:5000/api/status", timeout=0.5)
        if response.status_code == 200:
            return response.json()
    except:
        pass
    return None

def update_swarm_history(swarm_nodes):
    """Accumulates history for graphing."""
    timestamp = datetime.now().strftime("%H:%M:%S")
    for host, stats in swarm_nodes.items():
        if host not in st.session_state['swarm_history']:
            st.session_state['swarm_history'][host] = {'cpu': [], 'ram': [], 'time': []}
        
        history = st.session_state['swarm_history'][host]
        history['cpu'].append(stats.get('cpu', 0))
        history['ram'].append(stats.get('ram', 0))
        history['time'].append(timestamp)
        
        # Keep last 60 points
        if len(history['cpu']) > 60:
            history['cpu'].pop(0)
            history['ram'].pop(0)
            history['time'].pop(0)

# --- 5. RENDERERS ---

def render_metrics_dashboard(node_name, current_data, history_data):
    """The Main Visualization Component."""
    st.markdown(f"### 🖥️ Monitoring: **{node_name}**")
    
    # 1. Big Metrics
    c1, c2, c3 = st.columns(3)
    cpu = current_data.get('cpu', 0)
    ram = current_data.get('ram', 0)
    
    c1.metric("CPU Load", f"{cpu:.1f}%", delta_color="inverse")
    c2.metric("RAM Usage", f"{ram:.1f}%", delta_color="inverse")
    
    # Handle optional disk/net metrics
    if 'disk' in current_data:
        c3.metric("Disk Usage", f"{current_data['disk']:.1f}%")
    elif 'net_sent_kb_s' in current_data:
        c3.metric("Network Up", f"{current_data['net_sent_kb_s']} KB/s")

    # 2. Charts
    if history_data:
        chart_data = pd.DataFrame({
            'CPU (%)': history_data['cpu'],
            'RAM (%)': history_data['ram']
        }, index=history_data.get('time', []))
        st.line_chart(chart_data)
    else:
        st.info("Waiting for history data to build graphs...")

def render_network_intel(network_data, last_scan, arp_table, alerts):
    st.subheader("📡 Network & Active Defense")
    
    # Security Banner
    if alerts:
        st.error(f"🚨 {len(alerts)} SECURITY ALERTS DETECTED")
        with st.expander("View Threats", expanded=True):
            for a in alerts: st.warning(a)
    else:
        st.success("🛡️ Active Defense: Network Perimeter Secure")

    t1, t2 = st.tabs(["Router Inventory", "Local ARP Table"])
    
    with t1:
        if network_data:
            df = pd.DataFrame(list(network_data.values()))
            cols = ['hostname', 'ip', 'mac', 'vendor', 'status']
            st.dataframe(df[cols] if not df.empty else df, use_container_width=True)
        else:
            st.warning("No router data yet.")
            
    with t2:
        if arp_table:
            arp_df = pd.DataFrame(list(arp_table.items()), columns=['IP Address', 'MAC Address'])
            st.dataframe(arp_df, use_container_width=True)

# --- 6. MAIN DASHBOARD ---
def main_dashboard():
    # --- Data Sync ---
    swarm_payload = fetch_swarm_data()
    swarm_nodes = swarm_payload.get('swarm_nodes', {}) if swarm_payload else {}
    update_swarm_history(swarm_nodes)
    
    with CH.DATA_LOCK:
        local_metrics = CH.SHARED_HUB_DATA.get("system_metrics", {})
        local_history = CH.SHARED_HUB_DATA.get("metric_history", {})
        net_intel = CH.SHARED_HUB_DATA.get("network_inventory", {})
        last_net_scan = CH.SHARED_HUB_DATA.get("network_last_scan", 0)
        arp_table = CH.SHARED_HUB_DATA.get("arp_table", {})
        alerts = CH.SHARED_HUB_DATA.get("security_alerts", [])

    # --- Sidebar Controls ---
    st.sidebar.title("🎮 Control Hub")
    
    # Source Selector
    options = ["Local Server (This PC)"] + list(swarm_nodes.keys())
    target_node = st.sidebar.selectbox("Select Target System", options)
    
    # Meta Status
    st.sidebar.divider()
    if swarm_payload:
        st.sidebar.success(f"API Bus: ONLINE ({len(swarm_nodes)} Agents)")
    else:
        st.sidebar.error("API Bus: OFFLINE")

    # --- Main Content ---
    
    if target_node == "Local Server (This PC)":
        # Format local history for the renderer
        fmt_history = {'cpu': local_history.get('cpu_util', []), 'ram': local_history.get('mem_util', [])}
        render_metrics_dashboard("Secondary PC (Server)", local_metrics, fmt_history)
    else:
        # Render Remote Node
        node_data = swarm_nodes.get(target_node, {})
        node_hist = st.session_state['swarm_history'].get(target_node, {})
        render_metrics_dashboard(target_node, node_data, node_hist)

    st.divider()
    render_network_intel(net_intel, last_net_scan, arp_table, alerts)

    time.sleep(1)
    st.rerun()

if __name__ == "__main__":
    main_dashboard()