import streamlit as st
import pandas as pd
import time
import os
import sys
import threading
import requests  # <--- THIS WAS MISSING
import streamlit.components.v1 as components
from datetime import datetime, timedelta
from typing import List, Tuple, Optional

# --- CONFIGURATION ---
st.set_page_config(layout="wide", page_title="Control Hub Dashboard")

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

# Initialize a File Manager for the UI actions
FILE_MANAGER_UI = CH.FileManager()

# --- 2. FORENSIC LIFECYCLE MANAGEMENT ---
# Prevents "Zombie Tasks" by checking existing threads before spawning
@st.cache_resource
def ensure_background_threads_running():
    if not os.path.isdir(CH.DUPLICATE_SCAN_PATH):
        st.error(f"Invalid Scan Path: {CH.DUPLICATE_SCAN_PATH}")
        return False

    current_threads = {t.name for t in threading.enumerate()}
    
    if "MonitorThread" not in current_threads:
        print("STREAMLIT: Spawning MonitorThread...")
        monitor = CH.SystemMonitor()
        m_thread = threading.Thread(
            target=CH.monitor_thread_target, 
            args=(monitor,), 
            daemon=True, # Required for Streamlit
            name="MonitorThread"
        )
        m_thread.start()
    
    if "ScannerThread" not in current_threads:
        print("STREAMLIT: Spawning ScannerThread...")
        scanner_fm = CH.FileManager()
        s_thread = threading.Thread(
            target=CH.scanner_thread_target, 
            args=(scanner_fm, CH.DUPLICATE_SCAN_PATH), 
            daemon=True, 
            name="ScannerThread"
        )
        s_thread.start()

    # --- NEW: Spawning Network Intelligence Thread ---
    if "NetworkThread" not in current_threads:
        print("STREAMLIT: Spawning NetworkThread...")
        db_man = CH.SnapshotManager()
        net_man = CH.NetworkManager(db_man)
        n_thread = threading.Thread(
            target=net_man.start_loop,
            daemon=True,
            name="NetworkThread"
        )
        n_thread.start()

    return True

ensure_background_threads_running()

# --- 3. HELPER FUNCTIONS ---

def handle_file_action(action: str, target_paths: List[str], cleanup_folder: Optional[str] = None) -> Tuple[int, int]:
    success_count = 0
    failure_count = 0
    
    if action == 'move' and (not cleanup_folder):
        st.error(f"Move failed: Target folder is invalid.")
        return 0, len(target_paths)
    
    if action == 'move' and cleanup_folder and not os.path.exists(cleanup_folder):
        try:
            os.makedirs(cleanup_folder)
        except OSError:
            st.error("Could not create destination folder.")
            return 0, len(target_paths)

    for path in target_paths:
        if action == 'delete':
            if FILE_MANAGER_UI.delete_file_or_folder(path):
                success_count += 1
            else:
                failure_count += 1
        elif action == 'move' and cleanup_folder:
            if FILE_MANAGER_UI.move_file_or_folder(path, cleanup_folder):
                success_count += 1
            else:
                failure_count += 1
    return success_count, failure_count

# --- NEW: META-ORCHESTRATOR BRIDGE ---
def render_orchestrator_status():
    """Fetches and displays status from the Flask 'Signaler'."""
    st.sidebar.markdown("---")
    st.sidebar.subheader("ðŸ¤– Meta-Orchestrator")
    
    try:
        # Attempt to connect to the Flask API
        response = requests.get("http://127.0.0.1:5000/api/status", timeout=1)
        
        if response.status_code == 200:
            data = response.json()
            status = data.get("status", "unknown")
            watcher_active = data.get("watcher_active", False)
            events = data.get("events", [])
            
            # Status Badge
            if watcher_active:
                st.sidebar.success(f"Signal Server: {status.upper()}")
            else:
                st.sidebar.warning("Signal Server: Online (Watcher Stopped)")
            
            # Event Stream in Sidebar
            with st.sidebar.expander("Job Event Stream", expanded=True):
                if events:
                    for event in events[:5]: # Show last 5
                        st.text(event)
                else:
                    st.caption("No recent artifacts detected.")
        else:
            st.sidebar.error(f"Signal Server Error: {response.status_code}")

    except requests.exceptions.ConnectionError:
        st.sidebar.error("Signal Server: OFFLINE")
        st.sidebar.caption("Run 'python app.py' to start.")


# --- 4. UI RENDERING ---

def render_logs():
    with st.expander("ðŸ“Ÿ System Console Logs (Forensic Audit)", expanded=False):
        with CH.DATA_LOCK:
            logs = list(CH.SHARED_HUB_DATA["system_logs"])
        
        if logs:
            st.code("\n".join(logs), language="bash")
        else:
            st.info("No logs generated yet.")

def render_system_metrics(metrics_history: dict):
    st.subheader("ðŸ“ˆ System Performance Metrics")
    cols = st.columns(4)
    
    current_metrics = CH.SHARED_HUB_DATA.get("system_metrics", {})

    cols[0].metric("CPU Utilization", f"{current_metrics.get('cpu_util', 0.0):.1f} %")
    cols[1].metric("RAM Utilization", f"{current_metrics.get('mem_util', 0.0):.1f} %")
    cols[2].metric("Net Sent Rate", f"{current_metrics.get('net_sent_kb_s', 0.0):.1f} KB/s")
    cols[3].metric("Net Recv Rate", f"{current_metrics.get('net_recv_kb_s', 0.0):.1f} KB/s")

    if metrics_history and any(metrics_history.values()):
        min_len = min(len(v) for v in metrics_history.values() if isinstance(v, list))
        if min_len > 0:
            df = pd.DataFrame({
                'CPU (%)': list(metrics_history.get('cpu_util', []))[-min_len:],
                'RAM (%)': list(metrics_history.get('mem_util', []))[-min_len:],
            })
            st.line_chart(df)

def render_integrity_status():
    st.subheader("ðŸ›¡ï¸ Integrity & Snapshot Status")
    col1, col2 = st.columns(2)
    
    merkle = CH.SHARED_HUB_DATA.get("merkle_root", "Calculating...")
    status = CH.SHARED_HUB_DATA.get("snapshot_status", "Unknown")
    
    col1.info(f"**Current Merkle Root Hash:**\n`{merkle}`")
    
    if "Verified" in status:
        col2.success(f"**Database Status:** {status}")
    elif "Updated" in status:
        col2.warning(f"**Database Status:** {status}")
    else:
        col2.info(f"**Database Status:** {status}")

def render_file_audit(audit_report: dict):
    st.subheader("ðŸ§¹ File Audit & Cleanup")
    if not audit_report or 'duplicate_groups' not in audit_report:
        st.info("File scan report not yet available...")
        return

    wasted_bytes = audit_report.get('total_wasted_space_bytes', 0)
    wasted_mb = wasted_bytes / (1024 * 1024) if wasted_bytes else 0.0
    
    col1, col2, col3 = st.columns(3)
    col1.metric("Wasted Space (MB)", f"{wasted_mb:.1f}")
    col2.metric("Duplicate Files", audit_report.get('total_duplicate_files', 0))
    col3.metric("Duplicate Groups", len(audit_report.get('duplicate_groups', [])))
    
    groups = audit_report.get('duplicate_groups', [])
    if not groups:
        st.success("No duplicate file groups found!")
        return

    group_options = {g['hash']: f"Hash {g['hash'][:8]}... | Wasted {g['wasted_space_bytes'] / (1024*1024):.2f} MB" for g in groups}
    selected_hash = st.selectbox("Select Duplicate Group to Review", list(group_options.keys()), format_func=lambda x: group_options[x])

    if selected_hash:
        selected_group = next(g for g in groups if g['hash'] == selected_hash)
        
        table_data = []
        for path in selected_group['paths']:
            table_data.append({'select': False, 'Path': path, 'File Size (KB)': selected_group['size_kb']})

        df = pd.DataFrame(table_data)
        edited_df = st.data_editor(
            df, 
            key=f"editor_{selected_hash}",
            column_config={"select": st.column_config.CheckboxColumn("Select", default=False), "Path": st.column_config.TextColumn("File Path", width="large")}, 
            hide_index=True, 
            use_container_width=True
        )
        
        if not edited_df.empty:
            st.session_state['selected_paths'] = edited_df[edited_df['select']]['Path'].tolist()

def render_file_treemap(treemap_data: list):
    st.subheader("ðŸ“‚ File System Treemap")
    if not treemap_data:
        st.info("Treemap data is being calculated...")
        return
        
    root_node = treemap_data[0]
    total_size = root_node['size']
    st.metric("Total Scanned Size", f"{total_size / (1024*1024*1024):.2f} GB")
    
    st.caption(f"Root Node: {root_node['name']} ({len(treemap_data)} nodes visualized)")
    html_code = f"""
    <div style="width: 100%; height: 400px; background-color: #f0f0f0; border: 1px solid #ccc; display: flex; align-items: center; justify-content: center; flex-direction: column;">
        <div style="background-color: #CC2936; color: white; padding: 20px; text-align: center; border-radius: 8px;">
            <h3>ROOT: {root_node['name']}</h3>
            <p>Size: {total_size / (1024*1024):.2f} MB</p>
        </div>
    </div>
    """
    components.html(html_code, height=450)

# --- NEW: NETWORK INTELLIGENCE RENDERER ---
def render_network_intel(network_data: dict, last_scan: float):
    st.subheader("ðŸ“¡ Network Intelligence (NetIntel)")
    
    if not network_data:
        st.warning("No network data available. Waiting for next stealth poll...")
        return

    # Metrics Row
    online_count = sum(1 for d in network_data.values() if d.get('status') == 'Online')
    total_tracked = len(network_data)
    
    col1, col2, col3 = st.columns(3)
    col1.metric("Online Devices", online_count)
    col2.metric("Ghost Tracked (Offline)", total_tracked - online_count)
    if last_scan > 0:
        scan_time = datetime.fromtimestamp(last_scan).strftime('%H:%M:%S')
        col3.metric("Last Stealth Scan", scan_time)

    # Convert to DataFrame for display
    device_list = list(network_data.values())
    if device_list:
        df = pd.DataFrame(device_list)
        
        # Friendly Column Names & formatting
        display_df = df[['status', 'hostname', 'ip', 'mac', 'vendor', 'interface', 'tx_delta', 'rx_delta']].copy()
        display_df.rename(columns={
            'status': 'Status',
            'hostname': 'Hostname', 
            'ip': 'IP Address', 
            'mac': 'MAC Address', 
            'vendor': 'Vendor',
            'interface': 'Type',
            'tx_delta': 'Upload (Bytes)',
            'rx_delta': 'Download (Bytes)'
        }, inplace=True)

        # Highlight Bandwidth Hogs
        st.dataframe(
            display_df,
            use_container_width=True,
            column_config={
                "Status": st.column_config.TextColumn(
                    "Status", 
                    help="Online or Ghost Tracked",
                    validate="^(Online|Offline)$"
                ),
                "Upload (Bytes)": st.column_config.ProgressColumn(
                    "Upload Activity", 
                    format="%d", 
                    min_value=0, 
                    max_value=10000000 # Scaling factor for viz
                ),
                "Download (Bytes)": st.column_config.ProgressColumn(
                    "Download Activity", 
                    format="%d", 
                    min_value=0, 
                    max_value=50000000
                ),
            }
        )

# --- 5. MAIN DASHBOARD ---

def main_dashboard():
    st.title("ðŸŽ›ï¸ Control Hub: System & Network Defense")
    st.caption(f"Scanning Path: `{CH.DUPLICATE_SCAN_PATH}`")

    if 'cleanup_folder' not in st.session_state: st.session_state['cleanup_folder'] = os.path.join(os.getcwd(), 'cleanup_folder')
    
    st.sidebar.title("Bulk Actions")
    st.session_state['cleanup_folder'] = st.sidebar.text_input("Move Files to Folder:", value=st.session_state['cleanup_folder'])
    
    selected_paths = st.session_state.get('selected_paths', [])
    
    if st.sidebar.button("ðŸ—‘ï¸ Delete Selected", disabled=not selected_paths):
        success, failure = handle_file_action('delete', selected_paths)
        if success: st.toast(f"Deleted {success} files.", icon="âœ…")
        if failure: st.toast(f"Failed to delete {failure} files.", icon="âŒ")
        st.session_state['selected_paths'] = []
        time.sleep(1)
        st.rerun()

    if st.sidebar.button("âž¡ï¸ Move Selected", disabled=not selected_paths):
        success, failure = handle_file_action('move', selected_paths, st.session_state['cleanup_folder'])
        if success: st.toast(f"Moved {success} files.", icon="âœ…")
        if failure: st.toast(f"Failed to move {failure} files.", icon="âŒ")
        st.session_state['selected_paths'] = []
        time.sleep(1)
        st.rerun()
        
# --- CALL THE NEW ORCHESTRATOR RENDERER HERE ---
    render_orchestrator_status()


    # Data Refresh (Thread-Safe Reading)
    with CH.DATA_LOCK:
        metrics_history = CH.SHARED_HUB_DATA["metric_history"].copy()
        audit_report = CH.SHARED_HUB_DATA["file_audit_report"].copy()
        treemap_data = CH.SHARED_HUB_DATA["treemap_data"].copy()
        progress = CH.SHARED_HUB_DATA["scan_progress"]
        last_scan = CH.SHARED_HUB_DATA["last_scan_time"]
        # Network Data Fetch
        network_data = CH.SHARED_HUB_DATA.get("network_inventory", {}).copy()
        network_last_scan = CH.SHARED_HUB_DATA.get("network_last_scan", 0.0)
        
    progress_text = f"Scanner Cycle: {progress}%"
    st.progress(progress / 100, text=progress_text)

    # Added "Network Intel" Tab
    tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
        "Performance", 
        "Network Intel", 
        "Integrity Status", 
        "File Audit", 
        "Deep Scan", 
        "Treemap View"
    ])
    
    with tab1: render_system_metrics(metrics_history)
    with tab2: render_network_intel(network_data, network_last_scan) # New Render Call
    with tab3: render_integrity_status()
    with tab4: render_file_audit(audit_report)
    with tab5: 
        st.subheader("ðŸ”Ž Deep Scan")
        deep_data = audit_report.get('deep_scan_report', {}).get('ranked_files', [])
        if deep_data:
            st.dataframe(pd.DataFrame(deep_data), use_container_width=True)
        else:
            st.info("No deep scan results yet.")
    with tab6: render_file_treemap(treemap_data)

    st.markdown("---")
    render_logs()

    # UI Refresh Loop
    time.sleep(CH.MONITOR_INTERVAL_SEC)
    st.rerun()

if __name__ == "__main__":
    main_dashboard()