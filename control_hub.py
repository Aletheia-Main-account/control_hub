import os
import time
import threading
import hashlib
import math
import shutil
import sqlite3
import signal
import sys
import json
import subprocess
import re
from pathlib import Path
from datetime import datetime
from collections import defaultdict, deque
from typing import Dict, Any, List, Tuple, Optional, Deque
from dotenv import load_dotenv

# Load Environment Variables
load_dotenv(dotenv_path="./env/.env")

# Check for external dependencies
try:
    import psutil
except ImportError:
    print("CRITICAL WARNING: 'psutil' module not found. System metrics will be disabled.")
    psutil = None

# --- 1. SHARED STATE & LOCK ---
SHARED_HUB_DATA: Dict[str, Any] = {
    "system_metrics": {},
    "file_audit_report": {},
    "treemap_data": [],       
    "last_scan_time": 0.0,
    "scan_progress": 100,      
    "scan_start_timestamp": 0.0,
    "metric_history": {},
    "system_logs": deque(maxlen=50),
    "merkle_root": "Pending...", 
    "snapshot_status": "Initializing...",
    "network_inventory": {},
    "network_last_scan": 0.0,
    # --- NEW: ACTIVE DEFENSE STATE ---
    "arp_table": {},
    "security_alerts": [] 
}
DATA_LOCK = threading.RLock() 

# Cooperative Shutdown Signal
SHUTDOWN_EVENT = threading.Event()

# --- 2. CONFIGURATION ---
MONITOR_INTERVAL_SEC = 1 
SCANNER_INTERVAL_SEC = 15
ARP_POLL_INTERVAL_SEC = 5 # Aggressive polling for security
DUPLICATE_SCAN_PATH = os.getenv("CONTROL_HUB_SCAN_ROOT", os.path.join(os.getcwd(), 'sandbox_data'))
PROCESS_MONITOR_HISTORY = 60
TREEMAP_CANVAS_SIZE = (1200, 700) 
DB_PATH = os.getenv("CONTROL_HUB_DB_PATH", "control_hub_snapshots.db")

# --- 3. HELPER: LOGGING FUNCTION ---
def log_message(message: str):
    timestamp = datetime.now().strftime("%H:%M:%S")
    full_msg = f"[{timestamp}] {message}"
    print(full_msg) 
    with DATA_LOCK:
        SHARED_HUB_DATA["system_logs"].appendleft(full_msg)

# --- 4. SECURITY UTILITIES ---
def resolve_path_secure(path: str, base_dir: str = None) -> str:
    """Mitigates TOCTOU and Symlink Attacks."""
    if base_dir is None:
        base_dir = DUPLICATE_SCAN_PATH
    
    base = Path(base_dir).resolve()
    cwd = Path(os.getcwd()).resolve()

    if os.path.isabs(path):
        target = Path(path).resolve()
    else:
        target = (base / path).resolve()

    target_str = str(target)
    base_candidates = [str(base), str(cwd)]
    
    is_safe = False
    for safe_base in base_candidates:
        try:
            if os.path.commonpath([safe_base, target_str]) == safe_base:
                is_safe = True
                break
        except ValueError:
            continue
            
    if not is_safe:
         raise PermissionError(f"Security Violation: Path traversal attempt detected for {path}")
    
    return target_str

def shred_file(path: str):
    """Secure Deletion Implementation."""
    if not os.path.isfile(path): return
    try:
        file_size = os.path.getsize(path)
        with open(path, "r+b") as f:
            f.write(os.urandom(file_size))
            f.flush()
            os.fsync(f.fileno())
            f.seek(0)
            f.write(b'\x00' * file_size)
            f.flush()
            os.fsync(f.fileno())
        os.remove(path)
    except OSError as e:
        log_message(f"Shred Error: {e}")

# --- 5. SNAPSHOT & MERKLE MANAGER ---
class MerkleVerifier:
    @staticmethod
    def compute_merkle_root(hashes: List[str]) -> str:
        if not hashes: return "EMPTY_ROOT"
        tree = sorted(hashes)
        while len(tree) > 1:
            temp_tree = []
            for i in range(0, len(tree), 2):
                left = tree[i]
                right = tree[i+1] if i+1 < len(tree) else left
                combined = left + right
                temp_tree.append(hashlib.sha256(combined.encode()).hexdigest())
            tree = temp_tree
        return tree[0]

class SnapshotManager:
    def __init__(self, db_path=DB_PATH):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("PRAGMA journal_mode=WAL;")
                
                # File System Tables
                conn.execute("CREATE TABLE IF NOT EXISTS file_blobs (content_hash TEXT PRIMARY KEY, size_bytes INTEGER)")
                conn.execute("CREATE TABLE IF NOT EXISTS snapshots (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, merkle_root TEXT)")
                conn.execute("CREATE TABLE IF NOT EXISTS snapshot_manifest (snapshot_id INTEGER, file_path TEXT, content_hash TEXT)")
                
                # Network Intelligence Tables
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS device_inventory (
                        mac_address TEXT PRIMARY KEY,
                        vendor TEXT,
                        first_seen TEXT,
                        last_seen TEXT,
                        last_ip TEXT,
                        last_hostname TEXT
                    )
                """)
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS network_logs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        mac_address TEXT,
                        rssi INTEGER,
                        tx_bytes INTEGER,
                        rx_bytes INTEGER,
                        timestamp TEXT
                    )
                """)
                
                # --- NEW: Flight Recorder Table (System Stats) ---
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS system_stats (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT,
                        cpu_percent REAL,
                        ram_percent REAL,
                        disk_percent REAL
                    )
                """)
                conn.commit()
        except sqlite3.Error as e:
            log_message(f"DB Init Error: {e}")

    def get_last_merkle_root(self) -> str:
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT merkle_root FROM snapshots ORDER BY id DESC LIMIT 1")
                row = cursor.fetchone()
                return row[0] if row else None
        except sqlite3.Error:
            return None

    def save_snapshot(self, file_tracker: Dict[str, List[str]], merkle_root: str):
        timestamp = datetime.now().isoformat()
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("INSERT INTO snapshots (timestamp, merkle_root) VALUES (?, ?)", (timestamp, merkle_root))
                snapshot_id = cursor.lastrowid
                conn.commit()
        except sqlite3.Error as e:
            log_message(f"Snapshot Save Error: {e}")

    def save_network_log(self, devices: List[Dict], timestamp: Optional[str] = None):
        now = timestamp or datetime.now().isoformat()
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                for d in devices:
                    first_seen = d.get('first_seen', now)
                    cursor.execute("""
                        INSERT INTO device_inventory (mac_address, vendor, first_seen, last_seen, last_ip, last_hostname)
                        VALUES (?, ?, ?, ?, ?, ?)
                        ON CONFLICT(mac_address) DO UPDATE SET
                            last_seen=excluded.last_seen,
                            last_ip=excluded.last_ip,
                            last_hostname=excluded.last_hostname
                    """, (
                        d['mac'],
                        d.get('vendor', 'Unknown Vendor'),
                        first_seen,
                        now,
                        d.get('ip'),
                        d.get('hostname')
                    ))

                    cursor.execute("""
                        INSERT INTO network_logs (mac_address, rssi, tx_bytes, rx_bytes, timestamp)
                        VALUES (?, ?, ?, ?, ?)
                    """, (
                        d['mac'],
                        d.get('signal_strength'),
                        d.get('tx_delta', 0),
                        d.get('rx_delta', 0),
                        now
                    ))
                conn.commit()
        except sqlite3.Error as e:
            log_message(f"DB Network Save Error: {e}")

    # --- NEW: Save System Metrics (Flight Recorder) ---
    def save_system_metrics(self, metrics: Dict):
        now = datetime.now().isoformat()
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    "INSERT INTO system_stats (timestamp, cpu_percent, ram_percent, disk_percent) VALUES (?, ?, ?, ?)",
                    (now, metrics.get('cpu_util', 0), metrics.get('mem_util', 0), 0)
                )
                conn.commit()
        except Exception as e:
            log_message(f"DB Metrics Error: {e}")

# --- 6. CORE MONITORING CLASSES ---
class SystemMonitor:
    def __init__(self):
        self.metrics: Dict[str, Deque[float]] = {
            'cpu_util': deque(maxlen=PROCESS_MONITOR_HISTORY),
            'mem_util': deque(maxlen=PROCESS_MONITOR_HISTORY),
            'net_sent_rate': deque(maxlen=PROCESS_MONITOR_HISTORY),
            'net_recv_rate': deque(maxlen=PROCESS_MONITOR_HISTORY),
        }
        self._initial_net_counters = psutil.net_io_counters() if psutil else None
        self._last_net_time = time.time()

    def update_metrics(self) -> Dict[str, float]:
        if not psutil: return {}
        cpu_percent = psutil.cpu_percent(interval=None) 
        memory = psutil.virtual_memory()
        
        net_new = psutil.net_io_counters()
        now = time.time()
        time_diff = max(now - self._last_net_time, 1e-6)
        
        sent_rate = 0
        recv_rate = 0
        if self._initial_net_counters:
            sent_rate = (net_new.bytes_sent - self._initial_net_counters.bytes_sent) / time_diff
            recv_rate = (net_new.bytes_recv - self._initial_net_counters.bytes_recv) / time_diff
            
        self._initial_net_counters = net_new 
        self._last_net_time = now

        self.metrics['cpu_util'].append(cpu_percent)
        self.metrics['mem_util'].append(memory.percent)
        self.metrics['net_sent_rate'].append(sent_rate)
        self.metrics['net_recv_rate'].append(recv_rate)

        return {
            'cpu_util': cpu_percent, 
            'mem_util': memory.percent,
            'net_sent_kb_s': round(sent_rate / 1024, 2),
            'net_recv_kb_s': round(recv_rate / 1024, 2)
        }

class TMTree:
    def __init__(self, name: str, subtrees: List['TMTree'], data_size: int, full_path: str):
        self.name = name
        self.subtrees = subtrees
        self.data_size = data_size
        self.full_path = full_path
        self.rect = (0, 0, 0, 0)

    @classmethod
    def from_path(cls, path: str) -> Optional['TMTree']:
        try:
            secure_path = resolve_path_secure(path)
        except PermissionError:
            return None
        name = os.path.basename(secure_path) or secure_path
        try:
            if os.path.isfile(secure_path):
                size = os.path.getsize(secure_path)
                return cls(name, [], size, secure_path)
            
            subtrees = []
            total_size = 0
            with os.scandir(secure_path) as entries:
                for entry in entries:
                    if entry.name.startswith('.') or entry.name in ('$RECYCLE.BIN', 'System Volume Information', 'control_hub_snapshots.db'):
                        continue
                    subtree = cls.from_path(entry.path)
                    if subtree and subtree.data_size > 0:
                        subtrees.append(subtree)
                        total_size += subtree.data_size
            subtrees.sort(key=lambda t: t.data_size, reverse=True)
            return cls(name, subtrees, total_size, secure_path)
        except (OSError, PermissionError):
            return None
        
    def update_rectangles(self, rect: Tuple[int, int, int, int]) -> None:
        x, y, width, height = rect
        self.rect = (x, y, width, height)
        if not self.subtrees or self.data_size == 0 or min(width, height) <= 1: return

        if width > height:
            current_x = x
            for subtree in self.subtrees:
                sub_width = math.floor(width * subtree.data_size / self.data_size) 
                if subtree is self.subtrees[-1]: sub_width = x + width - current_x
                subtree.update_rectangles((current_x, y, sub_width, height))
                current_x += sub_width
        else: 
            current_y = y
            for subtree in self.subtrees:
                sub_height = math.floor(height * subtree.data_size / self.data_size) 
                if subtree is self.subtrees[-1]: sub_height = y + height - current_y
                subtree.update_rectangles((x, current_y, width, sub_height))
                current_y += sub_height

    def to_visualization_data(self) -> List[Dict[str, Any]]:
        data = []
        stack = [self]
        while stack:
            node = stack.pop()
            data.append({
                'name': node.name,
                'path': node.full_path,
                'size': node.data_size,
                'rect': node.rect
            })
            stack.extend(node.subtrees)
        return data

class FileManager:
    def _get_file_hash(self, filepath: str) -> Optional[str]:
        hasher = hashlib.sha256()
        try:
            with open(filepath, 'rb') as f:
                while chunk := f.read(65536): hasher.update(chunk)
            return hasher.hexdigest()
        except (IOError, OSError): return None

    def find_duplicates(self, root_dir: str) -> Tuple[Dict[str, Any], Dict[str, List[str]]]:
        try:
            secure_root = resolve_path_secure(root_dir)
        except PermissionError:
            return {}, {}

        file_tracker = defaultdict(list)
        for folder, _, files in os.walk(secure_root):
            for file in files:
                if file == DB_PATH: continue 
                file_path = os.path.join(folder, file)
                try:
                    file_size = os.path.getsize(file_path)
                    if file_size > 0:
                        file_hash = self._get_file_hash(file_path)
                        if file_hash: file_tracker[(file_size, file_hash)].append(file_path)
                except OSError: continue

        duplicate_groups = []
        total_wasted = 0
        for (size, hash_val), paths in file_tracker.items():
            if len(paths) > 1:
                wasted = (len(paths) - 1) * size
                total_wasted += wasted
                duplicate_groups.append({'hash': hash_val, 'size': size, 'paths': paths, 'wasted_space_bytes': wasted, 'size_kb': round(size/1024, 2)})

        report = {'total_duplicate_files': sum(len(g['paths']) for g in duplicate_groups), 'duplicate_groups': duplicate_groups, 'total_wasted_space_bytes': total_wasted}
        return report, file_tracker

    def deep_scan_and_rank(self, tree_root: 'TMTree', keywords: List[str]) -> Dict[str, Any]:
        if not tree_root: return {}
        rank_report = {'total_ranked_files': 0, 'ranked_files': []}
        keywords_lower = [k.lower() for k in keywords]
        stack = [tree_root]
        while stack:
            node = stack.pop()
            if node.subtrees:
                stack.extend(node.subtrees)
                continue
            path_lower = node.full_path.lower()
            matches = [k for k in keywords_lower if k in path_lower]
            if matches:
                rank_report['total_ranked_files'] += 1
                rank_report['ranked_files'].append({'path': node.full_path, 'rank': len(matches), 'matches': matches})
        rank_report['ranked_files'].sort(key=lambda x: x['rank'], reverse=True)
        return rank_report

    def delete_file_or_folder(self, path: str) -> bool:
        try:
            secure_path = resolve_path_secure(path)
            if os.path.isfile(secure_path): 
                shred_file(secure_path)
                log_message(f"SECURE ACTION: Shredded {secure_path}")
            elif os.path.isdir(secure_path): 
                shutil.rmtree(secure_path)
                log_message(f"ACTION: Deleted folder {secure_path}")
            return True
        except Exception as e:
            log_message(f"ERROR: Failed to delete {path} - {e}")
            return False

    def move_file_or_folder(self, source_path: str, destination_folder: str) -> bool:
        try:
            src = resolve_path_secure(source_path)
            dst_folder = resolve_path_secure(destination_folder)
            shutil.move(src, dst_folder)
            log_message(f"ACTION: Moved {src} to {dst_folder}")
            return True
        except Exception as e:
            log_message(f"ERROR: Failed to move {source_path} - {e}")
            return False

# --- 7. NEW: ACTIVE DEFENSE (ARP WATCHDOG) ---
class ArpWatchdog:
    """Monitors the system ARP table for poisoning attacks."""
    def __init__(self):
        self.ip_mac_map = {}
        self.mac_ip_map = defaultdict(list)
        
    def _parse_arp_table(self):
        """Cross-platform ARP table parser."""
        current_map = {}
        try:
            if sys.platform == "win32":
                output = subprocess.check_output("arp -a", shell=True).decode("cp437") # Safe encoding
                # Regex for Windows: IP ... MAC ... Type
                matches = re.findall(r"(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F-]{17})\s+(\w+)", output)
                for ip, mac, type_ in matches:
                    if type_ == "dynamic":
                        current_map[ip] = mac.replace('-', ':').upper()
            else:
                # Linux/Unix/Mac
                output = subprocess.check_output("arp -a", shell=True).decode("utf-8")
                # Typical format: ? (192.168.1.1) at 0:50:56:c0:0:8 on eth0
                matches = re.findall(r"\((\d{1,3}(?:\.\d{1,3}){3})\) at ([0-9a-fA-F:]{17})", output)
                for ip, mac in matches:
                    current_map[ip] = mac.upper()
        except Exception as e:
            log_message(f"ARP Parse Error: {e}")
        return current_map

    def scan_cycle(self):
        """Detects duplicate MACs (Poisoning) and Gateway changes."""
        new_map = self._parse_arp_table()
        alerts = []
        
        # Invert map to check for MACs claiming multiple IPs
        inverted_map = defaultdict(list)
        for ip, mac in new_map.items():
            inverted_map[mac].append(ip)
            
        # Analysis Rule 1: MAC Spoofing (One MAC, Multiple IPs)
        for mac, ips in inverted_map.items():
            if len(ips) > 1 and "FF:FF:FF:FF:FF:FF" not in mac:
                # Whitelist Broadcasts/Multicasts if needed
                alerts.append(f"[CRITICAL] ARP POISONING DETECTED: MAC {mac} is claiming IPs: {ips}")

        # Update Shared State
        with DATA_LOCK:
            SHARED_HUB_DATA["arp_table"] = new_map
            if alerts:
                # Append unique alerts
                existing = set(SHARED_HUB_DATA["security_alerts"])
                for a in alerts:
                    if a not in existing:
                        SHARED_HUB_DATA["security_alerts"].append(a)
                        log_message(a)

    def start_loop(self):
        log_message("Active Defense: ARP Watchdog Started.")
        while not SHUTDOWN_EVENT.is_set():
            self.scan_cycle()
            time.sleep(ARP_POLL_INTERVAL_SEC)

# --- 8. NETWORK INTELLIGENCE (NetIntel) ---
try:
    from arris_tg2492lg import ConnectBox
    from mac_vendor_lookup import MacLookup
    import aiohttp
    import asyncio
except ImportError:
    print("WARNING: Network dependencies missing. NetIntel disabled.")
    ConnectBox = None

class NetworkManager:
    """NetIntel Module: Stealth router interrogation & Ghost Tracking."""
    def __init__(self, db_manager: SnapshotManager):
        self.router_ip = os.getenv("ROUTER_IP", "192.168.178.1")
        self.router_pass = os.getenv("ROUTER_PASS", "") 
        self.poll_interval = int(os.getenv("NETWORK_POLL_SEC", 30))
        self.db_manager = db_manager
        
        self.mac_lookup = MacLookup()
        try:
            self.mac_lookup.lookup("00:00:00:00:00:00") 
        except:
            print("Initializing MAC Vendor DB...")
            try:
                self.mac_lookup.update_vendors()
            except:
                print("WARNING: Could not update MAC Vendor DB.")

        self.previous_traffic = {} 

    def _get_vendor(self, mac: str) -> str:
        try:
            return self.mac_lookup.lookup(mac)
        except:
            return "Unknown Vendor"

    async def _stealth_poll_cycle(self):
        """Single Shot Lifecycle: Login -> Query -> Logout -> Simulation Fallback."""
        import random
        timestamp = datetime.now().isoformat()
        
        # --- SIMULATION MODE ---
        use_simulation = True 

        if use_simulation or not ConnectBox or not self.router_pass:
            fake_macs = ["AC:12:34:56:78:90", "BC:23:45:67:89:01", "CC:34:56:78:90:12"]
            live_devices = []
            
            for i, mac in enumerate(fake_macs):
                tx = random.randint(100, 5000000) if random.random() > 0.5 else 0
                rx = random.randint(100, 10000000) if random.random() > 0.5 else 0
                
                device_info = {
                    "mac": mac,
                    "ip": f"192.168.178.{100+i}",
                    "hostname": f"Simulated-Device-{i+1}",
                    "vendor": "Simulation Corp",
                    "status": "Online",
                    "interface": "WiFi" if i < 2 else "Ethernet",
                    "signal_strength": random.randint(-80, -30),
                    "last_seen": timestamp,
                    "tx_delta": tx,
                    "rx_delta": rx
                }
                live_devices.append(device_info)
            
            with DATA_LOCK:
                existing = SHARED_HUB_DATA.get("network_inventory", {})
                for d in live_devices:
                    existing[d['mac']] = d
                SHARED_HUB_DATA["network_inventory"] = existing
                SHARED_HUB_DATA["network_last_scan"] = time.time()
                
            self.db_manager.save_network_log(live_devices)
            return

        # --- REAL HARDWARE LOGIC ---
        async with aiohttp.ClientSession() as session:
            client = ConnectBox(session, self.router_ip, self.router_pass)
            try:
                await client.async_login()
                devices = await client.async_get_connected_devices()
                await client.async_logout()
                
                live_devices = []
                for dev in devices:
                    mac = dev.mac.upper()
                    curr_tx = getattr(dev, 'tx_bytes', 0)
                    curr_rx = getattr(dev, 'rx_bytes', 0)
                    prev_stats = self.previous_traffic.get(mac, {'tx': 0, 'rx': 0})
                    
                    delta_tx = max(0, curr_tx - prev_stats['tx'])
                    delta_rx = max(0, curr_rx - prev_stats['rx'])
                    self.previous_traffic[mac] = {'tx': curr_tx, 'rx': curr_rx}

                    device_info = {
                        "mac": mac,
                        "ip": dev.ip,
                        "hostname": dev.hostname,
                        "vendor": self._get_vendor(mac),
                        "status": "Online",
                        "interface": "WiFi" if dev.interface == "wlan" else "Ethernet",
                        "signal_strength": getattr(dev, 'rssi', 0),
                        "last_seen": timestamp,
                        "tx_delta": delta_tx,
                        "rx_delta": delta_rx
                    }
                    live_devices.append(device_info)

                with DATA_LOCK:
                    existing_inventory = SHARED_HUB_DATA.get("network_inventory", {})
                    for d in existing_inventory.values():
                        d['status'] = "Offline"
                    for d in live_devices:
                        existing_inventory[d['mac']] = d
                    SHARED_HUB_DATA["network_inventory"] = existing_inventory
                    SHARED_HUB_DATA["network_last_scan"] = time.time()

                self.db_manager.save_network_log(live_devices)

            except Exception as e:
                log_message(f"NetIntel Error: {str(e)}")
                try: await client.async_logout()
                except: pass

    def start_loop(self):
        if not ConnectBox: return
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        log_message(f"NetIntel: Starting Stealth Polling (Interval: {self.poll_interval}s)")
        
        while not SHUTDOWN_EVENT.is_set():
            loop.run_until_complete(self._stealth_poll_cycle())
            for _ in range(self.poll_interval):
                if SHUTDOWN_EVENT.is_set(): break
                time.sleep(1)
        loop.close()
        log_message("NetIntel: Stopped.")

# --- 9. MAIN EXECUTION AGENT ---
def start_background_threads():
    # 1. System Monitor
    monitor = SystemMonitor()
    m_thread = threading.Thread(
        target=monitor_thread_target, 
        args=(monitor,), 
        daemon=False,
        name="MonitorThread"
    )
    
    # 2. File Scanner
    scanner_fm = FileManager()
    s_thread = threading.Thread(
        target=scanner_thread_target, 
        args=(scanner_fm, DUPLICATE_SCAN_PATH), 
        daemon=False,
        name="ScannerThread"
    )

    # 3. Network Intel
    db_man = SnapshotManager()
    net_man = NetworkManager(db_man)
    n_thread = threading.Thread(
        target=net_man.start_loop,
        daemon=False,
        name="NetworkThread"
    )

    # 4. Active Defense (ARP Watchdog)
    arp_watch = ArpWatchdog()
    a_thread = threading.Thread(
        target=arp_watch.start_loop,
        daemon=False,
        name="ArpWatchdogThread"
    )

    m_thread.start()
    s_thread.start()
    n_thread.start()
    a_thread.start() # Start the hunter

    return [m_thread, s_thread, n_thread, a_thread]

# WRAPPER TARGETS for Threads
def monitor_thread_target(monitor_instance):
    log_message("Monitor Thread Started.")
    # Create a dedicated DB manager for this thread
    snapshot_mgr = SnapshotManager() 
    
    while not SHUTDOWN_EVENT.is_set():
        current_metrics = monitor_instance.update_metrics()
        
        # 1. Update In-Memory State (For Dashboard)
        with DATA_LOCK:
            SHARED_HUB_DATA["system_metrics"] = current_metrics
            SHARED_HUB_DATA["metric_history"] = {k: list(v) for k, v in monitor_instance.metrics.items()}
            elapsed = time.time() - SHARED_HUB_DATA["scan_start_timestamp"]
            if SHARED_HUB_DATA["scan_progress"] < 100:
                SHARED_HUB_DATA["scan_progress"] = min(95, int((elapsed / SCANNER_INTERVAL_SEC) * 100))
        
        # 2. NEW: Persist to Database (Flight Recorder)
        snapshot_mgr.save_system_metrics(current_metrics)
        
        time.sleep(MONITOR_INTERVAL_SEC)
    log_message("Monitor Thread Stopped.")

def scanner_thread_target(file_manager_instance, path):
    DEEP_SCAN_KEYWORDS = ['report', 'invoice', 'backup', 'log', 'config', 'temp', 'data', 'secret']
    snapshot_mgr = SnapshotManager()
    log_message(f"Scanner Thread Started on path: {path}")

    while not SHUTDOWN_EVENT.is_set():
        with DATA_LOCK:
            SHARED_HUB_DATA["scan_start_timestamp"] = time.time()
            SHARED_HUB_DATA["scan_progress"] = 5
            SHARED_HUB_DATA["snapshot_status"] = "Scanning..."

        start_scan = time.time()
        audit_report, file_tracker = file_manager_instance.find_duplicates(path)
        
        all_hashes = [h for (_, h), _ in file_tracker.items()]
        current_merkle_root = MerkleVerifier.compute_merkle_root(all_hashes)
        last_merkle_root = snapshot_mgr.get_last_merkle_root()
        
        has_treemap = False
        with DATA_LOCK:
            has_treemap = bool(SHARED_HUB_DATA.get("treemap_data"))

        if current_merkle_root == last_merkle_root and has_treemap:
            log_message("Integrity Verified: Merkle Root match. Skipping heavy I/O.")
            with DATA_LOCK:
                SHARED_HUB_DATA["snapshot_status"] = "Verified (Synced)"
                SHARED_HUB_DATA["merkle_root"] = current_merkle_root
                SHARED_HUB_DATA["scan_progress"] = 100
                SHARED_HUB_DATA["last_scan_time"] = time.time()
        else:
            log_message("Integrity Variance Detected. Updating Snapshot...")
            tree_root = TMTree.from_path(path)
            viz_data = []
            rank_report = {}
            if tree_root:
                tree_root.update_rectangles((0, 0, TREEMAP_CANVAS_SIZE[0], TREEMAP_CANVAS_SIZE[1])) 
                viz_data = tree_root.to_visualization_data()
                rank_report = file_manager_instance.deep_scan_and_rank(tree_root, DEEP_SCAN_KEYWORDS)
            
            audit_report['deep_scan_report'] = rank_report
            with DATA_LOCK:
                SHARED_HUB_DATA["file_audit_report"] = audit_report
                SHARED_HUB_DATA["treemap_data"] = viz_data
                SHARED_HUB_DATA["merkle_root"] = current_merkle_root
                SHARED_HUB_DATA["snapshot_status"] = "Updated & Saved"
                SHARED_HUB_DATA["last_scan_time"] = time.time()
                SHARED_HUB_DATA["scan_progress"] = 100
            
            snapshot_mgr.save_snapshot(file_tracker, current_merkle_root)

        elapsed_total = time.time() - start_scan
        wait_time = max(0, SCANNER_INTERVAL_SEC - elapsed_total)
        
        for _ in range(int(wait_time)):
            if SHUTDOWN_EVENT.is_set(): break
            time.sleep(1)

    log_message("Scanner Thread Stopped.")

if __name__ == "__main__":
    def signal_handler(sig, frame):
        print("\nShutdown Signal Received. Stopping threads...")
        SHUTDOWN_EVENT.set()

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    print("--- DYNAMIC CONTROL HUB STARTING ---")
    threads = start_background_threads()
    
    for t in threads:
        t.join()
        
    print("--- SYSTEM HALTED SAFELY ---")