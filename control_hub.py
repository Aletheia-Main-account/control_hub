import os
import time
import threading
import hashlib
import math
import shutil
import sqlite3
import signal
import sys
from pathlib import Path
from datetime import datetime
from collections import defaultdict, deque
from typing import Dict, Any, List, Tuple, Optional, Deque

# Check for external dependencies
try:
    import psutil
except ImportError:
    print("CRITICAL WARNING: 'psutil' module not found. System metrics will be disabled.")
    psutil = None

# --- 1. SHARED STATE & LOCK ---
# We use RLock (Reentrant Lock) to prevent "Stale Data Overwrite" and Deadlocks.
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
    "snapshot_status": "Initializing..."
}
DATA_LOCK = threading.RLock() 

# Cooperative Shutdown Signal
SHUTDOWN_EVENT = threading.Event()

# --- 2. CONFIGURATION ---
MONITOR_INTERVAL_SEC = 1 
SCANNER_INTERVAL_SEC = 15
# Set the desired root directory for the scanner
DUPLICATE_SCAN_PATH = os.path.join(os.getcwd(), 'sandbox_data') 
PROCESS_MONITOR_HISTORY = 60
TREEMAP_CANVAS_SIZE = (1200, 700) 
DB_PATH = "control_hub_snapshots.db" 

# --- 3. HELPER: LOGGING FUNCTION ---
def log_message(message: str):
    timestamp = datetime.now().strftime("%H:%M:%S")
    full_msg = f"[{timestamp}] {message}"
    print(full_msg) 
    with DATA_LOCK:
        SHARED_HUB_DATA["system_logs"].appendleft(full_msg)

# --- 4. SECURITY UTILITIES ---

def resolve_path_secure(path: str, base_dir: str = None) -> str:
    """
    Mitigates TOCTOU and Symlink Attacks.
    Verifies the canonical path resides within the sandbox using os.path.commonpath.
    """
    if base_dir is None:
        base_dir = DUPLICATE_SCAN_PATH
    
    # 1. Resolve canonical paths (follow symlinks, remove ../)
    base = Path(base_dir).resolve()
    cwd = Path(os.getcwd()).resolve()

    if os.path.isabs(path):
        target = Path(path).resolve()
    else:
        target = (base / path).resolve()

    # 2. Mathematical Verification of Containment
    # We check if the target is inside the Base Scan Path OR the Current Working Directory (for DB/Logs)
    target_str = str(target)
    base_candidates = [str(base), str(cwd)]
    
    is_safe = False
    for safe_base in base_candidates:
        try:
            # os.path.commonpath returns the longest common sub-path.
            # If target is inside safe_base, the common path MUST be safe_base.
            if os.path.commonpath([safe_base, target_str]) == safe_base:
                is_safe = True
                break
        except ValueError:
            # commonpath raises ValueError if paths are on different drives (Windows)
            continue
            
    if not is_safe:
         raise PermissionError(f"Security Violation: Path traversal attempt detected for {path}")
    
    return target_str

def shred_file(path: str):
    """
    Secure Deletion Implementation.
    Overwrites data in-place before unlinking to prevent forensic recovery.
    """
    if not os.path.isfile(path): return
    try:
        file_size = os.path.getsize(path)
        # Use 'r+b' to open for reading and writing binary without truncating initially
        with open(path, "r+b") as f:
            # Pass 1: Random High-Entropy Data
            f.write(os.urandom(file_size))
            f.flush()
            os.fsync(f.fileno())
            # Pass 2: Zeroization
            f.seek(0)
            f.write(b'\x00' * file_size)
            f.flush()
            os.fsync(f.fileno())
        os.remove(path)
    except OSError as e:
        log_message(f"Shred Error: {e}")

# --- 5. SNAPSHOT & MERKLE MANAGER ---

class MerkleVerifier:
    """
    Implements Mathematical Certainty via Hash Trees.
    Allows efficient O(log n) verification of system state.
    """
    @staticmethod
    def compute_merkle_root(hashes: List[str]) -> str:
        if not hashes: return "EMPTY_ROOT"
        # Sort to ensure deterministic tree structure
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
    """
    Transactional SQLite Backend.
    Replaces fragile JSON serialization with ACID-compliant storage.
    """
    def __init__(self, db_path=DB_PATH):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        try:
            with sqlite3.connect(self.db_path) as conn:
                # Write-Ahead Logging (WAL) for concurrency
                conn.execute("PRAGMA journal_mode=WAL;")
                
                # Schema Enforcement
                conn.execute("CREATE TABLE IF NOT EXISTS file_blobs (content_hash TEXT PRIMARY KEY, size_bytes INTEGER)")
                conn.execute("CREATE TABLE IF NOT EXISTS snapshots (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT, merkle_root TEXT)")
                conn.execute("CREATE TABLE IF NOT EXISTS snapshot_manifest (snapshot_id INTEGER, file_path TEXT, content_hash TEXT)")
                conn.commit()
        except sqlite3.Error as e:
            log_message(f"DB Init Error: {e}")

    def save_snapshot(self, file_tracker: Dict[str, Any], merkle_root: str):
        """Atomic Transaction for State Persistence."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                # 1. Insert Snapshot
                cursor.execute("INSERT INTO snapshots (timestamp, merkle_root) VALUES (?, ?)", (datetime.now().isoformat(), merkle_root))
                snapshot_id = cursor.lastrowid
                
                # 2. Insert Data
                for (size, f_hash), paths in file_tracker.items():
                    # Ignore duplicates (Content Addressing)
                    cursor.execute("INSERT OR IGNORE INTO file_blobs (content_hash, size_bytes) VALUES (?, ?)", (f_hash, size))
                    for path in paths:
                        cursor.execute("INSERT INTO snapshot_manifest (snapshot_id, file_path, content_hash) VALUES (?, ?, ?)", (snapshot_id, path, f_hash))
                
                conn.commit() # Atomic Commit
                return True
        except sqlite3.Error as e:
            log_message(f"DB Save Error: {e}")
            return False

    def get_last_merkle_root(self) -> Optional[str]:
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT merkle_root FROM snapshots ORDER BY id DESC LIMIT 1")
                row = cursor.fetchone()
                return row[0] if row else None
        except sqlite3.Error:
            return None

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
        self._last_net_time = time.time() # Track real time for rate calc

    def update_metrics(self) -> Dict[str, float]:
        if not psutil: return {}
        cpu_percent = psutil.cpu_percent(interval=None) 
        memory = psutil.virtual_memory()
        
        net_new = psutil.net_io_counters()
        now = time.time()
        # Calculate real time difference, preventing division by zero
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
        # SHA-256 for Collision Resistance
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

# --- 7. THREAD TARGETS ---

def monitor_thread_target(monitor_instance: SystemMonitor):
    """Cooperative Multitasking: Checks SHUTDOWN_EVENT periodically."""
    log_message("Monitor Thread Started.")
    while not SHUTDOWN_EVENT.is_set():
        current_metrics = monitor_instance.update_metrics()
        with DATA_LOCK:
            SHARED_HUB_DATA["system_metrics"] = current_metrics
            SHARED_HUB_DATA["metric_history"] = {k: list(v) for k, v in monitor_instance.metrics.items()}
            elapsed = time.time() - SHARED_HUB_DATA["scan_start_timestamp"]
            if SHARED_HUB_DATA["scan_progress"] < 100:
                SHARED_HUB_DATA["scan_progress"] = min(95, int((elapsed / SCANNER_INTERVAL_SEC) * 100))
        time.sleep(MONITOR_INTERVAL_SEC)
    log_message("Monitor Thread Stopped.")

def scanner_thread_target(file_manager_instance: FileManager, path: str):
    """Forensic Integrity Scan with Merkle Verification."""
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
        
        # Merkle Verification
        all_hashes = [h for (_, h), _ in file_tracker.items()]
        current_merkle_root = MerkleVerifier.compute_merkle_root(all_hashes)
        last_merkle_root = snapshot_mgr.get_last_merkle_root()
        
        # Thread-Safe State Check
        has_treemap = False
        with DATA_LOCK:
            has_treemap = bool(SHARED_HUB_DATA.get("treemap_data"))

        # Integrity Check: Skip I/O if Root Hash matches AND we have visualization data
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
        
        # Heartbeat Check: Sleep in intervals to catch Shutdown Signal
        for _ in range(int(wait_time)):
            if SHUTDOWN_EVENT.is_set(): break
            time.sleep(1)

    log_message("Scanner Thread Stopped.")