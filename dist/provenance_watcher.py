import os
import time
import json
import threading
from datetime import datetime
from collections import deque

class ProvenanceWatcher:
    """
    Reactive Engine: Monitors a directory for 'Genesis Artifacts' (completed jobs).
    Decouples the heavy lifting (HPC) from the visualization.
    """
    def __init__(self, watch_dir="provenance_reports"):
        self.watch_dir = watch_dir
        self.events = deque(maxlen=50)  # In-memory event log
        self.active_runs = {}           # Track running jobs
        self._stop_event = threading.Event()
        
        # Ensure directory exists
        if not os.path.exists(self.watch_dir):
            os.makedirs(self.watch_dir)

    def _process_artifact(self, filepath):
        """Ingests a completed job artifact."""
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)
            
            job_id = data.get('job_id', 'unknown')
            timestamp = datetime.now().strftime("%H:%M:%S")
            
            # Create a human-readable event
            event_msg = f"[{timestamp}] âœ… Job {job_id} Completed. Hash: {data.get('hash', 'N/A')[:8]}..."
            self.events.appendleft(event_msg)
            
            # Avoid re-processing (Simple in-memory tracking)
            self.active_runs.setdefault('processed', []).append(os.path.basename(filepath))
            print(f"--> Watcher detected artifact: {os.path.basename(filepath)}")
            
        except json.JSONDecodeError:
            print(f"[Watcher Warning] Corrupted artifact: {filepath}")

    def start_watching(self):
        """Main loop for the background thread."""
        print(f"--- Provenance Watcher Active on directory: {self.watch_dir} ---")
        already_processed = set(os.listdir(self.watch_dir))
        
        while not self._stop_event.is_set():
            current_files = set(os.listdir(self.watch_dir))
            new_files = current_files - already_processed
            
            for filename in new_files:
                if filename.startswith("provenance_") and filename.endswith(".json"):
                    self._process_artifact(os.path.join(self.watch_dir, filename))
            
            already_processed = current_files
            time.sleep(1)  # fast reactive loop

    def stop(self):
        self._stop_event.set()