# app.py
from flask import Flask, jsonify, request
import threading
import time
from datetime import datetime
from provenance_watcher import ProvenanceWatcher

app = Flask(__name__)

# --- SWARM STATE MANAGEMENT ---
# Stores the heartbeat of every connected PC
SWARM_STATE = {}
STATE_LOCK = threading.Lock()

# Initialize the Watcher
watcher = ProvenanceWatcher()
watcher_thread = threading.Thread(target=watcher.start_watching, daemon=True)
watcher_thread.start()

@app.route('/api/status', methods=['GET'])
def get_status():
    """Returns the orchestrator status AND the swarm state."""
    with STATE_LOCK:
        # cleanup: remove nodes that haven't reported in 60 seconds
        current_time = time.time()
        active_nodes = {
            k: v for k, v in SWARM_STATE.items() 
            if (current_time - v['last_checkin_ts']) < 60
        }
        
    return jsonify({
        "status": "online",
        "role": "Meta-Orchestrator",
        "watcher_active": watcher_thread.is_alive(),
        "swarm_nodes": active_nodes, # <--- The Dashboard reads this
        "events": list(watcher.events)
    })

@app.route('/api/telemetry/ingest', methods=['POST'])
def ingest_telemetry():
    """
    Endpoint for Secondary PCs to upload their stats.
    """
    data = request.json
    if not data:
        return jsonify({"error": "No data"}), 400
        
    hostname = data.get("hostname", "Unknown-Agent")
    
    with STATE_LOCK:
        SWARM_STATE[hostname] = {
            "ip": request.remote_addr, 
            "cpu": data.get("cpu", 0),
            "ram": data.get("ram", 0),
            "disk": data.get("disk", 0),
            "status": "Online",
            "last_seen": datetime.now().strftime("%H:%M:%S"),
            "last_checkin_ts": time.time()
        }
        
    return jsonify({"status": "accepted"}), 202

@app.route('/api/start-simulation', methods=['POST'])
def start_simulation():
    return jsonify({"msg": "Simulation dispatched", "status": "PENDING"}), 202

if __name__ == '__main__':
    print("--- Swarm Orchestrator (Server) Starting on Port 5000 ---")
    # 0.0.0.0 is crucial to allow the Secondary PC to connect
    app.run(host='0.0.0.0', port=5000)