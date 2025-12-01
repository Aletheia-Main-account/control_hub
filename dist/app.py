# app.py
from flask import Flask, jsonify, request
import threading
import uuid
from provenance_watcher import ProvenanceWatcher

app = Flask(__name__)

# Initialize the Watcher
watcher = ProvenanceWatcher()
watcher_thread = threading.Thread(target=watcher.start_watching, daemon=True)
watcher_thread.start()

@app.route('/api/status', methods=['GET'])
def get_status():
    """Returns the latest events captured by the Watcher."""
    return jsonify({
        "status": "online",
        "events": list(watcher.events),
        "watcher_active": watcher_thread.is_alive()
    })

@app.route('/api/start-simulation', methods=['POST'])
def start_simulation():
    """
    Simulates sending a job to an HPC cluster.
    In reality, this would dispatch a task to a worker node.
    """
    job_id = str(uuid.uuid4())[:8]
    # Logic to dispatch job would go here
    return jsonify({
        "message": "Simulation dispatched",
        "job_id": job_id,
        "status": "PENDING"
    }), 202

if __name__ == '__main__':
    print("--- Meta-Orchestrator (Signaler) Starting on Port 5000 ---")
    app.run(host='0.0.0.0', port=5000)