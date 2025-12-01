# agent.py
import time
import psutil
import requests
import socket
import sys

# --- CONFIGURATION ---
# IMPORTANT: Replace this with the IP of your MAIN PC (Orchestrator)
# Run 'ipconfig' (Windows) or 'hostname -I' (Linux) on the Main PC to find it.
ORCHESTRATOR_PORT = 5000
POLL_INTERVAL = 2 

def get_system_stats():
    """Gathers local performance data."""
    return {
        "hostname": socket.gethostname(),
        "cpu": psutil.cpu_percent(interval=1),
        "ram": psutil.virtual_memory().percent,
        "disk": psutil.disk_usage('/').percent
    }

def run_agent():
    url = f"http://{ORCHESTRATOR_IP}:{ORCHESTRATOR_PORT}/api/telemetry/ingest"
    hostname = socket.gethostname()
    
    print(f"--- 🐝 Swarm Agent: {hostname} ---")
    print(f"--- Target Orchestrator: {url} ---")
    
    while True:
        try:
            payload = get_system_stats()
            response = requests.post(url, json=payload, timeout=2)
            
            if response.status_code == 202:
                print(f"✅ [Sent] CPU: {payload['cpu']}% | RAM: {payload['ram']}%")
            else:
                print(f"⚠️ [Server Error] {response.status_code}")
                
        except requests.exceptions.ConnectionError:
            print(f"❌ [Connection Failed] Is the Main PC running app.py?")
            print(f"   Retrying in {POLL_INTERVAL} seconds...")
        except Exception as e:
            print(f"❌ [Error] {e}")
            
        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    run_agent()