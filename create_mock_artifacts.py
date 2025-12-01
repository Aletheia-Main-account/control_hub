# create_mock_artifacts.py
import json
import time
import os
import uuid
import random

TARGET_DIR = "provenance_reports"

if not os.path.exists(TARGET_DIR):
    os.makedirs(TARGET_DIR)

print(f"--- HPC Simulation Mock Generator ---")
print(f"Targeting: {os.path.abspath(TARGET_DIR)}")

while True:
    input("Press Enter to simulate a completed job (or Ctrl+C to quit)...")
    
    job_id = str(uuid.uuid4())[:8]
    filename = f"provenance_{job_id}.json"
    filepath = os.path.join(TARGET_DIR, filename)
    
    data = {
        "job_id": job_id,
        "status": "SUCCESS",
        "hash": str(uuid.uuid4()), # Fake Merkle root
        "metrics": {
            "duration": random.randint(10, 500),
            "convergence": 0.001 * random.random()
        }
    }
    
    with open(filepath, 'w') as f:
        json.dump(data, f)
        
    print(f"generated artifact: {filename}")