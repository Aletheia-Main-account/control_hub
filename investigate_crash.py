import sqlite3
import os
from datetime import datetime

# Configuration
DB_PATH = "control_hub_snapshots.db"

def analyze_crash():
    if not os.path.exists(DB_PATH):
        print(f"❌ Error: Database not found at {DB_PATH}")
        return

    print(f"🔎 INVESTIGATING CRASH ARTIFACTS IN: {DB_PATH}")
    print("-" * 50)

    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        # 1. Establish Time of Death (Last Network Log)
        print("\n[1] NETWORK TIMELINE (Last 5 events):")
        try:
            cursor.execute("SELECT timestamp, mac_address, tx_bytes, rx_bytes FROM network_logs ORDER BY id DESC LIMIT 5")
            rows = cursor.fetchall()
            if rows:
                for row in rows:
                    ts, mac, tx, rx = row
                    print(f"   🕒 {ts} | MAC: {mac} | Up: {tx} | Down: {rx}")
                print(f"\n💀 ESTIMATED TIME OF DEATH: {rows[0][0]}")
            else:
                print("   (No network logs found)")
        except sqlite3.OperationalError:
            print("   (Network log table missing or corrupt)")

        # 2. Check for File Operations (Last Snapshot)
        print("\n[2] FILE SYSTEM STATE (Last Snapshot):")
        try:
            cursor.execute("SELECT timestamp, merkle_root FROM snapshots ORDER BY id DESC LIMIT 1")
            row = cursor.fetchone()
            if row:
                print(f"   🕒 {row[0]} | Root Hash: {row[1]}")
            else:
                print("   (No snapshots found)")
        except sqlite3.OperationalError:
            print("   (Snapshot table missing)")

        # 3. Check Device Inventory (Who was connected?)
        print("\n[3] SUSPECT LIST (Devices active at crash):")
        try:
            cursor.execute("SELECT ip, hostname, vendor, last_seen FROM device_inventory ORDER BY last_seen DESC LIMIT 5")
            rows = cursor.fetchall()
            for row in rows:
                print(f"   📱 {row[1]} ({row[0]}) | {row[2]} | Last Seen: {row[3]}")
        except sqlite3.OperationalError:
            print("   (Inventory table missing)")

    except Exception as e:
        print(f"❌ FATAL ERROR: {e}")
    finally:
        if conn: conn.close()

if __name__ == "__main__":
    analyze_crash()