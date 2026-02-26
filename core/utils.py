import os
import sqlite3
import json
from datetime import datetime
from config import DB_FILE

def log_message(msg):
    """
    No-op logging for terminal cleanliness.
    """
    pass

def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    # Table for scan metadata
    c.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            target TEXT
        )
    ''')
    # Table for individual host results
    c.execute('''
        CREATE TABLE IF NOT EXISTS scan_hosts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            ip TEXT,
            mac TEXT,
            os TEXT,
            port_count INTEGER,
            risk_score INTEGER,
            risk_level TEXT,
            FOREIGN KEY(scan_id) REFERENCES scans(id)
        )
    ''')
    conn.commit()
    conn.close()

def save_scan_history(target, hosts_list):
    """
    Saves a scan session and all its discovered hosts.
    """
    init_db()
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    # 1. Insert into scans table
    c.execute(
        "INSERT INTO scans (timestamp, target) VALUES (?, ?)",
        (datetime.now().isoformat(), target)
    )
    scan_id = c.lastrowid
    
    # 2. Insert each host into scan_hosts table
    for h in hosts_list:
        c.execute(
            """INSERT INTO scan_hosts 
               (scan_id, ip, mac, os, port_count, risk_score, risk_level) 
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                scan_id,
                h.get("ip"),
                h.get("mac"),
                h.get("os"),
                len(h.get("open_ports", [])),
                h.get("risk_score", 0),
                h.get("risk_level", "UNKNOWN")
            )
        )
        
    conn.commit()
    conn.close()

def get_scan_history():
    """
    Returns a summary of past scans.
    """
    init_db()
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    # Join with hosts to get some summary stats if needed, or just return scan list
    c.execute("""
        SELECT s.timestamp, s.target, COUNT(h.id) as host_count, AVG(h.risk_score) as avg_risk
        FROM scans s
        LEFT JOIN scan_hosts h ON s.id = h.scan_id
        GROUP BY s.id
        ORDER BY s.id DESC
    """)
    rows = c.fetchall()
    conn.close()
    return rows

def check_disclaimer():
    disclaimer_file = ".disclaimer_accepted"
    if not os.path.exists(disclaimer_file):
        print("\n" + "="*50)
        print("WARNING: Sn1p3rNetX+ is a Network Intelligence Tool.")
        print("Only scan authorized systems. The authors are not responsible for misuse.")
        print("="*50 + "\n")
        ans = input("Do you accept these terms? (yes/no): ")
        if ans.lower() not in ['y', 'yes']:
            print("You must accept the terms to use this tool.")
            exit(1)
        with open(disclaimer_file, "w") as f:
            f.write("accepted")
