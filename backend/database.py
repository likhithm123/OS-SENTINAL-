import sqlite3
import json
import time
from datetime import datetime
from backend.config import DB_PATH

def get_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cursor = conn.cursor()
    
    # Table 1: Events Log (System Telemetry snapshots)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        event_type TEXT,
        process_count INTEGER,
        file_mod_rate REAL,
        avg_entropy REAL,
        outbound_conns INTEGER,
        risk_score REAL,
        details TEXT
    );
    """)

    # Table 2: Security Alerts (Medium & High Risk alerts)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        severity TEXT,
        title TEXT,
        description TEXT,
        risk_score REAL,
        triggered_rules TEXT,
        threat_category TEXT,
        is_read INTEGER DEFAULT 0
    );
    """)

    # Table 3: Security Incidents (High Risk incidents requiring triage/action)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS incidents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        incident_code TEXT UNIQUE,
        severity TEXT,
        risk_score REAL,
        threat_category TEXT,
        pid INTEGER,
        process_name TEXT,
        evidence TEXT,
        status TEXT DEFAULT 'OPEN',
        containment_action TEXT
    );
    """)

    # Table 4: Containment Logs
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS containments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        incident_id INTEGER,
        target_pid INTEGER,
        target_name TEXT,
        action_taken TEXT,
        status TEXT,
        details TEXT
    );
    """)

    # Table 5: ML Metrics History
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS ml_metrics (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        accuracy REAL,
        precision REAL,
        recall REAL,
        f1_score REAL,
        model_version TEXT
    );
    """)

    # Table 6: Restricted Networks & IP Access Control
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS restricted_networks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        network_cidr TEXT UNIQUE NOT NULL,
        description TEXT,
        action TEXT DEFAULT 'BLOCK',
        is_active INTEGER DEFAULT 1,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # Seed default restricted networks if table is newly created
    cursor.execute("SELECT COUNT(*) FROM restricted_networks")
    if cursor.fetchone()[0] == 0:
        default_restricted = [
            ("198.51.100.0/24", "RFC 5737 Test-Net-2 (Restricted External Subnet)", "BLOCK"),
            ("203.0.113.0/24", "RFC 5737 Test-Net-3 (Restricted Threat Subnet)", "BLOCK"),
            ("10.99.0.0/16", "Restricted Internal High-Security Zone", "BLOCK"),
            ("185.220.101.0/24", "Known High-Risk Proxy / Scanner Subnet", "BLOCK")
        ]
        cursor.executemany(
            "INSERT INTO restricted_networks (network_cidr, description, action) VALUES (?, ?, ?)",
            default_restricted
        )

    conn.commit()
    conn.close()

def get_restricted_networks():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM restricted_networks ORDER BY id ASC")
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def add_restricted_network(network_cidr: str, description: str = "", action: str = "BLOCK"):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        """INSERT INTO restricted_networks (network_cidr, description, action, is_active)
           VALUES (?, ?, ?, 1)""",
        (network_cidr.strip(), description.strip(), action.upper())
    )
    conn.commit()
    new_id = cursor.lastrowid
    cursor.execute("SELECT * FROM restricted_networks WHERE id = ?", (new_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None

def delete_restricted_network(network_id: int):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM restricted_networks WHERE id = ?", (network_id,))
    affected = cursor.rowcount
    conn.commit()
    conn.close()
    return affected > 0

def toggle_restricted_network(network_id: int):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT is_active FROM restricted_networks WHERE id = ?", (network_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return None
    new_status = 0 if row["is_active"] else 1
    cursor.execute("UPDATE restricted_networks SET is_active = ? WHERE id = ?", (new_status, network_id))
    conn.commit()
    cursor.execute("SELECT * FROM restricted_networks WHERE id = ?", (network_id,))
    updated_row = cursor.fetchone()
    conn.close()
    return dict(updated_row) if updated_row else None

def log_event(event_type, process_count, file_mod_rate, avg_entropy, outbound_conns, risk_score, details_dict):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        """INSERT INTO events (event_type, process_count, file_mod_rate, avg_entropy, outbound_conns, risk_score, details)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (event_type, process_count, file_mod_rate, avg_entropy, outbound_conns, risk_score, json.dumps(details_dict))
    )
    conn.commit()
    conn.close()

def create_alert(severity, title, description, risk_score, triggered_rules, threat_category):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        """INSERT INTO alerts (severity, title, description, risk_score, triggered_rules, threat_category)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (severity, title, description, risk_score, json.dumps(triggered_rules), threat_category)
    )
    conn.commit()
    alert_id = cursor.lastrowid
    conn.close()
    return alert_id

def create_incident(severity, risk_score, threat_category, pid, process_name, evidence_dict, status="OPEN", containment_action="NONE"):
    conn = get_db()
    cursor = conn.cursor()
    inc_code = f"INC-{int(time.time()*1000)%1000000:06d}"
    cursor.execute(
        """INSERT INTO incidents (incident_code, severity, risk_score, threat_category, pid, process_name, evidence, status, containment_action)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (inc_code, severity, risk_score, threat_category, pid, process_name, json.dumps(evidence_dict), status, containment_action)
    )
    conn.commit()
    inc_id = cursor.lastrowid
    conn.close()
    return inc_id, inc_code

def get_recent_events(limit=50):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def get_incidents(limit=50):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM incidents ORDER BY id DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def get_alerts(limit=50):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def update_incident_status(incident_id, status, containment_action=None):
    conn = get_db()
    cursor = conn.cursor()
    if containment_action:
        cursor.execute("UPDATE incidents SET status = ?, containment_action = ? WHERE id = ?", (status, containment_action, incident_id))
    else:
        cursor.execute("UPDATE incidents SET status = ? WHERE id = ?", (status, incident_id))
    conn.commit()
    conn.close()

def log_containment_action(incident_id: int, target_pid: int, target_name: str, action_taken: str, status: str = "SUCCESS", details: str = ""):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        """INSERT INTO containments (incident_id, target_pid, target_name, action_taken, status, details)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (incident_id, target_pid, target_name, action_taken, status, details)
    )
    conn.commit()
    conn.close()
