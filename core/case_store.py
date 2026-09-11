import sqlite3
import json
import os
import csv
import io
import datetime
from typing import Dict, Any, List, Optional

DB_PATH = os.path.join("data", "cases", "cases.db")

def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS cases (
            case_id TEXT PRIMARY KEY,
            timestamp TEXT,
            sha256 TEXT,
            risk_score TEXT,
            status TEXT DEFAULT 'Open',
            assigned_investigator TEXT DEFAULT 'Unassigned',
            analyst_notes TEXT DEFAULT '',
            case_severity TEXT DEFAULT 'MEDIUM',
            raw_json TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS indicators (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id TEXT,
            type TEXT,
            value TEXT,
            FOREIGN KEY(case_id) REFERENCES cases(case_id)
        )
    ''')
    
    # Safe migration: ensure new columns exist if table was created in earlier version
    cursor.execute("PRAGMA table_info(cases)")
    existing_cols = [row[1] for row in cursor.fetchall()]
    
    if "status" not in existing_cols:
        cursor.execute("ALTER TABLE cases ADD COLUMN status TEXT DEFAULT 'Open'")
    if "assigned_investigator" not in existing_cols:
        cursor.execute("ALTER TABLE cases ADD COLUMN assigned_investigator TEXT DEFAULT 'Unassigned'")
    if "analyst_notes" not in existing_cols:
        cursor.execute("ALTER TABLE cases ADD COLUMN analyst_notes TEXT DEFAULT ''")
    if "case_severity" not in existing_cols:
        cursor.execute("ALTER TABLE cases ADD COLUMN case_severity TEXT DEFAULT 'MEDIUM'")

    conn.commit()
    conn.close()

def save_case(case_data: Dict[str, Any]):
    init_db()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    case_id = case_data.get("case_id")
    timestamp = case_data.get("timestamp")
    sha256 = case_data.get("original_sha256")
    risk_score = case_data.get("risk_score", "UNKNOWN")
    status = case_data.get("status", "Open")
    assigned_investigator = case_data.get("assigned_investigator", "Unassigned")
    analyst_notes = case_data.get("analyst_notes", "")
    case_severity = case_data.get("case_severity", "MEDIUM")
    raw_json = json.dumps(case_data, default=str)
    
    # Check if case exists to avoid overwriting existing analyst notes/status
    cursor.execute('SELECT status, assigned_investigator, analyst_notes FROM cases WHERE case_id = ?', (case_id,))
    row = cursor.fetchone()
    if row:
        status = row[0] or status
        assigned_investigator = row[1] or assigned_investigator
        analyst_notes = row[2] or analyst_notes

    cursor.execute('''
        INSERT OR REPLACE INTO cases (case_id, timestamp, sha256, risk_score, status, assigned_investigator, analyst_notes, case_severity, raw_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (case_id, timestamp, sha256, risk_score, status, assigned_investigator, analyst_notes, case_severity, raw_json))
    
    # Save indicators for correlation
    cursor.execute('DELETE FROM indicators WHERE case_id = ?', (case_id,))
    for ind in case_data.get("indicators", []):
        cursor.execute('''
            INSERT INTO indicators (case_id, type, value)
            VALUES (?, ?, ?)
        ''', (case_id, ind.get("type"), ind.get("value")))
        
    conn.commit()
    conn.close()

def update_case_metadata(case_id: str, status: str = None, investigator: str = None, notes: str = None):
    """Update case status, notes, or assigned investigator."""
    init_db()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    updates = []
    params = []
    if status is not None:
        updates.append("status = ?")
        params.append(status)
    if investigator is not None:
        updates.append("assigned_investigator = ?")
        params.append(investigator)
    if notes is not None:
        updates.append("analyst_notes = ?")
        params.append(notes)
        
    if updates:
        params.append(case_id)
        query = f"UPDATE cases SET {', '.join(updates)} WHERE case_id = ?"
        cursor.execute(query, params)
        conn.commit()
    conn.close()

def get_case_record(case_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve full record and metadata for a specific case."""
    init_db()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT case_id, timestamp, sha256, risk_score, status, assigned_investigator, analyst_notes, case_severity, raw_json FROM cases WHERE case_id = ?', (case_id,))
    row = cursor.fetchone()
    conn.close()
    if row:
        data = json.loads(row[8])
        data["status"] = row[4]
        data["assigned_investigator"] = row[5]
        data["analyst_notes"] = row[6]
        data["case_severity"] = row[7]
        return data
    return None

def get_all_cases() -> List[Dict[str, Any]]:
    init_db()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT case_id, timestamp, sha256, risk_score, status, assigned_investigator, analyst_notes, case_severity, raw_json FROM cases ORDER BY timestamp DESC')
    rows = cursor.fetchall()
    conn.close()
    
    results = []
    for r in rows:
        try:
            d = json.loads(r[8])
            d["status"] = r[4]
            d["assigned_investigator"] = r[5]
            d["analyst_notes"] = r[6]
            d["case_severity"] = r[7]
            results.append(d)
        except Exception:
            continue
    return results

def get_all_indicators() -> List[Dict[str, Any]]:
    init_db()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT case_id, type, value FROM indicators')
    rows = cursor.fetchall()
    conn.close()
    return [{"case_id": r[0], "type": r[1], "value": r[2]} for r in rows]

def export_case_iocs_csv(case_id: Optional[str] = None) -> str:
    """Generate a CSV string of IOCs for SIEM/Firewall ingestion."""
    init_db()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    if case_id:
        cursor.execute('SELECT case_id, type, value FROM indicators WHERE case_id = ?', (case_id,))
    else:
        cursor.execute('SELECT case_id, type, value FROM indicators')
    rows = cursor.fetchall()
    conn.close()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Indicator_Type", "Indicator_Value", "Case_ID", "Threat_Platform", "Export_Timestamp"])
    
    ts = datetime.datetime.utcnow().isoformat() + "Z"
    for r in rows:
        writer.writerow([r[1], r[2], r[0], "EMAILSHIELD INDIA", ts])
        
    return output.getvalue()

def export_case_iocs_json(case_id: Optional[str] = None) -> str:
    """Generate a structured JSON export of indicators ready for SIEM / MISP."""
    init_db()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    if case_id:
        cursor.execute('SELECT case_id, type, value FROM indicators WHERE case_id = ?', (case_id,))
    else:
        cursor.execute('SELECT case_id, type, value FROM indicators')
    rows = cursor.fetchall()
    conn.close()

    iocs = []
    for r in rows:
        iocs.append({
            "type": r[1],
            "value": r[2],
            "case_id": r[0],
            "source": "EMAILSHIELD Forensic Analyzer"
        })

    export_obj = {
        "version": "1.0",
        "system": "EMAILSHIELD INDIA Forensic Intelligence",
        "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
        "ioc_count": len(iocs),
        "indicators": iocs
    }
    return json.dumps(export_obj, indent=2)

