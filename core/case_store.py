"""
core/case_store.py
Multi-Tenant Forensic Case Store & Threat Intelligence Engine for EMAILSHIELD INDIA.
Supports Supabase PostgreSQL with Row Level Security (RLS) and local fallback.
Enforces strict raw_json allowlists to prevent credential and sensitive data persistence.
"""
import sqlite3
import json
import os
import csv
import io
import datetime
import uuid
import re

DB_PATH = os.path.join("data", "cases", "cases.db")

def _mask_sensitive_tokens(text: str) -> str:
    """Mask OTPs, PINs, and security codes from body excerpts and subjects."""
    if not text:
        return ""
    masked = re.sub(
        r'(?i)\b(code|otp|pin|passcode|token|verification|verify|secret|security code|one[- ]time password)\b(\s*(?:is|[:\-\=\s#])*\s*)([0-9]{4,8}|[0-9]{3}[-\s][0-9]{3})\b',
        r'\1\2••••••',
        text
    )
    masked = re.sub(
        r'(?i)\b([0-9]{4,8})\b(\s+(?:is your|is the|to verify|verification|code|otp))',
        r'••••••\2',
        masked
    )
    return masked

# =====================================================================
# 1. RAW_JSON ALLOWLIST ENFORCEMENT
# =====================================================================

FORBIDDEN_PERSISTENCE_KEYS = {
    "pwd", "password", "app_password", "token", "refresh_token", "access_token",
    "mailbox_creds", "current_email_bytes", "raw_bytes", "api_key", "secret",
    "body", "body_text"
}

def filter_raw_json_allowlist(case_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Strips raw RFC822 binaries, credentials, secrets, and full email body text.
    Retains only permitted forensic telemetry categories according to architecture design.
    """
    clean_report: Dict[str, Any] = {}

    # Core Identifiers
    clean_report["case_id"] = case_data.get("case_id")
    clean_report["case_number"] = case_data.get("case_number") or case_data.get("case_id")
    clean_report["timestamp"] = str(case_data.get("timestamp", ""))
    clean_report["sha256"] = case_data.get("sha256") or case_data.get("original_sha256", "UNKNOWN")

    # Header & Envelope Metadata
    clean_report["subject"] = case_data.get("subject", "No Subject")
    clean_report["sender"] = case_data.get("sender", "Unknown")
    clean_report["content_type"] = case_data.get("content_type", "Unknown")

    # Threat & Verdict Telemetry
    clean_report["threat_verdict"] = case_data.get("threat_verdict") or case_data.get("risk_score", "UNCLASSIFIED")
    clean_report["risk_score"] = case_data.get("risk_score", "UNKNOWN")
    clean_report["verdict_confidence"] = case_data.get("verdict_confidence", 0)
    clean_report["case_severity"] = case_data.get("case_severity", "MEDIUM")
    clean_report["status"] = case_data.get("status", "Open")
    clean_report["assigned_investigator"] = case_data.get("assigned_investigator", "Unassigned")
    clean_report["analyst_notes"] = case_data.get("analyst_notes", "")

    # Forensic Analysis Components
    clean_report["rule_findings"] = case_data.get("rule_findings", [])
    clean_report["auth_results"] = case_data.get("auth_results", [])
    clean_report["auth_alignment"] = case_data.get("auth_alignment", {})
    clean_report["ml_assessment"] = case_data.get("ml_assessment", {})
    clean_report["lookalike_analysis"] = case_data.get("lookalike_analysis", {})
    clean_report["relay_transit"] = case_data.get("relay_transit", {})
    clean_report["sender_location"] = case_data.get("sender_location", {})
    clean_report["geolocation"] = case_data.get("geolocation", [])

    # Attachment Metadata (Sanitized - SHA256, filename, verdict - NO binary contents)
    clean_atts = []
    for att in case_data.get("attachment_analyses", []):
        if isinstance(att, dict):
            clean_atts.append({
                "filename": att.get("filename", "unknown"),
                "sha256": att.get("sha256", "N/A"),
                "verdict_label": att.get("verdict_label", "SAFE"),
                "is_double_ext": att.get("is_double_ext", False)
            })
    clean_report["attachment_analyses"] = clean_atts

    # Sanitized Body Excerpt (< 300 chars with OTPs masked)
    raw_body = case_data.get("body_text") or case_data.get("body", "")
    if raw_body:
        excerpt = raw_body[:300].strip().replace("\r", " ").replace("\n", " ")
        clean_report["body_excerpt"] = _mask_sensitive_tokens(excerpt)
    else:
        clean_report["body_excerpt"] = ""

    return clean_report


# =====================================================================
# 2. LOCAL SQLITE FALLBACK ENGINE (FOR OFFLINE TESTS & LOCAL SANDBOX)
# =====================================================================

def _init_sqlite_db():
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
    cursor.execute("PRAGMA table_info(cases)")
    existing_cols = [row[1] for row in cursor.fetchall()]
    for col, c_type in [("status", "TEXT DEFAULT 'Open'"), ("assigned_investigator", "TEXT DEFAULT 'Unassigned'"),
                        ("analyst_notes", "TEXT DEFAULT ''"), ("case_severity", "TEXT DEFAULT 'MEDIUM'")]:
        if col not in existing_cols:
            cursor.execute(f"ALTER TABLE cases ADD COLUMN {col} {c_type}")
    conn.commit()
    conn.close()


def _save_case_sqlite(case_data: Dict[str, Any]):
    _init_sqlite_db()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    case_id = case_data.get("case_id")
    timestamp = str(case_data.get("timestamp", datetime.datetime.now(datetime.timezone.utc).isoformat()))
    sha256 = case_data.get("original_sha256") or case_data.get("sha256", "UNKNOWN")
    risk_score = case_data.get("risk_score", "UNKNOWN")
    status = case_data.get("status", "Open")
    assigned_investigator = case_data.get("assigned_investigator", "Unassigned")
    analyst_notes = case_data.get("analyst_notes", "")
    case_severity = case_data.get("case_severity", "MEDIUM")
    
    clean_json = filter_raw_json_allowlist(case_data)
    raw_json = json.dumps(clean_json, default=str)

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

    cursor.execute('DELETE FROM indicators WHERE case_id = ?', (case_id,))
    for ind in case_data.get("indicators", []):
        itype = ind.get("type") if isinstance(ind, dict) else getattr(ind, "type", "UNKNOWN")
        ival = ind.get("value") if isinstance(ind, dict) else getattr(ind, "value", "")
        cursor.execute('''
            INSERT INTO indicators (case_id, type, value)
            VALUES (?, ?, ?)
        ''', (case_id, itype, ival))

    conn.commit()
    conn.close()


# =====================================================================
# 3. UNIFIED MULTI-TENANT CASE STORE API & FAIL-CLOSED ENFORCEMENT
# =====================================================================

def is_public_multiuser_mode() -> bool:
    """
    Returns True if application is running in public multi-user production mode.
    Configured explicitly via EMAILSHIELD_MODE="public_multiuser" or EMAILSHIELD_ENV="production"
    in environment variables or Streamlit secrets.
    """
    mode = os.environ.get("EMAILSHIELD_MODE", "").strip().lower()
    env = os.environ.get("EMAILSHIELD_ENV", "").strip().lower()
    if mode == "public_multiuser" or env == "production":
        return True
    try:
        import streamlit as st
        st_mode = str(st.secrets.get("EMAILSHIELD_MODE", "")).strip().lower()
        st_env = str(st.secrets.get("EMAILSHIELD_ENV", "")).strip().lower()
        if st_mode == "public_multiuser" or st_env == "production":
            return True
    except Exception:
        pass
    return False


def save_case(case_data: Dict[str, Any], user_id: Optional[str] = None, client: Any = None) -> bool:
    """
    Persists forensic investigation case and indicators.
    If authenticated Supabase client and user_id are provided, persists to PostgreSQL with RLS.
    Enforces strict raw_json allowlist filtering.
    In public multi-user mode, fails closed if Supabase is unconfigured or unavailable.
    """
    clean_telemetry = filter_raw_json_allowlist(case_data)
    case_id_str = case_data.get("case_id") or f"CASE-{uuid.uuid4().hex[:8].upper()}"

    if is_public_multiuser_mode():
        if not client or not user_id:
            # Public multi-user mode: do not write to shared local SQLite
            return False
        try:
            # 1. Upsert Case Record into Supabase
            case_row = {
                "user_id": user_id,
                "case_number": case_id_str,
                "sha256": clean_telemetry.get("sha256", "UNKNOWN"),
                "threat_verdict": clean_telemetry.get("threat_verdict", "UNCLASSIFIED"),
                "risk_score": clean_telemetry.get("risk_score", "UNKNOWN"),
                "verdict_confidence": clean_telemetry.get("verdict_confidence", 0),
                "status": clean_telemetry.get("status", "Open"),
                "assigned_investigator": clean_telemetry.get("assigned_investigator", "Unassigned"),
                "analyst_notes": clean_telemetry.get("analyst_notes", ""),
                "case_severity": clean_telemetry.get("case_severity", "MEDIUM"),
                "subject": clean_telemetry.get("subject", "No Subject"),
                "sender": clean_telemetry.get("sender", "Unknown"),
                "content_type": clean_telemetry.get("content_type", "Unknown"),
                "raw_json": clean_telemetry
            }

            res = client.table("cases").upsert(case_row, on_conflict="id,user_id").execute()
            inserted_id = res.data[0]["id"] if res and res.data else None

            # 2. Insert Associated Indicators (With Composite Foreign Key Integrity)
            if inserted_id:
                raw_inds = case_data.get("indicators", [])
                ind_rows = []
                for ind in raw_inds:
                    itype = ind.get("type") if isinstance(ind, dict) else getattr(ind, "type", "UNKNOWN")
                    ival = ind.get("value") if isinstance(ind, dict) else getattr(ind, "value", "")
                    isrc = ind.get("source") if isinstance(ind, dict) else getattr(ind, "source", "Body/Headers")
                    if itype and ival:
                        ind_rows.append({
                            "case_id": inserted_id,
                            "user_id": user_id,
                            "type": itype,
                            "value": ival,
                            "source": isrc
                        })
                if ind_rows:
                    client.table("indicators").insert(ind_rows).execute()
            return True
        except Exception:
            # Fail closed in public multi-user mode
            return False

    # Development / Offline Test Fallback Mode
    if client and user_id:
        try:
            case_row = {
                "user_id": user_id,
                "case_number": case_id_str,
                "sha256": clean_telemetry.get("sha256", "UNKNOWN"),
                "threat_verdict": clean_telemetry.get("threat_verdict", "UNCLASSIFIED"),
                "risk_score": clean_telemetry.get("risk_score", "UNKNOWN"),
                "verdict_confidence": clean_telemetry.get("verdict_confidence", 0),
                "status": clean_telemetry.get("status", "Open"),
                "assigned_investigator": clean_telemetry.get("assigned_investigator", "Unassigned"),
                "analyst_notes": clean_telemetry.get("analyst_notes", ""),
                "case_severity": clean_telemetry.get("case_severity", "MEDIUM"),
                "subject": clean_telemetry.get("subject", "No Subject"),
                "sender": clean_telemetry.get("sender", "Unknown"),
                "content_type": clean_telemetry.get("content_type", "Unknown"),
                "raw_json": clean_telemetry
            }
            res = client.table("cases").upsert(case_row, on_conflict="id,user_id").execute()
            inserted_id = res.data[0]["id"] if res and res.data else None
            if inserted_id:
                raw_inds = case_data.get("indicators", [])
                ind_rows = []
                for ind in raw_inds:
                    itype = ind.get("type") if isinstance(ind, dict) else getattr(ind, "type", "UNKNOWN")
                    ival = ind.get("value") if isinstance(ind, dict) else getattr(ind, "value", "")
                    isrc = ind.get("source") if isinstance(ind, dict) else getattr(ind, "source", "Body/Headers")
                    if itype and ival:
                        ind_rows.append({
                            "case_id": inserted_id,
                            "user_id": user_id,
                            "type": itype,
                            "value": ival,
                            "source": isrc
                        })
                if ind_rows:
                    client.table("indicators").insert(ind_rows).execute()
            return True
        except Exception:
            _save_case_sqlite(case_data)
            return False
    else:
        _save_case_sqlite(case_data)
        return True


def get_case_record(case_id: str, client: Any = None) -> Optional[Dict[str, Any]]:
    """Retrieve full record and metadata for a specific case."""
    if client:
        try:
            res = client.table("cases").select("*").or_(f"id.eq.{case_id},case_number.eq.{case_id}").execute()
            if res and res.data:
                row = res.data[0]
                data = row.get("raw_json", {})
                data["status"] = row.get("status")
                data["assigned_investigator"] = row.get("assigned_investigator")
                data["analyst_notes"] = row.get("analyst_notes")
                data["case_severity"] = row.get("case_severity")
                data["case_id"] = row.get("case_number")
                return data
            return None
        except Exception:
            if is_public_multiuser_mode():
                return None

    if is_public_multiuser_mode():
        # Public multi-user mode: do not query shared local SQLite
        return None

    _init_sqlite_db()
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


def get_all_cases(client: Any = None) -> List[Dict[str, Any]]:
    """Retrieve historical cases (RLS-filtered to current user when client is provided)."""
    if client:
        try:
            res = client.table("cases").select("*").order("created_at", desc=True).execute()
            results = []
            for row in (res.data or []):
                d = row.get("raw_json", {})
                d["status"] = row.get("status")
                d["assigned_investigator"] = row.get("assigned_investigator")
                d["analyst_notes"] = row.get("analyst_notes")
                d["case_severity"] = row.get("case_severity")
                d["case_id"] = row.get("case_number")
                results.append(d)
            return results
        except Exception:
            if is_public_multiuser_mode():
                return []

    if is_public_multiuser_mode():
        return []

    _init_sqlite_db()
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


def get_all_indicators(client: Any = None, case_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """Retrieve threat indicators (RLS-filtered to current user when client is provided)."""
    if client:
        try:
            query = client.table("indicators").select("case_id, type, value, source")
            if case_id:
                query = query.eq("case_id", case_id)
            res = query.execute()
            return [{"case_id": r.get("case_id"), "type": r.get("type"), "value": r.get("value")} for r in (res.data or [])]
        except Exception:
            if is_public_multiuser_mode():
                return []

    if is_public_multiuser_mode():
        return []

    _init_sqlite_db()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    if case_id:
        cursor.execute('SELECT case_id, type, value FROM indicators WHERE case_id = ?', (case_id,))
    else:
        cursor.execute('SELECT case_id, type, value FROM indicators')
    rows = cursor.fetchall()
    conn.close()
    return [{"case_id": r[0], "type": r[1], "value": r[2]} for r in rows]


def update_case_metadata(case_id: str, status: str = None, investigator: str = None, notes: str = None, severity: str = None, client: Any = None) -> bool:
    """Update case status, notes, severity, or assigned investigator."""
    if client:
        try:
            updates = {}
            if status is not None:
                updates["status"] = status
            if investigator is not None:
                updates["assigned_investigator"] = investigator
            if notes is not None:
                updates["analyst_notes"] = notes
            if severity is not None:
                updates["case_severity"] = severity
            if updates:
                updates["updated_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
                client.table("cases").update(updates).or_(f"id.eq.{case_id},case_number.eq.{case_id}").execute()
            return True
        except Exception:
            if is_public_multiuser_mode():
                return False

    if is_public_multiuser_mode():
        return False

    _init_sqlite_db()
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
    if severity is not None:
        updates.append("case_severity = ?")
        params.append(severity)

    if updates:
        params.append(case_id)
        query = f"UPDATE cases SET {', '.join(updates)} WHERE case_id = ?"
        cursor.execute(query, params)
        conn.commit()
    conn.close()
    return True


def export_case_iocs_csv(case_id: Optional[str] = None, client: Any = None) -> str:
    """Generate a CSV string of IOCs for SIEM/Firewall ingestion."""
    rows = get_all_indicators(client=client, case_id=case_id)

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Indicator_Type", "Indicator_Value", "Case_ID", "Threat_Platform", "Export_Timestamp"])

    ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for r in rows:
        writer.writerow([r.get("type"), r.get("value"), r.get("case_id"), "EMAILSHIELD INDIA", ts])

    return output.getvalue()


def export_case_iocs_json(case_id: Optional[str] = None, client: Any = None) -> str:
    """Generate a structured JSON export of indicators ready for SIEM / MISP."""
    rows = get_all_indicators(client=client, case_id=case_id)

    iocs = []
    for r in rows:
        iocs.append({
            "type": r.get("type"),
            "value": r.get("value"),
            "case_id": r.get("case_id"),
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
