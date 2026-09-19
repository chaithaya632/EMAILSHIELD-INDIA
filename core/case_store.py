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
from typing import Dict, Any, Optional, List, Tuple
from core.supabase_client import is_supabase_configured

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

    # Infrastructure & Threat Intelligence Telemetry
    infra_raw = case_data.get("infrastructure_intel")
    if hasattr(infra_raw, "model_dump"):
        clean_report["infrastructure_intel"] = infra_raw.model_dump()
    elif isinstance(infra_raw, dict):
        clean_report["infrastructure_intel"] = infra_raw
    else:
        clean_report["infrastructure_intel"] = {}

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
    if is_supabase_configured() and (not client or not user_id):
        return False

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
            if is_supabase_configured():
                return False
            _save_case_sqlite(case_data)
            return False
    else:
        if is_supabase_configured():
            return False
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
            if is_public_multiuser_mode() or is_supabase_configured():
                return None

    if is_public_multiuser_mode() or (is_supabase_configured() and client is None):
        # Fail closed: do not query shared local SQLite without authenticated client
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


def get_all_cases(client: Any = None, limit: int = 100) -> List[Dict[str, Any]]:
    """Retrieve historical cases with bounded memory allocation (RLS-filtered when client provided)."""
    effective_limit = max(1, min(limit or 100, 500))
    if client:
        try:
            query = client.table("cases").select("*").order("created_at", desc=True)
            if hasattr(query, "limit"):
                query = query.limit(effective_limit)
            res = query.execute()
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
            if is_public_multiuser_mode() or is_supabase_configured():
                return []

    if is_public_multiuser_mode() or (is_supabase_configured() and client is None):
        # Fail closed: do not query shared local SQLite without authenticated client
        return []

    _init_sqlite_db()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT case_id, timestamp, sha256, risk_score, status, assigned_investigator, analyst_notes, case_severity, raw_json FROM cases ORDER BY timestamp DESC LIMIT ?', (effective_limit,))
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


def get_all_indicators(client: Any = None, case_id: Optional[str] = None, limit: int = 500) -> List[Dict[str, Any]]:
    """Retrieve threat indicators with bounded query allocation."""
    effective_limit = max(1, min(limit or 500, 2000))
    if client:
        try:
            query = client.table("indicators").select("case_id, type, value, source")
            if hasattr(query, "limit"):
                query = query.limit(effective_limit)
            if case_id:
                query = query.eq("case_id", case_id)
            res = query.execute()
            return [{"case_id": r.get("case_id"), "type": r.get("type"), "value": r.get("value")} for r in (res.data or [])]
        except Exception:
            if is_public_multiuser_mode() or is_supabase_configured():
                return []

    if is_public_multiuser_mode() or (is_supabase_configured() and client is None):
        # Fail closed: do not query shared local SQLite without authenticated client
        return []

    _init_sqlite_db()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    if case_id:
        cursor.execute('SELECT case_id, type, value FROM indicators WHERE case_id = ? LIMIT ?', (case_id, effective_limit))
    else:
        cursor.execute('SELECT case_id, type, value FROM indicators LIMIT ?', (effective_limit,))
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
                res = client.table("cases").update(updates).or_(f"id.eq.{case_id},case_number.eq.{case_id}").execute()
                if res and hasattr(res, "data") and isinstance(res.data, list):
                    return len(res.data) > 0
            return True
        except Exception:
            if is_public_multiuser_mode() or is_supabase_configured():
                return False

    if is_public_multiuser_mode() or (is_supabase_configured() and client is None):
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


def sanitize_csv_cell(val: Any) -> Any:
    """Neutralize spreadsheet formula injection characters (=, +, -, @, tab, cr)."""
    if val is None:
        return ""
    s = str(val)
    if s and s[0] in ("=", "+", "-", "@", "\t", "\r"):
        return f"'{s}"
    return s


def export_case_iocs_csv(case_id: Optional[str] = None, client: Any = None) -> str:
    """Generate a CSV string of IOCs for SIEM/Firewall ingestion, protected against CSV injection."""
    rows = get_all_indicators(client=client, case_id=case_id)

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Indicator_Type", "Indicator_Value", "Case_ID", "Threat_Platform", "Export_Timestamp"])

    ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for r in rows:
        writer.writerow([
            sanitize_csv_cell(r.get("type")),
            sanitize_csv_cell(r.get("value")),
            sanitize_csv_cell(r.get("case_id")),
            "EMAILSHIELD INDIA",
            ts
        ])

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
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "ioc_count": len(iocs),
        "indicators": iocs
    }
    return json.dumps(export_obj, indent=2)


def export_case_report_pdf(case_id: str, client: Any = None, user_id: Optional[str] = None) -> Optional[bytes]:
    """
    Secure backend export for Case PDF report with strict authorization and RLS checks.
    Fails closed (returns None) if unauthenticated, wrong tenant, or RLS blocked.
    """
    if not case_id:
        return None
    case_rec = get_case_record(case_id, client=client)
    if not case_rec:
        return None
    if not is_authorized_caller(user_id=user_id, client=client, resource_owner_id=case_rec.get("user_id")):
        return None
    from core.report import generate_pdf_report
    pdf_buf = io.BytesIO()
    generate_pdf_report(case_rec, pdf_buf)
    return pdf_buf.getvalue()


def export_case_report_json(case_id: str, client: Any = None, user_id: Optional[str] = None) -> Optional[str]:
    """
    Secure backend export for Case JSON report with strict authorization and RLS checks.
    Fails closed (returns None) if unauthenticated, wrong tenant, or RLS blocked.
    """
    if not case_id:
        return None
    case_rec = get_case_record(case_id, client=client)
    if not case_rec:
        return None
    if not is_authorized_caller(user_id=user_id, client=client, resource_owner_id=case_rec.get("user_id")):
        return None
    from core.report import generate_json_report
    return generate_json_report(case_rec)


def export_case_ncrp_pdf(case_id: str, client: Any = None, user_id: Optional[str] = None) -> Optional[bytes]:
    """
    Secure backend export for Indian NCRP / BSA Section 63 Annexure PDF.
    Fails closed (returns None) if unauthenticated, wrong tenant, or RLS blocked.
    """
    if not case_id:
        return None
    case_rec = get_case_record(case_id, client=client)
    if not case_rec:
        return None
    if not is_authorized_caller(user_id=user_id, client=client, resource_owner_id=case_rec.get("user_id")):
        return None
    from core.ncrp_packager import generate_ncrp_pdf_annexure
    pdf_buf = io.BytesIO()
    generate_ncrp_pdf_annexure(case_rec, pdf_buf)
    return pdf_buf.getvalue()


def export_case_bsa_pdf(case_id: str, client: Any = None, user_id: Optional[str] = None) -> Optional[bytes]:
    """Alias for BSA Section 63 Annexure PDF export."""
    return export_case_ncrp_pdf(case_id, client=client, user_id=user_id)


def export_case_executive_pdf(case_id: str, client: Any = None, user_id: Optional[str] = None) -> Optional[bytes]:
    """
    Secure backend export for Case Executive Summary PDF report with strict authorization checks.
    Fails closed (returns None) if unauthenticated, wrong tenant, or RLS blocked.
    """
    if not case_id:
        return None
    case_rec = get_case_record(case_id, client=client)
    if not case_rec:
        return None
    if not is_authorized_caller(user_id=user_id, client=client, resource_owner_id=case_rec.get("user_id")):
        return None
    from core.report import generate_executive_pdf_report
    pdf_buf = io.BytesIO()
    generate_executive_pdf_report(case_rec, pdf_buf)
    return pdf_buf.getvalue()


def export_case_evidence_manifest(case_id: str, client: Any = None, user_id: Optional[str] = None) -> Optional[str]:
    """
    Secure backend export for Evidence Manifest JSON with strict authorization checks.
    Fails closed (returns None) if unauthenticated, wrong tenant, or RLS blocked.
    """
    if not case_id:
        return None
    case_rec = get_case_record(case_id, client=client)
    if not case_rec:
        return None
    if not is_authorized_caller(user_id=user_id, client=client, resource_owner_id=case_rec.get("user_id")):
        return None
    from core.evidence import build_evidence_manifest, scan_and_redact_secrets
    manifest = build_evidence_manifest(case_rec, client=client)
    manifest_data = {
        "case_id": case_id,
        "exported_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "item_count": len(manifest),
        "evidence_manifest": manifest,
    }
    return json.dumps(scan_and_redact_secrets(manifest_data), indent=2)


def export_case_zip_package(
    case_id: str,
    client: Any = None,
    user_id: Optional[str] = None,
    raw_eml_bytes: Optional[bytes] = None
) -> Optional[bytes]:
    """
    Secure backend export for complete Investigation Evidence ZIP Package with strict authorization checks.
    Fails closed (returns None) if unauthenticated, wrong tenant, or RLS blocked.
    """
    if not case_id:
        return None
    case_rec = get_case_record(case_id, client=client)
    if not case_rec:
        return None
    if not is_authorized_caller(user_id=user_id, client=client, resource_owner_id=case_rec.get("user_id")):
        return None
    from core.evidence import build_investigation_zip_package
    return build_investigation_zip_package(
        case_id=case_id,
        case_data=case_rec,
        client=client,
        user_id=user_id,
        raw_eml_bytes=raw_eml_bytes,
    )


# =====================================================================
# 4. SOC DASHBOARD METRICS & MULTI-TENANT QUERY HELPERS
# =====================================================================

def _extract_primary_ioc(case_data: Dict[str, Any]) -> str:
    """Extract primary IOC indicator or origin domain for display in SOC views."""
    # 1. Check indicators in case_data
    indicators = case_data.get("indicators", [])
    if isinstance(indicators, list):
        for ind in indicators:
            itype = ind.get("type", "") if isinstance(ind, dict) else getattr(ind, "type", "")
            ival = ind.get("value", "") if isinstance(ind, dict) else getattr(ind, "value", "")
            if itype.lower() in ("url", "domain", "ip", "ipv4") and ival:
                return str(ival)[:40]
    
    # 2. Check rule findings for specific indicators
    rule_findings = case_data.get("rule_findings", [])
    if isinstance(rule_findings, list):
        for rf in rule_findings:
            if isinstance(rf, dict) and rf.get("evidence"):
                ev = str(rf.get("evidence"))
                if "http" in ev or ".com" in ev or ".in" in ev:
                    return ev[:40]

    # 3. Fallback to sender domain or sender address
    sender = case_data.get("sender", "")
    if "@" in sender:
        return sender.split("@")[-1].strip(">").strip()
    return "N/A"


def is_authorized_caller(
    user_id: Optional[str] = None,
    client: Any = None,
    resource_owner_id: Optional[str] = None
) -> bool:
    """
    Consolidated authorization & access-control evaluator for EMAILSHIELD INDIA.
    Enforces the single-pass authorization chain:
    REQUEST -> AUTHENTICATION -> USER ID -> TENANT -> RESOURCE OWNERSHIP -> RLS -> AUTHORIZED DATA

    Fail-closed security guarantees:
    1. If neither user_id nor client is provided -> DENIED (Fail closed).
    2. When Supabase is configured or in public multi-user mode:
       - Requires both authenticated client and valid user_id.
       - If resource_owner_id is specified, user_id must match resource_owner_id.
    3. In local offline developer sandbox (Supabase unconfigured & not multi-user):
       - Requires user_id or client.
       - If resource_owner_id is specified, user_id must match resource_owner_id.
    """
    if not user_id and not client:
        return False

    try:
        supabase_active = is_supabase_configured()
    except Exception:
        supabase_active = False

    if is_public_multiuser_mode() or supabase_active:
        if not (client and user_id):
            return False
    else:
        if not (user_id or client):
            return False

    # Ownership / Tenant check (if resource owner specified)
    if resource_owner_id is not None:
        eff_user = user_id or getattr(client, "user_id", None)
        if eff_user != resource_owner_id:
            return False

    return True


# Backward-compatibility alias
is_authenticated_soc_caller = is_authorized_caller


def derive_case_classification(case_data: Dict[str, Any]) -> str:
    """
    Authoritative classification derivation for forensic investigations.
    Returns strictly one of: 'THREAT', 'SUSPICIOUS', 'CLEAN'.
    
    Rules:
    - 'THREAT': Confirmed malicious intent (Phishing, Malware, BEC, Impersonation, Credential Harvesting, Extortion, Quishing, Fraud).
    - 'SUSPICIOUS': Anomalous, unverified, or high-scrutiny solicitation without confirmed threat payloads.
    - 'CLEAN': Legitimate, benign, transactional, newsletter, or verified safe communications.
    
    Heuristic rule triggers or raw risk scores alone NEVER elevate a record to THREAT.
    """
    # 1. Direct explicit classification field
    explicit_cls = str(case_data.get("classification") or "").strip().upper()
    if explicit_cls in ("THREAT", "MALICIOUS", "PHISHING"):
        return "THREAT"
    if explicit_cls in ("SUSPICIOUS", "SUSPICIOUS FINANCIAL", "MEDIUM"):
        return "SUSPICIOUS"
    if explicit_cls in ("CLEAN", "BENIGN", "SAFE", "LEGITIMATE"):
        return "CLEAN"

    # 2. Threat verdict analysis
    verdict = str(case_data.get("threat_verdict") or case_data.get("verdict") or "").strip()
    verdict_upper = verdict.upper()

    if verdict_upper:
        # Check clean / legitimate verdicts first to avoid false positives
        clean_indicators = (
            "LEGITIMATE", "CLEAN", "BENIGN", "SAFE",
            "SECURITY ALERT / NOTIFICATION (AUTHENTICATED)", "NO THREAT", "UNCLASSIFIED / SAFE"
        )
        if any(ind in verdict_upper for ind in clean_indicators):
            return "CLEAN"

        # Check threat verdicts
        threat_indicators = (
            "PHISH", "QUISH", "MALICIOUS", "MALWARE", "BEC", "BUSINESS EMAIL COMPROMISE",
            "EXECUTIVE IMPERSONATION", "BRAND / SERVICE IMPERSONATION", "CREDENTIAL HARVESTING",
            "EXTORTION", "BLACKMAIL", "FRAUD", "TROJAN", "RANSOMWARE",
            "SPOOFING / FORGERY DETECTED", "THREAT"
        )
        if any(ind in verdict_upper for ind in threat_indicators):
            return "THREAT"

        # Check suspicious verdicts
        if "SUSPICIOUS" in verdict_upper:
            return "SUSPICIOUS"

    # 3. Explicit boolean threat detection flags
    if case_data.get("threat_detected") is True or case_data.get("is_threat") is True:
        return "THREAT"

    # 4. Fallback when verdict is absent / None / unclassified
    # Notice: Raw risk_score or rules triggered do NOT qualify as THREAT per specification.
    raw_risk = str(case_data.get("risk_score") or "").strip().upper()
    if raw_risk in ("HIGH", "SUSPICIOUS"):
        return "SUSPICIOUS"

    return "CLEAN"


def derive_case_severity(case_data: Dict[str, Any]) -> str:
    """Extract and normalize case severity level into standard uppercase enum."""
    sev = str(case_data.get("case_severity") or case_data.get("severity") or "MEDIUM").strip().upper()
    if "CRIT" in sev:
        return "CRITICAL"
    if "HIGH" in sev:
        return "HIGH"
    if "LOW" in sev or "INFO" in sev:
        return "LOW"
    return "MEDIUM"


def get_soc_kpi_metrics(user_id: Optional[str] = None, client: Any = None) -> Dict[str, int]:
    """
    Retrieve real tenant-scoped KPI metrics for the SOC Operations Dashboard:
    - emails_analysed: Total authorized forensic cases evaluated for this tenant.
    - threats_detected: Cases where final classification is strictly THREAT.
    - high_critical: Cases where final classification == THREAT and severity in ('HIGH', 'CRITICAL').
    - open_investigations: Cases with active open lifecycle status (OPEN, IN_PROGRESS, ACTIVE, NEW).
    
    Strict Tenant Isolation & Authorization:
    - Fails closed with all zero metrics if unauthenticated.
    """
    if not is_authenticated_soc_caller(user_id, client):
        return {
            "emails_analysed": 0,
            "threats_detected": 0,
            "high_critical": 0,
            "open_investigations": 0,
            "status": "unauthorized",
            "authenticated": False
        }

    cases = get_all_cases(client=client, limit=500)
    
    total = len(cases)
    threats = 0
    high_crit = 0
    open_inv = 0

    for c in cases:
        cls = derive_case_classification(c)
        sev = derive_case_severity(c)
        status = str(c.get("status") or "Open").strip().upper()

        if cls == "THREAT":
            threats += 1
            if sev in ("HIGH", "CRITICAL"):
                high_crit += 1

        if status in ("OPEN", "IN_PROGRESS", "IN PROGRESS", "ACTIVE", "NEW", "INVESTIGATING"):
            open_inv += 1

    return {
        "emails_analysed": total,
        "threats_detected": threats,
        "high_critical": high_crit,
        "open_investigations": open_inv,
        "status": "authorized",
        "authenticated": True
    }


def get_soc_threat_distribution(user_id: Optional[str] = None, client: Any = None) -> Dict[str, int]:
    """
    Retrieve threat distribution breakdown for the SOC Operations Dashboard:
    - Clean: Legitimate / Benign / Safe cases
    - Suspicious: Suspicious solicitation / Medium-risk cases
    - High: High severity threats (THREAT + HIGH)
    - Critical: Critical severity active campaigns (THREAT + CRITICAL)
    
    Strict Tenant Isolation & Authorization:
    - Fails closed with all zeros if unauthenticated.
    """
    dist = {"Clean": 0, "Suspicious": 0, "High": 0, "Critical": 0}
    if not is_authenticated_soc_caller(user_id, client):
        return dist

    cases = get_all_cases(client=client, limit=500)
    for c in cases:
        cls = derive_case_classification(c)
        sev = derive_case_severity(c)

        if cls == "THREAT":
            if sev == "CRITICAL":
                dist["Critical"] += 1
            elif sev == "HIGH":
                dist["High"] += 1
            else:
                dist["Suspicious"] += 1
        elif cls == "SUSPICIOUS":
            dist["Suspicious"] += 1
        else:
            dist["Clean"] += 1

    return dist


def get_soc_threat_activity(user_id: Optional[str] = None, client: Any = None, limit: int = 10) -> List[Dict[str, Any]]:
    """
    Retrieve recent threat events for the tenant, with sensitive tokens masked.
    Strictly tenant-scoped via RLS. Fails closed if unauthenticated.
    """
    if not is_authenticated_soc_caller(user_id, client):
        return []

    effective_limit = max(1, min(limit or 10, 50))
    cases = get_all_cases(client=client, limit=effective_limit * 2)

    activity = []
    for c in cases:
        raw_subject = c.get("subject", "No Subject")
        masked_subject = _mask_sensitive_tokens(raw_subject)
        
        primary_ioc = _extract_primary_ioc(c)
        cls = derive_case_classification(c)
        sev = derive_case_severity(c)

        activity.append({
            "case_id": c.get("case_id") or c.get("case_number", "N/A"),
            "timestamp": str(c.get("timestamp", ""))[:19],
            "sender": c.get("sender", "Unknown"),
            "subject": masked_subject,
            "risk_score": cls,
            "case_severity": sev,
            "status": c.get("status", "Open"),
            "primary_ioc": primary_ioc
        })
        if len(activity) >= effective_limit:
            break

    return activity


def get_soc_investigation_queue(user_id: Optional[str] = None, client: Any = None, limit: int = 15) -> List[Dict[str, Any]]:
    """
    Retrieve active/open investigations prioritised by severity:
    CRITICAL (0) > HIGH (1) > MEDIUM / SUSPICIOUS (2) > LOW / CLEAN (3).
    Enforces strict RLS tenant isolation. Fails closed if unauthenticated.
    """
    if not is_authenticated_soc_caller(user_id, client):
        return []

    effective_limit = max(1, min(limit or 15, 100))
    cases = get_all_cases(client=client, limit=effective_limit * 3)

    severity_weight = {
        "CRITICAL": 0,
        "HIGH": 1,
        "MEDIUM": 2,
        "SUSPICIOUS": 2,
        "LOW": 3,
        "CLEAN": 4
    }

    queue = []
    for c in cases:
        raw_subj = c.get("subject", "No Subject")
        masked_subj = _mask_sensitive_tokens(raw_subj)
        sev = derive_case_severity(c)
        cls = derive_case_classification(c)
        status = str(c.get("status") or "Open")
        primary_ioc = _extract_primary_ioc(c)

        # Prioritise open and active investigations
        is_open = status.strip().upper() in ("OPEN", "IN_PROGRESS", "IN PROGRESS", "ACTIVE", "NEW", "INVESTIGATING")

        queue.append({
            "case_id": c.get("case_id") or c.get("case_number", "N/A"),
            "timestamp": str(c.get("timestamp", ""))[:19],
            "sender": c.get("sender", "Unknown"),
            "subject": masked_subj,
            "severity": sev,
            "risk_score": cls,
            "status": status,
            "assigned_investigator": c.get("assigned_investigator", "Unassigned"),
            "primary_ioc": primary_ioc,
            "_sort_key": (0 if is_open else 1, severity_weight.get(sev, 2))
        })

    queue.sort(key=lambda x: x["_sort_key"])
    for item in queue:
        del item["_sort_key"]

    return queue[:effective_limit]

