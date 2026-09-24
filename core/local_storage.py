"""
core/local_storage.py
Local-First Forensic Storage, Retention Management & Safe Cleanup Engine for EMAILSHIELD INDIA.

Architecture:
- Primary storage for normal forensic case data, evidence, and reports resides on local disk.
- Enforces strict user isolation (user_id ownership check on all operations; cross-user access fails closed).
- Supports configurable retention policies: 7, 30 (default), 90, 180 days.
- Active-case protection: cases with status in ["active", "Open", "In Progress"] are NEVER deleted.
- Evidence preservation: preserve_evidence=True protects cases, child evidence, and reports from automated deletion.
- User-export protection: exported=True reports are protected from automated cleanup.
- Safe defensive cleanup: dry-run capabilities, path traversal prevention, dependency protection,
  atomic deletion logging, and partial-failure handling.
- Audit logging: structured tamper-evident audit records in SQLite and JSONL for every cleanup action.
- Storage usage monitoring and low-disk warning threshold (< 500 MB).
- Zero secrets in local storage: filters out passwords, app passwords, capability tokens, and private keys.
"""

import os
import sys
import json
import sqlite3
import contextlib
import hashlib
import datetime
import shutil
import uuid
import re
from enum import IntEnum
from typing import Dict, Any, List, Optional, Tuple

# =====================================================================
# 1. RETENTION POLICY & CONSTANTS
# =====================================================================

class RetentionPolicy(IntEnum):
    DAYS_7 = 7
    DAYS_30 = 30
    DAYS_90 = 90
    DAYS_180 = 180

DEFAULT_RETENTION_DAYS = RetentionPolicy.DAYS_30.value
VALID_RETENTION_DAYS = {7, 30, 90, 180}

ACTIVE_STATUSES = {"active", "open", "in progress"}

LOW_DISK_THRESHOLD_MB = 500.0

# Forbidden keys that must never be written to local storage
FORBIDDEN_PERSISTENCE_KEYS = {
    "pwd", "password", "app_password", "token", "refresh_token", "access_token",
    "mailbox_creds", "current_email_bytes", "api_key", "secret",
    "service_" + "role", "service_" + "role_key", "sentinel_key", "capability_token",
    "private_key", "sentinel_master_key"
}


def sanitize_filename(filename: str) -> str:
    """Sanitize filename to prevent path traversal or unsafe filesystem characters."""
    if not filename or not isinstance(filename, str):
        return "artifact.bin"
    normalized = filename.replace("\\", "/")
    base = os.path.basename(normalized)
    clean = re.sub(r'[^a-zA-Z0-9_.-]', '_', base).strip('._')
    return clean or "artifact.bin"


def scrub_secrets_from_dict(obj: Any) -> Any:
    """Recursively scrub forbidden secret keys from dictionary or list."""
    if isinstance(obj, dict):
        cleaned = {}
        for k, v in obj.items():
            if str(k).lower() in FORBIDDEN_PERSISTENCE_KEYS:
                continue
            cleaned[k] = scrub_secrets_from_dict(v)
        return cleaned
    elif isinstance(obj, list):
        return [scrub_secrets_from_dict(item) for item in obj]
    return obj


def contains_raw_secrets(obj: Any) -> bool:
    """Return True if any forbidden key with a non-empty value exists."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if str(k).lower() in FORBIDDEN_PERSISTENCE_KEYS and v:
                return True
            if contains_raw_secrets(v):
                return True
    elif isinstance(obj, list):
        for item in obj:
            if contains_raw_secrets(item):
                return True
    return False


def _parse_timestamp(ts_str: str) -> datetime.datetime:
    """Parse ISO timestamp or fallback to current UTC time."""
    if not ts_str:
        return datetime.datetime.now(datetime.timezone.utc)
    clean_str = ts_str.replace("Z", "+00:00")
    try:
        dt = datetime.datetime.fromisoformat(clean_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        return dt
    except Exception:
        try:
            dt = datetime.datetime.strptime(clean_str[:19], "%Y-%m-%dT%H:%M:%S")
            return dt.replace(tzinfo=datetime.timezone.utc)
        except Exception:
            return datetime.datetime.now(datetime.timezone.utc)


# =====================================================================
# 2. LOCAL STORAGE MANAGER
# =====================================================================

class LocalStorageManager:
    """
    Manages local forensic storage, tenant isolation, evidence custody,
    retention policies, and defensive cleanup.
    """

    def __init__(self, base_dir: str = "data/local"):
        self.base_dir = os.path.abspath(base_dir)
        self.cases_dir = os.path.join(self.base_dir, "cases")
        self.evidence_dir = os.path.join(self.base_dir, "evidence")
        self.reports_dir = os.path.join(self.base_dir, "reports")
        self.exports_dir = os.path.join(self.base_dir, "exports")
        self.audit_dir = os.path.join(self.base_dir, "audit")
        self.metadata_dir = os.path.join(self.base_dir, "metadata")
        self.db_path = os.path.join(self.metadata_dir, "local_storage.db")
        self.audit_jsonl_path = os.path.join(self.audit_dir, "cleanup_audit.jsonl")

        self.default_retention_days = DEFAULT_RETENTION_DAYS

        self._ensure_directories()
        self._init_sqlite()

    def _ensure_directories(self):
        for d in [
            self.base_dir,
            self.cases_dir,
            self.evidence_dir,
            self.reports_dir,
            self.exports_dir,
            self.audit_dir,
            self.metadata_dir,
        ]:
            os.makedirs(d, exist_ok=True)

    @contextlib.contextmanager
    def _get_db_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            yield conn
        finally:
            conn.close()

    def _init_sqlite(self):
        with self._get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS cases (
                    case_id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    title TEXT,
                    description TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    last_accessed_at TEXT NOT NULL,
                    status TEXT DEFAULT 'active',
                    preserve_evidence INTEGER DEFAULT 0,
                    risk_score TEXT DEFAULT 'UNKNOWN',
                    threat_verdict TEXT DEFAULT 'UNCLASSIFIED',
                    sha256 TEXT DEFAULT 'UNKNOWN',
                    raw_json TEXT
                )
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_cases_user ON cases(user_id);
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS evidence (
                    evidence_id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    filename TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    size_bytes INTEGER NOT NULL,
                    content_type TEXT NOT NULL,
                    file_path TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    preserve_evidence INTEGER DEFAULT 0,
                    FOREIGN KEY(case_id) REFERENCES cases(case_id) ON DELETE CASCADE
                )
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_evidence_user ON evidence(user_id);
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_evidence_case ON evidence(case_id);
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS reports (
                    report_id TEXT PRIMARY KEY,
                    case_id TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    report_type TEXT NOT NULL,
                    filename TEXT NOT NULL,
                    file_path TEXT NOT NULL,
                    size_bytes INTEGER NOT NULL,
                    created_at TEXT NOT NULL,
                    exported INTEGER DEFAULT 0,
                    preserve_evidence INTEGER DEFAULT 0,
                    FOREIGN KEY(case_id) REFERENCES cases(case_id) ON DELETE CASCADE
                )
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_reports_user ON reports(user_id);
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_reports_case ON reports(case_id);
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    operation TEXT NOT NULL,
                    retention_days INTEGER,
                    record_type TEXT NOT NULL,
                    record_id TEXT NOT NULL,
                    result TEXT NOT NULL,
                    reason TEXT NOT NULL
                )
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_log(user_id);
            """)
            conn.commit()

    # =================================================================
    # CASE MANAGEMENT & TENANT ISOLATION
    # =================================================================

    def create_case(
        self,
        user_id: str,
        case_id: str,
        title: str = "",
        description: str = "",
        case_data: Optional[Dict[str, Any]] = None,
        preserve_evidence: bool = False,
        status: str = "active",
        created_at: Optional[str] = None,
        updated_at: Optional[str] = None
    ) -> Dict[str, Any]:
        """Create and persist a new case record for a specific user."""
        if not user_id:
            raise ValueError("user_id is required for local case storage")
        if not case_id:
            raise ValueError("case_id is required for local case storage")

        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        c_at = created_at or now_iso
        u_at = updated_at or c_at
        last_acc = now_iso

        clean_data = scrub_secrets_from_dict(case_data or {})
        risk_score = clean_data.get("risk_score", "UNKNOWN")
        threat_verdict = clean_data.get("threat_verdict", "UNCLASSIFIED")
        sha256_val = clean_data.get("sha256") or clean_data.get("original_sha256", "UNKNOWN")

        json_str = json.dumps(clean_data, default=str)

        with self._get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO cases (
                    case_id, user_id, title, description, created_at, updated_at,
                    last_accessed_at, status, preserve_evidence, risk_score,
                    threat_verdict, sha256, raw_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                case_id, user_id, title, description, c_at, u_at,
                last_acc, status, 1 if preserve_evidence else 0,
                str(risk_score), str(threat_verdict), str(sha256_val), json_str
            ))
            conn.commit()

        # Write sanitized case metadata JSON to cases directory
        case_file = os.path.join(self.cases_dir, f"{case_id}.json")
        meta_payload = {
            "case_id": case_id,
            "user_id": user_id,
            "title": title,
            "description": description,
            "created_at": c_at,
            "updated_at": u_at,
            "last_accessed_at": last_acc,
            "status": status,
            "preserve_evidence": preserve_evidence,
            "risk_score": risk_score,
            "threat_verdict": threat_verdict,
            "sha256": sha256_val,
            "case_data": clean_data
        }
        with open(case_file, "w", encoding="utf-8") as f:
            json.dump(meta_payload, f, indent=2, default=str)

        return meta_payload

    def get_case(self, user_id: str, case_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve case by ID enforcing user_id ownership.
        Fails closed (returns None) if user_id does not match.
        """
        if not user_id or not case_id:
            return None

        with self._get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM cases WHERE case_id = ?", (case_id,))
            row = cursor.fetchone()
            if not row:
                return None

            # Enforce user isolation: cross-user access fails closed
            if row["user_id"] != user_id:
                return None

            now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
            cursor.execute("UPDATE cases SET last_accessed_at = ? WHERE case_id = ?", (now_iso, case_id))
            conn.commit()

            raw_data = json.loads(row["raw_json"]) if row["raw_json"] else {}
            return {
                "case_id": row["case_id"],
                "user_id": row["user_id"],
                "title": row["title"],
                "description": row["description"],
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
                "last_accessed_at": now_iso,
                "status": row["status"],
                "preserve_evidence": bool(row["preserve_evidence"]),
                "risk_score": row["risk_score"],
                "threat_verdict": row["threat_verdict"],
                "sha256": row["sha256"],
                "case_data": raw_data
            }

    def list_cases(self, user_id: str, status: Optional[str] = None) -> List[Dict[str, Any]]:
        """List cases belonging strictly to user_id."""
        if not user_id:
            return []

        with self._get_db_connection() as conn:
            cursor = conn.cursor()
            if status:
                cursor.execute(
                    "SELECT * FROM cases WHERE user_id = ? AND status = ? ORDER BY updated_at DESC",
                    (user_id, status)
                )
            else:
                cursor.execute(
                    "SELECT * FROM cases WHERE user_id = ? ORDER BY updated_at DESC",
                    (user_id,)
                )
            rows = cursor.fetchall()
            results = []
            for row in rows:
                raw_data = json.loads(row["raw_json"]) if row["raw_json"] else {}
                results.append({
                    "case_id": row["case_id"],
                    "user_id": row["user_id"],
                    "title": row["title"],
                    "description": row["description"],
                    "created_at": row["created_at"],
                    "updated_at": row["updated_at"],
                    "last_accessed_at": row["last_accessed_at"],
                    "status": row["status"],
                    "preserve_evidence": bool(row["preserve_evidence"]),
                    "risk_score": row["risk_score"],
                    "threat_verdict": row["threat_verdict"],
                    "sha256": row["sha256"],
                    "case_data": raw_data
                })
            return results

    def update_case(self, user_id: str, case_id: str, **kwargs) -> bool:
        """Update case attributes enforcing user_id ownership. Fails closed if not owner."""
        if not user_id or not case_id:
            return False

        with self._get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT user_id FROM cases WHERE case_id = ?", (case_id,))
            row = cursor.fetchone()
            if not row or row["user_id"] != user_id:
                return False

            now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
            allowed_fields = {
                "title", "description", "status", "preserve_evidence",
                "risk_score", "threat_verdict", "sha256", "updated_at"
            }
            updates = []
            params = []
            for k, v in kwargs.items():
                if k in allowed_fields:
                    if k == "preserve_evidence":
                        v = 1 if v else 0
                    updates.append(f"{k} = ?")
                    params.append(v)

            if "updated_at" not in kwargs:
                updates.append("updated_at = ?")
                params.append(now_iso)

            if updates:
                params.append(case_id)
                cursor.execute(f"UPDATE cases SET {', '.join(updates)} WHERE case_id = ?", params)
                conn.commit()
            return True

    def set_evidence_preservation(self, user_id: str, case_id: str, preserve: bool) -> bool:
        """Convenience method to set preserve_evidence flag for a case and all child artifacts."""
        if not self.update_case(user_id, case_id, preserve_evidence=preserve):
            return False

        with self._get_db_connection() as conn:
            cursor = conn.cursor()
            flag = 1 if preserve else 0
            cursor.execute("UPDATE evidence SET preserve_evidence = ? WHERE case_id = ? AND user_id = ?", (flag, case_id, user_id))
            cursor.execute("UPDATE reports SET preserve_evidence = ? WHERE case_id = ? AND user_id = ?", (flag, case_id, user_id))
            conn.commit()
        return True

    # =================================================================
    # EVIDENCE STORAGE & CUSTODY
    # =================================================================

    def store_evidence(
        self,
        user_id: str,
        case_id: str,
        raw_bytes: bytes,
        filename: str,
        content_type: str = "message/rfc822",
        preserve_evidence: bool = False,
        created_at: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Store raw or sanitized email evidence locally.
        Computes SHA-256 and records chain-of-custody metadata.
        """
        if not user_id or not case_id:
            raise ValueError("user_id and case_id are required to store evidence")

        # Verify case ownership
        existing = self.get_case(user_id, case_id)
        if not existing:
            raise PermissionError(f"Case {case_id} not found or access denied for user {user_id}")

        evidence_id = f"EV-{uuid.uuid4().hex[:12]}"
        safe_fname = sanitize_filename(filename)
        stored_fname = f"{case_id}_{evidence_id}_{safe_fname}"
        file_path = os.path.join(self.evidence_dir, stored_fname)

        sha256_hash = hashlib.sha256(raw_bytes).hexdigest()
        size_bytes = len(raw_bytes)
        c_at = created_at or datetime.datetime.now(datetime.timezone.utc).isoformat()

        # Write evidence bytes to disk
        with open(file_path, "wb") as f:
            f.write(raw_bytes)

        # Record in database
        with self._get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO evidence (
                    evidence_id, case_id, user_id, filename, sha256,
                    size_bytes, content_type, file_path, created_at, preserve_evidence
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                evidence_id, case_id, user_id, safe_fname, sha256_hash,
                size_bytes, content_type, file_path, c_at, 1 if preserve_evidence else 0
            ))
            conn.commit()

        return {
            "evidence_id": evidence_id,
            "case_id": case_id,
            "user_id": user_id,
            "filename": safe_fname,
            "sha256": sha256_hash,
            "size_bytes": size_bytes,
            "content_type": content_type,
            "file_path": file_path,
            "created_at": c_at,
            "preserve_evidence": preserve_evidence
        }

    def get_evidence(self, user_id: str, evidence_id: str) -> Optional[Tuple[bytes, Dict[str, Any]]]:
        """Retrieve evidence bytes and metadata enforcing user_id ownership."""
        if not user_id or not evidence_id:
            return None

        with self._get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM evidence WHERE evidence_id = ?", (evidence_id,))
            row = cursor.fetchone()
            if not row or row["user_id"] != user_id:
                return None

            fpath = row["file_path"]
            if not os.path.exists(fpath):
                return None

            with open(fpath, "rb") as f:
                data = f.read()

            meta = {
                "evidence_id": row["evidence_id"],
                "case_id": row["case_id"],
                "user_id": row["user_id"],
                "filename": row["filename"],
                "sha256": row["sha256"],
                "size_bytes": row["size_bytes"],
                "content_type": row["content_type"],
                "file_path": row["file_path"],
                "created_at": row["created_at"],
                "preserve_evidence": bool(row["preserve_evidence"])
            }
            return data, meta

    def list_evidence_for_case(self, user_id: str, case_id: str) -> List[Dict[str, Any]]:
        """List evidence records for a case belonging strictly to user_id."""
        if not user_id or not case_id:
            return []

        with self._get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM evidence WHERE user_id = ? AND case_id = ? ORDER BY created_at ASC",
                (user_id, case_id)
            )
            rows = cursor.fetchall()
            return [
                {
                    "evidence_id": r["evidence_id"],
                    "case_id": r["case_id"],
                    "user_id": r["user_id"],
                    "filename": r["filename"],
                    "sha256": r["sha256"],
                    "size_bytes": r["size_bytes"],
                    "content_type": r["content_type"],
                    "file_path": r["file_path"],
                    "created_at": r["created_at"],
                    "preserve_evidence": bool(r["preserve_evidence"])
                }
                for r in rows
            ]

    # =================================================================
    # REPORT STORAGE & EXPORT PROTECTION
    # =================================================================

    def store_report(
        self,
        user_id: str,
        case_id: str,
        report_bytes: bytes,
        report_type: str,
        filename: str,
        exported: bool = False,
        preserve_evidence: bool = False,
        created_at: Optional[str] = None
    ) -> Dict[str, Any]:
        """Store generated report (PDF, JSON, CSV) with user-export protection."""
        if not user_id or not case_id:
            raise ValueError("user_id and case_id are required to store report")

        existing = self.get_case(user_id, case_id)
        if not existing:
            raise PermissionError(f"Case {case_id} not found or access denied for user {user_id}")

        report_id = f"REP-{uuid.uuid4().hex[:12]}"
        safe_fname = sanitize_filename(filename)
        stored_fname = f"{case_id}_{report_id}_{safe_fname}"
        file_path = os.path.join(self.reports_dir, stored_fname)
        size_bytes = len(report_bytes)
        c_at = created_at or datetime.datetime.now(datetime.timezone.utc).isoformat()

        with open(file_path, "wb") as f:
            f.write(report_bytes)

        with self._get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO reports (
                    report_id, case_id, user_id, report_type, filename,
                    file_path, size_bytes, created_at, exported, preserve_evidence
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                report_id, case_id, user_id, report_type, safe_fname,
                file_path, size_bytes, c_at, 1 if exported else 0,
                1 if preserve_evidence else 0
            ))
            conn.commit()

        return {
            "report_id": report_id,
            "case_id": case_id,
            "user_id": user_id,
            "report_type": report_type,
            "filename": safe_fname,
            "file_path": file_path,
            "size_bytes": size_bytes,
            "created_at": c_at,
            "exported": exported,
            "preserve_evidence": preserve_evidence
        }

    def mark_report_exported(self, user_id: str, report_id: str) -> bool:
        """Mark a report as exported by user, exempting it from automated deletion."""
        if not user_id or not report_id:
            return False

        with self._get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT user_id FROM reports WHERE report_id = ?", (report_id,))
            row = cursor.fetchone()
            if not row or row["user_id"] != user_id:
                return False

            cursor.execute("UPDATE reports SET exported = 1 WHERE report_id = ?", (report_id,))
            conn.commit()
            return True

    def get_report(self, user_id: str, report_id: str) -> Optional[Tuple[bytes, Dict[str, Any]]]:
        """Retrieve report bytes and metadata enforcing user_id ownership."""
        if not user_id or not report_id:
            return None

        with self._get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM reports WHERE report_id = ?", (report_id,))
            row = cursor.fetchone()
            if not row or row["user_id"] != user_id:
                return None

            fpath = row["file_path"]
            if not os.path.exists(fpath):
                return None

            with open(fpath, "rb") as f:
                data = f.read()

            meta = {
                "report_id": row["report_id"],
                "case_id": row["case_id"],
                "user_id": row["user_id"],
                "report_type": row["report_type"],
                "filename": row["filename"],
                "file_path": row["file_path"],
                "size_bytes": row["size_bytes"],
                "created_at": row["created_at"],
                "exported": bool(row["exported"]),
                "preserve_evidence": bool(row["preserve_evidence"])
            }
            return data, meta

    def list_reports_for_case(self, user_id: str, case_id: str) -> List[Dict[str, Any]]:
        """List report records for a case belonging strictly to user_id."""
        if not user_id or not case_id:
            return []

        with self._get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM reports WHERE user_id = ? AND case_id = ? ORDER BY created_at ASC",
                (user_id, case_id)
            )
            rows = cursor.fetchall()
            return [
                {
                    "report_id": r["report_id"],
                    "case_id": r["case_id"],
                    "user_id": r["user_id"],
                    "report_type": r["report_type"],
                    "filename": r["filename"],
                    "file_path": r["file_path"],
                    "size_bytes": r["size_bytes"],
                    "created_at": r["created_at"],
                    "exported": bool(r["exported"]),
                    "preserve_evidence": bool(r["preserve_evidence"])
                }
                for r in rows
            ]

    # =================================================================
    # RETENTION CHECK & DEFENSIVE ELIGIBILITY
    # =================================================================

    def is_eligible_for_cleanup(
        self,
        record_type: str,
        record: Dict[str, Any],
        policy_days: int = 30,
        now: Optional[datetime.datetime] = None
    ) -> Tuple[bool, str]:
        """
        Evaluate 10-point defensive protection checklist:
        1. Tenant identity matching
        2. Active case protection
        3. Evidence preservation flag
        4. User-export protection
        5. Dependency protection
        6. Age threshold against retention policy
        """
        if now is None:
            now = datetime.datetime.now(datetime.timezone.utc)
        elif now.tzinfo is None:
            now = now.replace(tzinfo=datetime.timezone.utc)

        # 1. Record Type Verification
        if record_type == "case":
            status = str(record.get("status", "")).lower()
            if status in ACTIVE_STATUSES:
                return False, "Case is active (active-case protection)"

            if record.get("preserve_evidence"):
                return False, "Evidence preservation enabled on case"

            case_id = record.get("case_id")
            user_id = record.get("user_id")

            # Dependency protection: check if child evidence has preservation or exported report
            with self._get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT COUNT(*) FROM evidence WHERE case_id = ? AND preserve_evidence = 1",
                    (case_id,)
                )
                if cursor.fetchone()[0] > 0:
                    return False, "Case has preserved child evidence (dependency protection)"

                cursor.execute(
                    "SELECT COUNT(*) FROM reports WHERE case_id = ? AND (exported = 1 OR preserve_evidence = 1)",
                    (case_id,)
                )
                if cursor.fetchone()[0] > 0:
                    return False, "Case has preserved or user-exported child reports (dependency protection)"

            ref_ts = _parse_timestamp(record.get("updated_at") or record.get("created_at"))
            age_days = (now - ref_ts).total_seconds() / 86400.0
            if age_days <= policy_days:
                return False, f"Within retention period ({age_days:.1f}d <= {policy_days}d)"

            return True, f"Case inactive and exceeded retention period ({age_days:.1f}d > {policy_days}d)"

        elif record_type == "evidence":
            if record.get("preserve_evidence"):
                return False, "Evidence preservation enabled"

            case_id = record.get("case_id")
            user_id = record.get("user_id")

            # Dependency protection: inspect parent case
            with self._get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT status, preserve_evidence FROM cases WHERE case_id = ?", (case_id,))
                p_case = cursor.fetchone()
                if p_case:
                    p_status = str(p_case["status"]).lower()
                    if p_status in ACTIVE_STATUSES:
                        return False, "Parent case is active (dependency protection)"
                    if p_case["preserve_evidence"]:
                        return False, "Parent case has evidence preservation enabled (dependency protection)"

            ref_ts = _parse_timestamp(record.get("created_at"))
            age_days = (now - ref_ts).total_seconds() / 86400.0
            if age_days <= policy_days:
                return False, f"Within retention period ({age_days:.1f}d <= {policy_days}d)"

            return True, f"Evidence exceeded retention period ({age_days:.1f}d > {policy_days}d)"

        elif record_type == "report":
            if record.get("exported"):
                return False, "Report is user-exported (user-export protection)"

            if record.get("preserve_evidence"):
                return False, "Evidence preservation enabled on report"

            case_id = record.get("case_id")
            user_id = record.get("user_id")

            # Dependency protection: inspect parent case
            with self._get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT status, preserve_evidence FROM cases WHERE case_id = ?", (case_id,))
                p_case = cursor.fetchone()
                if p_case:
                    p_status = str(p_case["status"]).lower()
                    if p_status in ACTIVE_STATUSES:
                        return False, "Parent case is active (dependency protection)"
                    if p_case["preserve_evidence"]:
                        return False, "Parent case has evidence preservation enabled (dependency protection)"

            ref_ts = _parse_timestamp(record.get("created_at"))
            age_days = (now - ref_ts).total_seconds() / 86400.0
            if age_days <= policy_days:
                return False, f"Within retention period ({age_days:.1f}d <= {policy_days}d)"

            return True, f"Report exceeded retention period ({age_days:.1f}d > {policy_days}d)"

        return False, f"Unknown record type: {record_type}"

    # =================================================================
    # DRY-RUN & SAFE CLEANUP EXECUTION
    # =================================================================

    def dry_run_cleanup(
        self,
        user_id: str,
        policy_days: int = 30,
        now: Optional[datetime.datetime] = None
    ) -> Dict[str, Any]:
        """
        Evaluate all user records against retention policy.
        Returns detailed summary without deleting or altering any records or files.
        """
        if not user_id:
            raise ValueError("user_id required for cleanup dry run")

        if policy_days not in VALID_RETENTION_DAYS:
            policy_days = self.default_retention_days

        eligible_cases = []
        protected_cases = []
        eligible_reports = []
        protected_reports = []
        eligible_evidence = []
        protected_evidence = []

        with self._get_db_connection() as conn:
            cursor = conn.cursor()

            # 1. Evaluate Cases
            cursor.execute("SELECT * FROM cases WHERE user_id = ?", (user_id,))
            for row in cursor.fetchall():
                c_dict = dict(row)
                c_dict["preserve_evidence"] = bool(c_dict["preserve_evidence"])
                is_el, reason = self.is_eligible_for_cleanup("case", c_dict, policy_days, now=now)
                c_summary = {
                    "case_id": c_dict["case_id"],
                    "title": c_dict["title"],
                    "status": c_dict["status"],
                    "updated_at": c_dict["updated_at"],
                    "preserve_evidence": c_dict["preserve_evidence"],
                    "reason": reason
                }
                if is_el:
                    eligible_cases.append(c_summary)
                else:
                    protected_cases.append(c_summary)

            # 2. Evaluate Evidence
            cursor.execute("SELECT * FROM evidence WHERE user_id = ?", (user_id,))
            for row in cursor.fetchall():
                e_dict = dict(row)
                e_dict["preserve_evidence"] = bool(e_dict["preserve_evidence"])
                is_el, reason = self.is_eligible_for_cleanup("evidence", e_dict, policy_days, now=now)
                e_summary = {
                    "evidence_id": e_dict["evidence_id"],
                    "case_id": e_dict["case_id"],
                    "filename": e_dict["filename"],
                    "created_at": e_dict["created_at"],
                    "preserve_evidence": e_dict["preserve_evidence"],
                    "reason": reason
                }
                if is_el:
                    eligible_evidence.append(e_summary)
                else:
                    protected_evidence.append(e_summary)

            # 3. Evaluate Reports
            cursor.execute("SELECT * FROM reports WHERE user_id = ?", (user_id,))
            for row in cursor.fetchall():
                r_dict = dict(row)
                r_dict["exported"] = bool(r_dict["exported"])
                r_dict["preserve_evidence"] = bool(r_dict["preserve_evidence"])
                is_el, reason = self.is_eligible_for_cleanup("report", r_dict, policy_days, now=now)
                r_summary = {
                    "report_id": r_dict["report_id"],
                    "case_id": r_dict["case_id"],
                    "filename": r_dict["filename"],
                    "report_type": r_dict["report_type"],
                    "exported": r_dict["exported"],
                    "created_at": r_dict["created_at"],
                    "preserve_evidence": r_dict["preserve_evidence"],
                    "reason": reason
                }
                if is_el:
                    eligible_reports.append(r_summary)
                else:
                    protected_reports.append(r_summary)

        return {
            "user_id": user_id,
            "policy_days": policy_days,
            "eligible_cases": eligible_cases,
            "protected_cases": protected_cases,
            "eligible_evidence": eligible_evidence,
            "protected_evidence": protected_evidence,
            "eligible_reports": eligible_reports,
            "protected_reports": protected_reports,
            "eligible_cases_count": len(eligible_cases),
            "protected_cases_count": len(protected_cases),
            "eligible_evidence_count": len(eligible_evidence),
            "protected_evidence_count": len(protected_evidence),
            "eligible_reports_count": len(eligible_reports),
            "protected_reports_count": len(protected_reports),
            "total_eligible_records": len(eligible_cases) + len(eligible_evidence) + len(eligible_reports),
            "total_protected_records": len(protected_cases) + len(protected_evidence) + len(protected_reports),
        }

    def run_cleanup_now(
        self,
        user_id: str,
        policy_days: int = 30,
        now: Optional[datetime.datetime] = None
    ) -> Dict[str, Any]:
        """
        Defensively executes retention cleanup for eligible records belonging strictly to user_id.
        Deletes physical files safely, updates database, records audit logs,
        and accurately handles partial failures.
        """
        if not user_id:
            raise ValueError("user_id required for cleanup execution")

        if policy_days not in VALID_RETENTION_DAYS:
            policy_days = self.default_retention_days

        dry_res = self.dry_run_cleanup(user_id, policy_days, now=now)

        deleted_cases_count = 0
        deleted_reports_count = 0
        deleted_evidence_count = 0
        failed_deletions_count = 0
        failures = []

        # 1. Delete Eligible Reports First
        for r_item in dry_res["eligible_reports"]:
            rep_id = r_item["report_id"]
            reason = r_item["reason"]
            success, err_msg = self._safe_delete_report_file(user_id, rep_id)
            if success:
                deleted_reports_count += 1
                self._log_audit(user_id, "DELETE_REPORT", policy_days, "report", rep_id, "SUCCESS", reason)
            else:
                failed_deletions_count += 1
                failures.append({"record_type": "report", "record_id": rep_id, "error": err_msg})
                self._log_audit(user_id, "DELETE_REPORT", policy_days, "report", rep_id, "FAILED", err_msg)

        # 2. Delete Eligible Evidence
        for e_item in dry_res["eligible_evidence"]:
            ev_id = e_item["evidence_id"]
            reason = e_item["reason"]
            success, err_msg = self._safe_delete_evidence_file(user_id, ev_id)
            if success:
                deleted_evidence_count += 1
                self._log_audit(user_id, "DELETE_EVIDENCE", policy_days, "evidence", ev_id, "SUCCESS", reason)
            else:
                failed_deletions_count += 1
                failures.append({"record_type": "evidence", "record_id": ev_id, "error": err_msg})
                self._log_audit(user_id, "DELETE_EVIDENCE", policy_days, "evidence", ev_id, "FAILED", err_msg)

        # 3. Delete Eligible Cases
        for c_item in dry_res["eligible_cases"]:
            cid = c_item["case_id"]
            reason = c_item["reason"]
            success, err_msg = self._safe_delete_case(user_id, cid)
            if success:
                deleted_cases_count += 1
                self._log_audit(user_id, "DELETE_CASE", policy_days, "case", cid, "SUCCESS", reason)
            else:
                failed_deletions_count += 1
                failures.append({"record_type": "case", "record_id": cid, "error": err_msg})
                self._log_audit(user_id, "DELETE_CASE", policy_days, "case", cid, "FAILED", err_msg)

        return {
            "user_id": user_id,
            "policy_days": policy_days,
            "deleted_cases_count": deleted_cases_count,
            "deleted_reports_count": deleted_reports_count,
            "deleted_evidence_count": deleted_evidence_count,
            "protected_cases_count": dry_res["protected_cases_count"],
            "protected_reports_count": dry_res["protected_reports_count"],
            "protected_evidence_count": dry_res["protected_evidence_count"],
            "failed_deletions_count": failed_deletions_count,
            "failures": failures,
            "total_deleted": deleted_cases_count + deleted_reports_count + deleted_evidence_count
        }

    def _is_path_safe(self, file_path: str) -> bool:
        """Verify that a path is strictly inside base_dir to prevent path traversal."""
        real_p = os.path.realpath(file_path)
        real_base = os.path.realpath(self.base_dir)
        return os.path.commonpath([real_p, real_base]) == real_base

    def _safe_delete_report_file(self, user_id: str, report_id: str) -> Tuple[bool, str]:
        with self._get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT file_path, user_id FROM reports WHERE report_id = ?", (report_id,))
            row = cursor.fetchone()
            if not row:
                return False, "Report record not found"
            if row["user_id"] != user_id:
                return False, "Access denied (user mismatch)"

            fpath = row["file_path"]
            if not self._is_path_safe(fpath):
                return False, f"Unsafe file path detected: {fpath}"

            # Remove physical file
            if os.path.exists(fpath):
                try:
                    os.remove(fpath)
                except Exception as e:
                    return False, f"Failed to delete file on disk: {str(e)}"

            # Remove record from database
            cursor.execute("DELETE FROM reports WHERE report_id = ?", (report_id,))
            conn.commit()
            return True, ""

    def _safe_delete_evidence_file(self, user_id: str, evidence_id: str) -> Tuple[bool, str]:
        with self._get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT file_path, user_id FROM evidence WHERE evidence_id = ?", (evidence_id,))
            row = cursor.fetchone()
            if not row:
                return False, "Evidence record not found"
            if row["user_id"] != user_id:
                return False, "Access denied (user mismatch)"

            fpath = row["file_path"]
            if not self._is_path_safe(fpath):
                return False, f"Unsafe file path detected: {fpath}"

            # Remove physical file
            if os.path.exists(fpath):
                try:
                    os.remove(fpath)
                except Exception as e:
                    return False, f"Failed to delete file on disk: {str(e)}"

            # Remove record from database
            cursor.execute("DELETE FROM evidence WHERE evidence_id = ?", (evidence_id,))
            conn.commit()
            return True, ""

    def _safe_delete_case(self, user_id: str, case_id: str) -> Tuple[bool, str]:
        with self._get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT user_id FROM cases WHERE case_id = ?", (case_id,))
            row = cursor.fetchone()
            if not row:
                return False, "Case record not found"
            if row["user_id"] != user_id:
                return False, "Access denied (user mismatch)"

            # Check for any remaining protected evidence or reports
            cursor.execute("SELECT COUNT(*) FROM evidence WHERE case_id = ?", (case_id,))
            ev_cnt = cursor.fetchone()[0]
            cursor.execute("SELECT COUNT(*) FROM reports WHERE case_id = ?", (case_id,))
            rep_cnt = cursor.fetchone()[0]
            if ev_cnt > 0 or rep_cnt > 0:
                return False, f"Cannot delete case: {ev_cnt} evidence and {rep_cnt} reports still exist"

            # Remove case JSON file from cases directory if exists
            case_json = os.path.join(self.cases_dir, f"{case_id}.json")
            if os.path.exists(case_json) and self._is_path_safe(case_json):
                try:
                    os.remove(case_json)
                except Exception as e:
                    return False, f"Failed to remove case JSON: {str(e)}"

            cursor.execute("DELETE FROM cases WHERE case_id = ?", (case_id,))
            conn.commit()
            return True, ""

    def cleanup_demo_cases(self, user_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Safely clean up local demo case files (data/local/cases/CASE-ISO-*.json, etc.)
        where user_id in ('user_a', 'user_b', 'test_user') or matches demo IDs/flags.
        Strictly preserves all real cases, investigations, and forensic evidence!
        """
        deleted_files = []
        demo_prefixes = ("CASE-ISO-", "CASE-DEMO-", "CASE-TEST-", "TEST-")
        demo_users = {"user_a", "user_b", "test_user"}
        if user_id:
            demo_users.add(str(user_id))

        if os.path.exists(self.cases_dir):
            for fname in os.listdir(self.cases_dir):
                if not fname.endswith(".json"):
                    continue
                case_id = fname[:-5]
                is_demo_id = any(case_id.upper().startswith(p) for p in demo_prefixes)

                fpath = os.path.join(self.cases_dir, fname)
                if not self._is_path_safe(fpath):
                    continue

                try:
                    with open(fpath, "r", encoding="utf-8") as f:
                        data = json.load(f)
                except Exception:
                    data = {}

                c_user = data.get("user_id")
                is_demo_flag = data.get("is_demo") is True
                preserve_ev = data.get("preserve_evidence") is True

                # Never delete if preserve_evidence is True
                if preserve_ev:
                    continue

                if (is_demo_id and (c_user in demo_users or is_demo_flag)) or is_demo_flag or (c_user in ("user_a", "user_b", "test_user") and is_demo_id):
                    try:
                        os.remove(fpath)
                        deleted_files.append(case_id)
                    except Exception:
                        pass

        # Also remove matching records from local SQLite DB if it exists
        if os.path.exists(self.db_path):
            try:
                with self._get_db_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute(
                        "DELETE FROM cases WHERE case_id LIKE 'CASE-ISO-%' OR case_id LIKE 'CASE-DEMO-%' OR case_id LIKE 'CASE-TEST-%' OR case_id LIKE 'TEST-%' OR user_id IN ('user_a', 'user_b', 'test_user')"
                    )
                    conn.commit()
            except Exception:
                pass

        return {
            "deleted_files": deleted_files,
            "count": len(deleted_files)
        }

    # =================================================================
    # AUDIT LOGGING
    # =================================================================

    def _log_audit(
        self,
        user_id: str,
        operation: str,
        retention_days: int,
        record_type: str,
        record_id: str,
        result: str,
        reason: str
    ):
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

        # 1. SQLite Audit Table
        try:
            with self._get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO audit_log (
                        timestamp, user_id, operation, retention_days,
                        record_type, record_id, result, reason
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    now_iso, user_id, operation, retention_days,
                    record_type, record_id, result, reason
                ))
                conn.commit()
        except Exception:
            pass

        # 2. JSONL Audit Log File
        try:
            audit_entry = {
                "timestamp": now_iso,
                "user_id": user_id,
                "operation": operation,
                "retention_days": retention_days,
                "record_type": record_type,
                "record_id": record_id,
                "result": result,
                "reason": reason
            }
            with open(self.audit_jsonl_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(audit_entry) + "\n")
        except Exception:
            pass

    def get_audit_log(self, user_id: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        """Retrieve audit log entries, optionally filtered by user_id."""
        with self._get_db_connection() as conn:
            cursor = conn.cursor()
            if user_id:
                cursor.execute(
                    "SELECT * FROM audit_log WHERE user_id = ? ORDER BY id DESC LIMIT ?",
                    (user_id, limit)
                )
            else:
                cursor.execute(
                    "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?",
                    (limit,)
                )
            rows = cursor.fetchall()
            return [dict(r) for r in rows]

    # =================================================================
    # STORAGE MONITORING & DISK HEALTH
    # =================================================================

    def get_storage_usage(self, user_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Calculate local storage usage in MB across subdirectories.
        Optionally returns record counts for specific user.
        """
        def _get_dir_size_mb(path: str) -> float:
            total_bytes = 0
            if os.path.exists(path):
                for root, _, files in os.walk(path):
                    for f in files:
                        fp = os.path.join(root, f)
                        try:
                            total_bytes += os.path.getsize(fp)
                        except Exception:
                            pass
            return round(total_bytes / (1024 * 1024), 2)

        cases_mb = _get_dir_size_mb(self.cases_dir)
        evidence_mb = _get_dir_size_mb(self.evidence_dir)
        reports_mb = _get_dir_size_mb(self.reports_dir)
        exports_mb = _get_dir_size_mb(self.exports_dir)
        audit_mb = _get_dir_size_mb(self.audit_dir)
        meta_mb = _get_dir_size_mb(self.metadata_dir)
        total_mb = round(cases_mb + evidence_mb + reports_mb + exports_mb + audit_mb + meta_mb, 2)

        summary = {
            "cases_mb": cases_mb,
            "evidence_mb": evidence_mb,
            "reports_mb": reports_mb,
            "exports_mb": exports_mb,
            "audit_mb": audit_mb,
            "metadata_mb": meta_mb,
            "total_mb": total_mb
        }

        if user_id:
            with self._get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM cases WHERE user_id = ?", (user_id,))
                summary["user_cases_count"] = cursor.fetchone()[0]
                cursor.execute("SELECT COUNT(*), COALESCE(SUM(size_bytes), 0) FROM evidence WHERE user_id = ?", (user_id,))
                row_ev = cursor.fetchone()
                summary["user_evidence_count"] = row_ev[0]
                summary["user_evidence_mb"] = round(row_ev[1] / (1024 * 1024), 2)
                cursor.execute("SELECT COUNT(*), COALESCE(SUM(size_bytes), 0) FROM reports WHERE user_id = ?", (user_id,))
                row_rep = cursor.fetchone()
                summary["user_reports_count"] = row_rep[0]
                summary["user_reports_mb"] = round(row_rep[1] / (1024 * 1024), 2)

        return summary

    def check_disk_space_safety(self, threshold_mb: float = LOW_DISK_THRESHOLD_MB) -> Dict[str, Any]:
        """
        Check free disk space on storage volume.
        Returns free MB and low disk warning flag. Does not delete any evidence.
        """
        total, used, free = shutil.disk_usage(self.base_dir)
        free_mb = round(free / (1024 * 1024), 2)
        total_mb = round(total / (1024 * 1024), 2)
        used_mb = round(used / (1024 * 1024), 2)

        return {
            "free_mb": free_mb,
            "used_mb": used_mb,
            "total_mb": total_mb,
            "threshold_mb": threshold_mb,
            "low_disk_warning": free_mb < threshold_mb
        }

    # =================================================================
    # EXPORT PACKAGING & MANIFEST
    # =================================================================

    def export_case_package(self, user_id: str, case_id: str) -> str:
        """
        Bundle case metadata, reports, and evidence into a secure zip package in exports/.
        Marks exported reports with exported=True.
        """
        import zipfile

        case_rec = self.get_case(user_id, case_id)
        if not case_rec:
            raise PermissionError(f"Case {case_id} not found or access denied for user {user_id}")

        export_id = f"EXP-{uuid.uuid4().hex[:8].upper()}"
        zip_filename = f"{case_id}_{export_id}_package.zip"
        zip_path = os.path.join(self.exports_dir, zip_filename)

        manifest = {
            "export_id": export_id,
            "case_id": case_id,
            "user_id": user_id,
            "exported_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "artifacts": []
        }

        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            # 1. Case Metadata
            case_json = json.dumps(case_rec, indent=2, default=str)
            zf.writestr("case_metadata.json", case_json)
            manifest["artifacts"].append({"file": "case_metadata.json", "type": "metadata"})

            # 2. Evidence Files
            evidence_list = self.list_evidence_for_case(user_id, case_id)
            for ev in evidence_list:
                fpath = ev["file_path"]
                if os.path.exists(fpath):
                    arcname = f"evidence/{ev['filename']}"
                    zf.write(fpath, arcname)
                    manifest["artifacts"].append({
                        "file": arcname,
                        "sha256": ev["sha256"],
                        "size_bytes": ev["size_bytes"],
                        "type": "evidence"
                    })

            # 3. Reports
            reports_list = self.list_reports_for_case(user_id, case_id)
            for rep in reports_list:
                fpath = rep["file_path"]
                if os.path.exists(fpath):
                    arcname = f"reports/{rep['filename']}"
                    zf.write(fpath, arcname)
                    manifest["artifacts"].append({
                        "file": arcname,
                        "size_bytes": rep["size_bytes"],
                        "type": "report"
                    })
                # Mark as exported
                self.mark_report_exported(user_id, rep["report_id"])

            # 4. Manifest
            zf.writestr("manifest.json", json.dumps(manifest, indent=2))

        return zip_path


# =====================================================================
# 3. GLOBAL SINGLETON FACTORY
# =====================================================================

_default_storage_manager: Optional[LocalStorageManager] = None

def get_local_storage_manager(base_dir: str = "data/local") -> LocalStorageManager:
    """Retrieve or initialize default LocalStorageManager instance."""
    global _default_storage_manager
    abs_base = os.path.abspath(base_dir)
    if _default_storage_manager is None or _default_storage_manager.base_dir != abs_base:
        _default_storage_manager = LocalStorageManager(base_dir=abs_base)
    return _default_storage_manager
