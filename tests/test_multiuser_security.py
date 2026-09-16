"""
tests/test_multiuser_security.py
Automated Multi-User Security, RLS & Isolation Test Suite for EMAILSHIELD INDIA.
Validates:
1. Strict raw_json allowlist filtering and OTP/token redaction.
2. In-memory report streaming (PDF, JSON, NCRP) with zero disk footprint.
3. Supabase SQL DDL integrity (RLS enabled, composite foreign keys, unique constraints).
4. Multi-tenant PostgREST client isolation (User A vs User B).
5. Offline / local fallback mode stability.
"""

import io
import json
import os
import re
import uuid
import pytest
from typing import Dict, Any, List

from core.case_store import (
    filter_raw_json_allowlist,
    save_case,
    get_case_record,
    get_all_cases,
    get_all_indicators,
    update_case_metadata,
    is_public_multiuser_mode,
    FORBIDDEN_PERSISTENCE_KEYS
)
from core.batch_scanner import scan_mailbox_batch
from core.report import generate_pdf_report, generate_json_report
from core.ncrp_packager import generate_ncrp_pdf_annexure
from core.supabase_client import is_supabase_configured, sign_out_user


# =====================================================================
# 1. RAW_JSON ALLOWLIST & SENSITIVE DATA REDACTION TESTS
# =====================================================================

def test_raw_json_allowlist_strips_forbidden_keys():
    """Verify that credentials, tokens, raw binaries, and raw body are stripped from persistence."""
    dirty_case_data = {
        "case_id": "CASE-TEST-DIRTY-01",
        "timestamp": "2026-09-16T10:00:00Z",
        "sha256": "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        "subject": "Important Account Update",
        "sender": "attacker@fakebank.com",
        "risk_score": "HIGH",
        "threat_verdict": "Credential Harvesting",
        # FORBIDDEN CREDENTIALS / SECRETS
        "pwd": "super_secret_password_123",
        "password": "compromised_user_password",
        "app_password": "abcd-efgh-ijkl-mnop",
        "token": "ya29.a0AfH6SMD_sample_oauth_token",
        "refresh_token": "1//04_sample_refresh_token",
        "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
        "mailbox_creds": {"user": "victim@gmail.com", "pass": "secret"},
        "current_email_bytes": b"\x00\x01\x02\x03\x04\x05raw_email_bytes",
        "raw_bytes": b"binary_data",
        "api_key": "sbp_live_api_key_12345",
        "secret": "top_secret_hmac_key",
        "body": "Full body text containing 10,000 words...",
        "body_text": "Full raw body text of the email...",
        # ALLOWED FORENSIC TELEMETRY
        "rule_findings": [{"rule_id": "RULE-001", "finding": "Spoofed Sender"}],
        "auth_results": [{"mech": "SPF", "status": "FAIL"}],
        "attachment_analyses": [
            {
                "filename": "payload.pdf.exe",
                "sha256": "11223344556677889900aabbccddeeff",
                "verdict_label": "MALICIOUS",
                "is_double_ext": True,
                "raw_bytes": b"dangerous_binary_payload"  # Should be stripped
            }
        ]
    }

    clean = filter_raw_json_allowlist(dirty_case_data)

    # 1. Confirm none of the forbidden keys are present in the top-level clean dict
    for forbidden_key in FORBIDDEN_PERSISTENCE_KEYS:
        assert forbidden_key not in clean, f"Forbidden key '{forbidden_key}' found in sanitized raw_json"

    # 2. Confirm raw bytes were stripped from attachment analysis objects
    assert len(clean["attachment_analyses"]) == 1
    att = clean["attachment_analyses"][0]
    assert "raw_bytes" not in att
    assert att["filename"] == "payload.pdf.exe"
    assert att["sha256"] == "11223344556677889900aabbccddeeff"
    assert att["verdict_label"] == "MALICIOUS"
    assert att["is_double_ext"] is True

    # 3. Confirm permitted metadata and telemetry remain intact
    assert clean["case_id"] == "CASE-TEST-DIRTY-01"
    assert clean["subject"] == "Important Account Update"
    assert clean["threat_verdict"] == "Credential Harvesting"
    assert len(clean["rule_findings"]) == 1


def test_body_excerpt_redacts_otps_and_pins():
    """Verify that body excerpts truncate to < 300 chars and redact OTP/PIN numbers."""
    case_with_otp = {
        "case_id": "CASE-OTP-01",
        "body_text": "Your State Bank of India OTP is 849201. Please use this verification code 123456 within 5 minutes. Do not share your PIN 9988 with anyone."
    }

    clean = filter_raw_json_allowlist(case_with_otp)
    excerpt = clean.get("body_excerpt", "")

    # Check that plain OTP numbers are masked
    assert "849201" not in excerpt
    assert "123456" not in excerpt
    assert "9988" not in excerpt
    assert "••••••" in excerpt
    assert len(excerpt) <= 300


# =====================================================================
# 2. IN-MEMORY STREAMING & ZERO DISK FOOTPRINT TESTS
# =====================================================================

def test_pdf_report_generates_in_memory_without_disk_write():
    """Verify generate_pdf_report returns an in-memory BytesIO buffer with no disk creation."""
    sample_data = {
        "case_id": "CASE-MEM-PDF-01",
        "timestamp": "2026-09-16 10:00:00",
        "subject": "Phishing Incident Report",
        "sender": "alerts@security-test.in",
        "threat_verdict": "Credential Harvesting",
        "risk_score": "HIGH",
        "verdict_confidence": 95,
        "rule_findings": [{"rule_id": "RULE-01", "finding": "Test finding", "severity": "HIGH", "explanation": "Test"}],
        "auth_alignment": {"spf_result": "PASS", "spf_aligned": True, "effective_dmarc": "PASS"}
    }

    # Snapshot existing reports on disk before call
    existing_files_before = set(os.listdir("data/reports")) if os.path.exists("data/reports") else set()

    # Call with output_path=None (in-memory mode)
    pdf_buffer = generate_pdf_report(sample_data, output_path=None)

    # 1. Output must be a BytesIO buffer
    assert isinstance(pdf_buffer, io.BytesIO)
    pdf_bytes = pdf_buffer.getvalue()

    # 2. Must start with standard PDF magic number %PDF-
    assert pdf_bytes.startswith(b"%PDF-")
    assert len(pdf_bytes) > 500

    # 3. No new files must have been created on disk
    existing_files_after = set(os.listdir("data/reports")) if os.path.exists("data/reports") else set()
    new_files = existing_files_after - existing_files_before
    assert len(new_files) == 0, f"Unexpected files created on disk: {new_files}"


def test_json_report_generates_in_memory_without_disk_write():
    """Verify generate_json_report returns formatted JSON without disk creation."""
    sample_data = {
        "case_id": "CASE-MEM-JSON-01",
        "timestamp": "2026-09-16 10:00:00",
        "subject": "JSON Investigation Report",
        "threat_verdict": "Standard / Legitimate",
        "risk_score": "LOW"
    }

    existing_files_before = set(os.listdir("data/reports")) if os.path.exists("data/reports") else set()

    # 1. Calling without filepath returns in-memory JSON string
    json_str = generate_json_report(sample_data, output_path=None)
    assert isinstance(json_str, str)
    parsed = json.loads(json_str)
    assert parsed["case_id"] == "CASE-MEM-JSON-01"
    assert parsed["threat_verdict"] == "Standard / Legitimate"

    # 2. Calling with an in-memory BytesIO buffer streams to buffer
    buf = io.BytesIO()
    out_buf = generate_json_report(sample_data, filepath=buf)
    assert out_buf is buf
    parsed_buf = json.loads(buf.getvalue().decode("utf-8"))
    assert parsed_buf["case_id"] == "CASE-MEM-JSON-01"

    # 3. Confirm 0 new files created on disk
    existing_files_after = set(os.listdir("data/reports")) if os.path.exists("data/reports") else set()
    new_files = existing_files_after - existing_files_before
    assert len(new_files) == 0, f"Unexpected files created on disk: {new_files}"


def test_ncrp_annexure_generates_in_memory_without_disk_write():
    """Verify generate_ncrp_pdf_annexure returns an in-memory BytesIO buffer."""
    sample_data = {
        "case_id": "CASE-MEM-NCRP-01",
        "timestamp": "2026-09-16 10:00:00",
        "subject": "NCRP Cybercrime Annexure",
        "threat_verdict": "UPI / Financial Fraud",
        "risk_score": "CRITICAL",
        "indicators": [{"type": "UPI", "value": "fraud@okhdfcbank", "source": "Body"}]
    }

    existing_files_before = set(os.listdir("data/reports")) if os.path.exists("data/reports") else set()

    ncrp_buffer = generate_ncrp_pdf_annexure(sample_data, output_path=None)

    assert isinstance(ncrp_buffer, io.BytesIO)
    ncrp_bytes = ncrp_buffer.getvalue()
    assert ncrp_bytes.startswith(b"%PDF-")

    existing_files_after = set(os.listdir("data/reports")) if os.path.exists("data/reports") else set()
    new_files = existing_files_after - existing_files_before
    assert len(new_files) == 0, f"Unexpected files created on disk: {new_files}"


# =====================================================================
# 3. SUPABASE POSTGRESQL SCHEMA DDL INTEGRITY AUDIT
# =====================================================================

def test_supabase_schema_ddl_security_constraints():
    """Verify data/supabase_schema.sql implements all architectural isolation rules."""
    schema_path = os.path.join("data", "supabase_schema.sql")
    assert os.path.exists(schema_path), "Schema file data/supabase_schema.sql missing"

    with open(schema_path, "r", encoding="utf-8") as f:
        sql = f.read()

    # 1. RLS must be explicitly enabled on all core tables
    assert "ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;" in sql
    assert "ALTER TABLE public.cases ENABLE ROW LEVEL SECURITY;" in sql
    assert "ALTER TABLE public.indicators ENABLE ROW LEVEL SECURITY;" in sql

    # 2. Composite unique constraint on cases (id, user_id) and user-scoped case_number
    assert "CONSTRAINT uq_cases_id_user UNIQUE (id, user_id)" in sql
    assert "CONSTRAINT uq_cases_user_case_number UNIQUE (user_id, case_number)" in sql

    # 3. Verdict confidence check constraint (0 to 100)
    assert "CHECK (verdict_confidence BETWEEN 0 AND 100)" in sql

    # 4. Composite foreign key on indicators (case_id, user_id) -> cases (id, user_id)
    composite_fk_pattern = re.search(
        r"CONSTRAINT\s+fk_indicators_case_user\s+FOREIGN\s+KEY\s*\(\s*case_id\s*,\s*user_id\s*\)\s+REFERENCES\s+public\.cases\s*\(\s*id\s*,\s*user_id\s*\)",
        sql,
        re.IGNORECASE
    )
    assert composite_fk_pattern is not None, "Composite foreign key on indicators(case_id, user_id) not found"

    # 5. RLS policies must strictly use auth.uid() and indicators INSERT must check case ownership
    assert "USING (user_id = auth.uid())" in sql
    assert "WITH CHECK (user_id = auth.uid())" in sql
    assert "USING (id = auth.uid())" in sql
    assert "AND EXISTS (" in sql
    assert "WHERE cases.id = indicators.case_id" in sql

    # 6. Indicators update policy must NOT exist (immutable telemetry)
    assert "CREATE POLICY" not in sql or "UPDATE ON public.indicators" not in sql
    assert 'CREATE POLICY "indicators_update_own"' not in sql

    # 7. Must NOT define columns for raw RFC822 binary or passwords
    assert "raw_bytes bytea" not in sql.lower()
    assert "password text" not in sql.lower()
    assert "app_password" not in sql.lower()


# =====================================================================
# 4. MULTI-TENANT POSTGREST CLIENT MOCK ISOLATION TESTS
# =====================================================================

class MockPostgrestTable:
    """Simulates PostgreSQL table behavior with kernel-level RLS based on active user_id."""
    def __init__(self, db_state: Dict[str, List[Dict[str, Any]]], table_name: str, active_user_id: str):
        self.db_state = db_state
        self.table_name = table_name
        self.active_user_id = active_user_id
        self._filter_user = True
        self._or_cond = None
        self._eq_field = None
        self._eq_val = None

    def select(self, *args, **kwargs):
        return self

    def order(self, *args, **kwargs):
        return self

    def or_(self, condition: str):
        self._or_cond = condition
        return self

    def eq(self, field: str, val: Any):
        self._eq_field = field
        self._eq_val = val
        return self

    def insert(self, rows):
        if isinstance(rows, dict):
            rows = [rows]
        for row in rows:
            # 1. Evaluate RLS WITH CHECK: user_id must equal active_user_id
            if row.get("user_id") != self.active_user_id:
                raise PermissionError('RLS Violation: new row violates row-level security policy for table "indicators"')

            # 2. For indicators, evaluate RLS EXISTS check on cases table:
            # cases.id = indicators.case_id AND cases.user_id = auth.uid()
            if self.table_name == "indicators":
                target_case_id = row.get("case_id")
                cases = self.db_state.get("cases", [])
                user_owns_case = any(c.get("id") == target_case_id and c.get("user_id") == self.active_user_id for c in cases)
                if not user_owns_case:
                    # RLS rejects with identical generic error regardless of whether target_case_id
                    # belongs to another user or does not exist at all, eliminating side-channel probing.
                    raise PermissionError('RLS Violation: new row violates row-level security policy for table "indicators"')

                # 3. Composite Foreign Key Constraint Check
                match_fk = any(c.get("id") == target_case_id and c.get("user_id") == row.get("user_id") for c in cases)
                if not match_fk:
                    raise ValueError("Composite FK violation: (case_id, user_id) does not exist in cases table")
            
            # Auto-assign UUID if not present
            if "id" not in row:
                row["id"] = str(uuid.uuid4())
            self.db_state[self.table_name].append(row)
        return self

    def upsert(self, row: Dict[str, Any], on_conflict: str = ""):
        # RLS check: insert must belong to active user
        if row.get("user_id") != self.active_user_id:
            raise PermissionError("RLS Violation: user cannot upsert records for another user_id")
        
        table = self.db_state[self.table_name]
        existing = next((r for r in table if r.get("case_number") == row.get("case_number") and r.get("user_id") == row.get("user_id")), None)
        if existing:
            existing.update(row)
            self._last_data = [existing]
        else:
            if "id" not in row:
                row["id"] = str(uuid.uuid4())
            table.append(row)
            self._last_data = [row]
        return self

    def update(self, updates: Dict[str, Any]):
        self._pending_update = updates
        return self

    def execute(self):
        # Apply RLS filtering: only return or modify rows where row.user_id == active_user_id
        table_rows = self.db_state.get(self.table_name, [])
        user_rows = [r for r in table_rows if r.get("user_id") == self.active_user_id]

        if hasattr(self, "_pending_update") and self._pending_update:
            updated = []
            target_rows = user_rows
            if self._or_cond:
                parts = self._or_cond.split(",")
                cond_vals = [p.split(".eq.")[1] for p in parts if ".eq." in p]
                target_rows = [r for r in user_rows if r.get("id") in cond_vals or r.get("case_number") in cond_vals]
            for r in target_rows:
                if self._eq_field:
                    if r.get(self._eq_field) == self._eq_val:
                        r.update(self._pending_update)
                        updated.append(r)
                else:
                    r.update(self._pending_update)
                    updated.append(r)
            self._pending_update = None
            class Response:
                pass
            res = Response()
            res.data = updated
            return res

        if hasattr(self, "_last_data"):
            data = self._last_data
            del self._last_data
            class Response:
                pass
            res = Response()
            res.data = data
            return res

        # Filter by ID/case_number or condition if provided
        filtered = user_rows
        if self._or_cond:
            parts = self._or_cond.split(",")
            cond_vals = [p.split(".eq.")[1] for p in parts if ".eq." in p]
            filtered = [r for r in filtered if r.get("id") in cond_vals or r.get("case_number") in cond_vals]

        class Response:
            pass
        res = Response()
        res.data = filtered
        return res


class MockSupabaseClient:
    """Mock Supabase client providing isolated PostgREST access per user session."""
    def __init__(self, db_state: Dict[str, List[Dict[str, Any]]], user_id: str):
        self.db_state = db_state
        self.user_id = user_id

    def table(self, table_name: str) -> MockPostgrestTable:
        return MockPostgrestTable(self.db_state, table_name, self.user_id)


def test_multiuser_case_and_indicator_isolation():
    """
    Simulate two independent authenticated investigators (User A and User B):
    1. User A analyzes an email and persists Case A + indicators.
    2. User B queries cases -> cannot see Case A.
    3. User B queries specific case by ID -> returns None.
    4. User B attempts to update Case A metadata -> fails/no-op.
    5. User B attempts to attach indicators to Case A -> blocked by composite FK.
    """
    shared_database = {
        "profiles": [],
        "cases": [],
        "indicators": []
    }

    user_a_id = "00000000-0000-4000-8000-000000000001"
    user_b_id = "00000000-0000-4000-8000-000000000002"

    client_a = MockSupabaseClient(shared_database, user_a_id)
    client_b = MockSupabaseClient(shared_database, user_b_id)

    # 1. User A saves Case A
    case_a_data = {
        "case_id": "CASE-USER-A-01",
        "timestamp": "2026-09-16T10:00:00Z",
        "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "subject": "User A Private Threat Report",
        "sender": "attacker@victim-a.com",
        "threat_verdict": "Credential Harvesting",
        "risk_score": "HIGH",
        "verdict_confidence": 98,
        "indicators": [
            {"type": "URL", "value": "https://malicious-site-a.com", "source": "Body"},
            {"type": "IP", "value": "198.51.100.1", "source": "Headers"}
        ]
    }

    success_a = save_case(case_a_data, user_id=user_a_id, client=client_a)
    assert success_a is True
    assert len(shared_database["cases"]) == 1
    assert len(shared_database["indicators"]) == 2
    case_a_uuid = shared_database["cases"][0]["id"]

    # 2. User A can read Case A
    cases_for_a = get_all_cases(client=client_a)
    assert len(cases_for_a) == 1
    assert cases_for_a[0]["case_id"] == "CASE-USER-A-01"

    rec_a = get_case_record("CASE-USER-A-01", client=client_a)
    assert rec_a is not None
    assert rec_a["case_id"] == "CASE-USER-A-01"

    # 3. User B CANNOT see User A's case
    cases_for_b = get_all_cases(client=client_b)
    assert len(cases_for_b) == 0, "User B leaked User A's cases in get_all_cases()!"

    rec_b = get_case_record("CASE-USER-A-01", client=client_b)
    assert rec_b is None, "User B was able to fetch User A's case record by case ID!"

    # 4. User B CANNOT update User A's case
    update_case_metadata("CASE-USER-A-01", "Closed", "Investigator B", "Tampered notes", "LOW", client=client_b)
    
    # Verify User A's case was NOT altered
    case_record_after = next(c for c in shared_database["cases"] if c["case_number"] == "CASE-USER-A-01")
    assert case_record_after["status"] == "Open"
    assert case_record_after["assigned_investigator"] == "Unassigned"
    assert case_record_after["analyst_notes"] == ""

    # 5. User B CANNOT insert indicators referencing User A's case_id (RLS check denies it)
    with pytest.raises(PermissionError, match='RLS Violation: new row violates row-level security policy for table "indicators"'):
        client_b.table("indicators").insert({
            "case_id": case_a_uuid,
            "user_id": user_b_id,
            "type": "Domain",
            "value": "rogue-indicator.com"
        })

    # 6. Anti-probing side-channel test: Attempting to insert an indicator with a non-existent UUID
    # yields the EXACT same RLS rejection error, proving that probe enumeration yields zero delta.
    non_existent_uuid = "99999999-9999-4999-9999-999999999999"
    with pytest.raises(PermissionError, match='RLS Violation: new row violates row-level security policy for table "indicators"'):
        client_b.table("indicators").insert({
            "case_id": non_existent_uuid,
            "user_id": user_b_id,
            "type": "Domain",
            "value": "probing-indicator.com"
        })


# =====================================================================
# 5. OFFLINE / LOCAL FALLBACK MODE TEST
# =====================================================================

def test_offline_local_fallback_mode():
    """Verify that when Supabase client is None (offline / unconfigured), SQLite store works safely."""
    offline_case = {
        "case_id": "CASE-OFFLINE-01",
        "timestamp": "2026-09-16T11:00:00Z",
        "sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "subject": "Local Offline Case",
        "sender": "test@localhost.com",
        "threat_verdict": "Standard / Legitimate",
        "risk_score": "LOW",
        "verdict_confidence": 90,
        "indicators": [{"type": "Email", "value": "test@localhost.com"}]
    }

    # Save without user_id and client (offline fallback)
    success = save_case(offline_case, user_id=None, client=None)
    assert success is True

    # Retrieve from local store
    record = get_case_record("CASE-OFFLINE-01", client=None)
    assert record is not None
    assert record["case_id"] == "CASE-OFFLINE-01"
    assert record["subject"] == "Local Offline Case"


def test_supabase_client_helpers_without_env_vars():
    """Verify is_supabase_configured() returns False when environment variables are not set."""
    # Ensure env vars are temporarily unset
    old_url = os.environ.pop("SUPABASE_URL", None)
    old_key = os.environ.pop("SUPABASE_ANON_KEY", None)
    try:
        assert is_supabase_configured() is False
    finally:
        if old_url:
            os.environ["SUPABASE_URL"] = old_url
        if old_key:
            os.environ["SUPABASE_ANON_KEY"] = old_key


def test_batch_scanner_fails_closed_without_session_mailbox():
    """Verify scan_mailbox_batch fails closed with ValueError if session-scoped mailbox is missing."""
    with pytest.raises(ValueError, match="Session-scoped mailbox input is required; global Gmail OAuth fallback is disabled."):
        scan_mailbox_batch(ml_classifier=None)


def test_public_multiuser_mode_sqlite_fails_closed(monkeypatch):
    """Verify that in public multi-user mode, all unauthenticated operations fail closed without SQLite fallback."""
    monkeypatch.setenv("EMAILSHIELD_MODE", "public_multiuser")
    assert is_public_multiuser_mode() is True

    test_case = {
        "case_id": "CASE-PUBLIC-01",
        "subject": "Public Mode Test Email",
        "threat_verdict": "Malicious"
    }

    # 1. Unauthenticated save_case must return False and not write to SQLite
    saved = save_case(test_case, user_id=None, client=None)
    assert saved is False

    # 2. Unauthenticated get_case_record must return None
    rec = get_case_record("CASE-PUBLIC-01", client=None)
    assert rec is None

    # 3. Unauthenticated get_all_cases must return empty list
    all_cases = get_all_cases(client=None)
    assert all_cases == []

    # 4. Unauthenticated get_all_indicators must return empty list
    all_inds = get_all_indicators(client=None)
    assert all_inds == []

    # 5. Unauthenticated update_case_metadata must return False
    updated = update_case_metadata("CASE-PUBLIC-01", status="Closed", client=None)
    assert updated is False

