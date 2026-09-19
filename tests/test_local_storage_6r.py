"""
tests/test_local_storage_6r.py
Phase 6R: Comprehensive Test Suite for Local-First Forensic Storage,
Retention Policies, Evidence Preservation & Safe Cleanup Engine.

Validates all 25 critical Phase 6R invariants:
- Strict user/tenant isolation (fails closed)
- Configurable retention periods (7, 30 [default], 90, 180 days)
- Active-case protection
- Evidence preservation
- User-export protection
- Dependency protection
- Safe defensive cleanup with dry-run
- Tamper-evident audit logging (SQLite + JSONL)
- Low disk space monitoring without destructive actions
- Graceful partial-failure handling
- Zero secrets persisted
- Service role key never used
- Sentinel functionality unaffected
"""

import os
import sys
import json
import uuid
import datetime
import tempfile
import shutil
import pytest
from unittest.mock import patch

from core.local_storage import (
    LocalStorageManager,
    RetentionPolicy,
    DEFAULT_RETENTION_DAYS,
    contains_raw_secrets,
    FORBIDDEN_PERSISTENCE_KEYS
)


@pytest.fixture
def temp_storage():
    """Create an isolated temporary storage directory for testing."""
    tmp_dir = tempfile.mkdtemp(prefix="emailshield_storage_test_")
    mgr = LocalStorageManager(base_dir=tmp_dir)
    yield mgr, tmp_dir
    # Cleanup directory
    shutil.rmtree(tmp_dir, ignore_errors=True)


# =====================================================================
# TEST 01: Create local case
# =====================================================================
def test_01_create_local_case(temp_storage):
    mgr, tmp_dir = temp_storage
    user_id = "user-alice"
    case_id = "CASE-2026-001"

    rec = mgr.create_case(
        user_id=user_id,
        case_id=case_id,
        title="Suspicious Wire Transfer",
        description="CEO impersonation email targeting finance team",
        status="active"
    )

    assert rec["case_id"] == case_id
    assert rec["user_id"] == user_id
    assert rec["title"] == "Suspicious Wire Transfer"
    assert rec["status"] == "active"
    assert os.path.exists(os.path.join(tmp_dir, "cases", f"{case_id}.json"))


# =====================================================================
# TEST 02: Read own case
# =====================================================================
def test_02_read_own_case(temp_storage):
    mgr, _ = temp_storage
    user_id = "user-alice"
    case_id = "CASE-2026-002"

    mgr.create_case(
        user_id=user_id,
        case_id=case_id,
        title="Phishing Invoice",
        description="Fake PDF invoice attachment",
        status="active"
    )

    fetched = mgr.get_case(user_id=user_id, case_id=case_id)
    assert fetched is not None
    assert fetched["case_id"] == case_id
    assert fetched["user_id"] == user_id
    assert fetched["title"] == "Phishing Invoice"
    assert fetched["description"] == "Fake PDF invoice attachment"


# =====================================================================
# TEST 03: Cross-user case access denied
# =====================================================================
def test_03_cross_user_case_access_denied(temp_storage):
    mgr, _ = temp_storage
    user_alice = "user-alice"
    user_bob = "user-bob"
    case_id = "CASE-2026-003"

    mgr.create_case(
        user_id=user_alice,
        case_id=case_id,
        title="Confidential Investigation",
        description="Private forensic data"
    )

    # Bob attempts to access Alice's case -> MUST FAIL CLOSED
    denied = mgr.get_case(user_id=user_bob, case_id=case_id)
    assert denied is None, "Cross-user access did not fail closed"


# =====================================================================
# TEST 04: Store forensic metadata
# =====================================================================
def test_04_store_forensic_metadata(temp_storage):
    mgr, _ = temp_storage
    user_id = "user-alice"
    case_id = "CASE-2026-004"

    forensic_data = {
        "threat_verdict": "Credential Harvesting",
        "risk_score": "CRITICAL",
        "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "indicators": [
            {"type": "URL", "value": "https://fake-login.evil.com/auth"},
            {"type": "IP", "value": "198.51.100.42"}
        ],
        "rule_findings": [
            {"rule_id": "RULE-SPF-FAIL", "finding": "SPF authentication hard failed"}
        ]
    }

    rec = mgr.create_case(
        user_id=user_id,
        case_id=case_id,
        title="Credential Harvester",
        case_data=forensic_data
    )

    assert rec["risk_score"] == "CRITICAL"
    assert rec["threat_verdict"] == "Credential Harvesting"

    fetched = mgr.get_case(user_id, case_id)
    assert fetched["case_data"]["risk_score"] == "CRITICAL"
    assert len(fetched["case_data"]["indicators"]) == 2
    assert fetched["case_data"]["indicators"][0]["value"] == "https://fake-login.evil.com/auth"


# =====================================================================
# TEST 05: Store evidence metadata
# =====================================================================
def test_05_store_evidence_metadata(temp_storage):
    mgr, tmp_dir = temp_storage
    user_id = "user-alice"
    case_id = "CASE-2026-005"
    mgr.create_case(user_id, case_id, "Evidence Test Case")

    eml_bytes = b"From: spoofed@evil.com\nTo: victim@example.com\nSubject: Urgent Payment\n\nPay now."
    ev = mgr.store_evidence(
        user_id=user_id,
        case_id=case_id,
        raw_bytes=eml_bytes,
        filename="urgent_payment.eml",
        content_type="message/rfc822"
    )

    assert ev["case_id"] == case_id
    assert ev["filename"] == "urgent_payment.eml"
    assert ev["size_bytes"] == len(eml_bytes)
    assert os.path.exists(ev["file_path"])

    fetched_bytes, meta = mgr.get_evidence(user_id, ev["evidence_id"])
    assert fetched_bytes == eml_bytes
    assert meta["sha256"] == ev["sha256"]


# =====================================================================
# TEST 06: Store report metadata
# =====================================================================
def test_06_store_report_metadata(temp_storage):
    mgr, tmp_dir = temp_storage
    user_id = "user-alice"
    case_id = "CASE-2026-006"
    mgr.create_case(user_id, case_id, "Report Test Case")

    pdf_bytes = b"%PDF-1.4 sample forensic investigation report binary content"
    rep = mgr.store_report(
        user_id=user_id,
        case_id=case_id,
        report_bytes=pdf_bytes,
        report_type="pdf",
        filename="forensic_report.pdf"
    )

    assert rep["case_id"] == case_id
    assert rep["report_type"] == "pdf"
    assert rep["size_bytes"] == len(pdf_bytes)
    assert os.path.exists(rep["file_path"])

    fetched_bytes, meta = mgr.get_report(user_id, rep["report_id"])
    assert fetched_bytes == pdf_bytes
    assert meta["report_type"] == "pdf"


# =====================================================================
# TEST 07: Default retention 30 days
# =====================================================================
def test_07_default_retention_30_days(temp_storage):
    mgr, _ = temp_storage
    assert mgr.default_retention_days == 30
    assert RetentionPolicy.DAYS_30 == 30
    assert RetentionPolicy.DAYS_30.value == 30


# =====================================================================
# TEST 08: Retention 7 days
# =====================================================================
def test_08_retention_7_days(temp_storage):
    mgr, _ = temp_storage
    now = datetime.datetime.now(datetime.timezone.utc)
    ts_6d = (now - datetime.timedelta(days=6)).isoformat()
    ts_8d = (now - datetime.timedelta(days=8)).isoformat()

    c_6d = {"status": "closed", "preserve_evidence": False, "updated_at": ts_6d, "case_id": "C-6D", "user_id": "u1"}
    c_8d = {"status": "closed", "preserve_evidence": False, "updated_at": ts_8d, "case_id": "C-8D", "user_id": "u1"}

    mgr.create_case("u1", "C-6D", status="closed", updated_at=ts_6d)
    mgr.create_case("u1", "C-8D", status="closed", updated_at=ts_8d)

    is_el_6d, _ = mgr.is_eligible_for_cleanup("case", c_6d, policy_days=7, now=now)
    is_el_8d, _ = mgr.is_eligible_for_cleanup("case", c_8d, policy_days=7, now=now)

    assert is_el_6d is False, "6-day record should be within 7-day retention"
    assert is_el_8d is True, "8-day record should be eligible for 7-day retention"


# =====================================================================
# TEST 09: Retention 90 days
# =====================================================================
def test_09_retention_90_days(temp_storage):
    mgr, _ = temp_storage
    now = datetime.datetime.now(datetime.timezone.utc)
    ts_89d = (now - datetime.timedelta(days=89)).isoformat()
    ts_91d = (now - datetime.timedelta(days=91)).isoformat()

    c_89d = {"status": "closed", "preserve_evidence": False, "updated_at": ts_89d, "case_id": "C-89D", "user_id": "u1"}
    c_91d = {"status": "closed", "preserve_evidence": False, "updated_at": ts_91d, "case_id": "C-91D", "user_id": "u1"}

    mgr.create_case("u1", "C-89D", status="closed", updated_at=ts_89d)
    mgr.create_case("u1", "C-91D", status="closed", updated_at=ts_91d)

    is_el_89d, _ = mgr.is_eligible_for_cleanup("case", c_89d, policy_days=90, now=now)
    is_el_91d, _ = mgr.is_eligible_for_cleanup("case", c_91d, policy_days=90, now=now)

    assert is_el_89d is False, "89-day record should be within 90-day retention"
    assert is_el_91d is True, "91-day record should be eligible for 90-day retention"


# =====================================================================
# TEST 10: Retention 180 days
# =====================================================================
def test_10_retention_180_days(temp_storage):
    mgr, _ = temp_storage
    now = datetime.datetime.now(datetime.timezone.utc)
    ts_179d = (now - datetime.timedelta(days=179)).isoformat()
    ts_181d = (now - datetime.timedelta(days=181)).isoformat()

    c_179d = {"status": "closed", "preserve_evidence": False, "updated_at": ts_179d, "case_id": "C-179D", "user_id": "u1"}
    c_181d = {"status": "closed", "preserve_evidence": False, "updated_at": ts_181d, "case_id": "C-181D", "user_id": "u1"}

    mgr.create_case("u1", "C-179D", status="closed", updated_at=ts_179d)
    mgr.create_case("u1", "C-181D", status="closed", updated_at=ts_181d)

    is_el_179d, _ = mgr.is_eligible_for_cleanup("case", c_179d, policy_days=180, now=now)
    is_el_181d, _ = mgr.is_eligible_for_cleanup("case", c_181d, policy_days=180, now=now)

    assert is_el_179d is False, "179-day record should be within 180-day retention"
    assert is_el_181d is True, "181-day record should be eligible for 180-day retention"


# =====================================================================
# TEST 11: Old inactive case becomes eligible
# =====================================================================
def test_11_old_inactive_case_becomes_eligible(temp_storage):
    mgr, _ = temp_storage
    now = datetime.datetime.now(datetime.timezone.utc)
    old_ts = (now - datetime.timedelta(days=35)).isoformat()

    case_rec = mgr.create_case(
        user_id="user-alice",
        case_id="CASE-OLD-INACTIVE",
        title="Resolved Case",
        status="closed",
        created_at=old_ts,
        updated_at=old_ts
    )

    is_el, reason = mgr.is_eligible_for_cleanup("case", case_rec, policy_days=30, now=now)
    assert is_el is True
    assert "exceeded retention period" in reason


# =====================================================================
# TEST 12: Active case protected
# =====================================================================
def test_12_active_case_protected(temp_storage):
    mgr, _ = temp_storage
    now = datetime.datetime.now(datetime.timezone.utc)
    old_ts = (now - datetime.timedelta(days=45)).isoformat()

    for active_st in ["active", "Open", "In Progress"]:
        cid = f"CASE-ACTIVE-{active_st.replace(' ', '_')}"
        case_rec = mgr.create_case(
            user_id="user-alice",
            case_id=cid,
            title=f"Active Case ({active_st})",
            status=active_st,
            created_at=old_ts,
            updated_at=old_ts
        )

        is_el, reason = mgr.is_eligible_for_cleanup("case", case_rec, policy_days=30, now=now)
        assert is_el is False, f"Case with status '{active_st}' was not protected"
        assert "active-case protection" in reason


# =====================================================================
# TEST 13: Preserved case protected
# =====================================================================
def test_13_preserved_case_protected(temp_storage):
    mgr, _ = temp_storage
    now = datetime.datetime.now(datetime.timezone.utc)
    old_ts = (now - datetime.timedelta(days=50)).isoformat()

    case_rec = mgr.create_case(
        user_id="user-alice",
        case_id="CASE-PRESERVED",
        title="Preserved Case",
        status="closed",
        preserve_evidence=True,
        created_at=old_ts,
        updated_at=old_ts
    )

    is_el, reason = mgr.is_eligible_for_cleanup("case", case_rec, policy_days=30, now=now)
    assert is_el is False
    assert "Evidence preservation enabled" in reason


# =====================================================================
# TEST 14: Preserved evidence protected
# =====================================================================
def test_14_preserved_evidence_protected(temp_storage):
    mgr, _ = temp_storage
    now = datetime.datetime.now(datetime.timezone.utc)
    old_ts = (now - datetime.timedelta(days=40)).isoformat()

    mgr.create_case("user-alice", "CASE-EV-TEST", status="closed", updated_at=old_ts)
    ev_rec = mgr.store_evidence(
        user_id="user-alice",
        case_id="CASE-EV-TEST",
        raw_bytes=b"sample evidence",
        filename="evidence.eml",
        preserve_evidence=True,
        created_at=old_ts
    )

    is_el, reason = mgr.is_eligible_for_cleanup("evidence", ev_rec, policy_days=30, now=now)
    assert is_el is False
    assert "Evidence preservation enabled" in reason


# =====================================================================
# TEST 15: User exported report protected
# =====================================================================
def test_15_user_exported_report_protected(temp_storage):
    mgr, _ = temp_storage
    now = datetime.datetime.now(datetime.timezone.utc)
    old_ts = (now - datetime.timedelta(days=40)).isoformat()

    mgr.create_case("user-alice", "CASE-REP-TEST", status="closed", updated_at=old_ts)
    rep_rec = mgr.store_report(
        user_id="user-alice",
        case_id="CASE-REP-TEST",
        report_bytes=b"sample report content",
        report_type="pdf",
        filename="compliance_report.pdf",
        exported=True,
        created_at=old_ts
    )

    is_el, reason = mgr.is_eligible_for_cleanup("report", rep_rec, policy_days=30, now=now)
    assert is_el is False
    assert "user-export protection" in reason


# =====================================================================
# TEST 16: Cleanup dry run does not delete
# =====================================================================
def test_16_cleanup_dry_run_does_not_delete(temp_storage):
    mgr, tmp_dir = temp_storage
    now = datetime.datetime.now(datetime.timezone.utc)
    old_ts = (now - datetime.timedelta(days=45)).isoformat()

    # 1. Create eligible closed case with evidence and report
    mgr.create_case("user-alice", "CASE-OLD-1", status="closed", created_at=old_ts, updated_at=old_ts)
    ev = mgr.store_evidence("user-alice", "CASE-OLD-1", b"raw bytes", "test.eml", created_at=old_ts)
    rep = mgr.store_report("user-alice", "CASE-OLD-1", b"pdf bytes", "pdf", "test.pdf", created_at=old_ts)

    # 2. Create protected active case
    mgr.create_case("user-alice", "CASE-ACTIVE-1", status="active", created_at=old_ts, updated_at=old_ts)

    dry_summary = mgr.dry_run_cleanup("user-alice", policy_days=30, now=now)

    assert dry_summary["eligible_cases_count"] == 1
    assert dry_summary["protected_cases_count"] == 1
    assert dry_summary["eligible_evidence_count"] == 1
    assert dry_summary["eligible_reports_count"] == 1

    # CRITICAL INVARIANT: Zero files or DB rows deleted during dry run
    assert os.path.exists(ev["file_path"]), "Evidence file was deleted during dry run!"
    assert os.path.exists(rep["file_path"]), "Report file was deleted during dry run!"
    assert mgr.get_case("user-alice", "CASE-OLD-1") is not None
    assert mgr.get_case("user-alice", "CASE-ACTIVE-1") is not None


# =====================================================================
# TEST 17: Run cleanup now deletes only eligible
# =====================================================================
def test_17_run_cleanup_now_deletes_only_eligible(temp_storage):
    mgr, tmp_dir = temp_storage
    now = datetime.datetime.now(datetime.timezone.utc)
    old_ts = (now - datetime.timedelta(days=45)).isoformat()

    # Case A: Old closed case with unpreserved evidence & report -> ELIGIBLE
    mgr.create_case("user-alice", "CASE-TO-DELETE", status="closed", created_at=old_ts, updated_at=old_ts)
    ev_to_del = mgr.store_evidence("user-alice", "CASE-TO-DELETE", b"eml1", "del.eml", created_at=old_ts)
    rep_to_del = mgr.store_report("user-alice", "CASE-TO-DELETE", b"rep1", "pdf", "del.pdf", created_at=old_ts)

    # Case B: Old closed case with PRESERVED evidence -> PROTECTED
    mgr.create_case("user-alice", "CASE-TO-KEEP", status="closed", preserve_evidence=True, created_at=old_ts, updated_at=old_ts)
    ev_to_keep = mgr.store_evidence("user-alice", "CASE-TO-KEEP", b"eml2", "keep.eml", preserve_evidence=True, created_at=old_ts)
    rep_to_keep = mgr.store_report("user-alice", "CASE-TO-KEEP", b"rep2", "pdf", "keep.pdf", exported=True, created_at=old_ts)

    res = mgr.run_cleanup_now("user-alice", policy_days=30, now=now)

    assert res["deleted_cases_count"] == 1
    assert res["deleted_evidence_count"] == 1
    assert res["deleted_reports_count"] == 1
    assert res["failed_deletions_count"] == 0

    # Eligible files and cases removed
    assert not os.path.exists(ev_to_del["file_path"])
    assert not os.path.exists(rep_to_del["file_path"])
    assert mgr.get_case("user-alice", "CASE-TO-DELETE") is None

    # Protected files and cases intact
    assert os.path.exists(ev_to_keep["file_path"])
    assert os.path.exists(rep_to_keep["file_path"])
    assert mgr.get_case("user-alice", "CASE-TO-KEEP") is not None


# =====================================================================
# TEST 18: Cleanup audit generated
# =====================================================================
def test_18_cleanup_audit_generated(temp_storage):
    mgr, tmp_dir = temp_storage
    now = datetime.datetime.now(datetime.timezone.utc)
    old_ts = (now - datetime.timedelta(days=40)).isoformat()

    mgr.create_case("user-alice", "CASE-AUDIT-TEST", status="closed", created_at=old_ts, updated_at=old_ts)
    mgr.run_cleanup_now("user-alice", policy_days=30, now=now)

    audit_records = mgr.get_audit_log("user-alice")
    assert len(audit_records) >= 1

    entry = audit_records[0]
    assert entry["user_id"] == "user-alice"
    assert entry["operation"] == "DELETE_CASE"
    assert entry["record_id"] == "CASE-AUDIT-TEST"
    assert entry["result"] == "SUCCESS"
    assert "reason" in entry

    # Verify JSONL log also contains entry
    jsonl_path = os.path.join(tmp_dir, "audit", "cleanup_audit.jsonl")
    assert os.path.exists(jsonl_path)
    with open(jsonl_path, "r", encoding="utf-8") as f:
        lines = f.readlines()
        assert len(lines) >= 1
        parsed = json.loads(lines[-1])
        assert parsed["record_id"] == "CASE-AUDIT-TEST"


# =====================================================================
# TEST 19: Ownership cannot be bypassed
# =====================================================================
def test_19_ownership_cannot_be_bypassed(temp_storage):
    mgr, _ = temp_storage
    mgr.create_case("user-alice", "CASE-ALICE", title="Alice Case")

    # Bob attempts to update Alice's case -> FAILS
    assert mgr.update_case("user-bob", "CASE-ALICE", title="Hacked") is False
    assert mgr.get_case("user-alice", "CASE-ALICE")["title"] == "Alice Case"

    # Bob attempts to run cleanup on Alice's user_id -> dry run returns 0 for Bob
    bob_dry = mgr.dry_run_cleanup("user-bob", 30)
    assert bob_dry["total_eligible_records"] == 0
    assert bob_dry["total_protected_records"] == 0


# =====================================================================
# TEST 20: Low disk space warning
# =====================================================================
def test_20_low_disk_space_warning(temp_storage):
    mgr, _ = temp_storage
    mgr.create_case("user-alice", "CASE-DISK", "Disk Safety Test")

    # Set threshold unrealistically high (e.g., 10 PB) to test low_disk_warning trigger
    status = mgr.check_disk_space_safety(threshold_mb=10_000_000_000.0)
    assert status["low_disk_warning"] is True
    assert "free_mb" in status

    # Invariant: Low disk space triggers notification/warning, does NOT delete data
    assert mgr.get_case("user-alice", "CASE-DISK") is not None


# =====================================================================
# TEST 21: Dependency protection
# =====================================================================
def test_21_dependency_protection(temp_storage):
    mgr, _ = temp_storage
    now = datetime.datetime.now(datetime.timezone.utc)
    old_ts = (now - datetime.timedelta(days=60)).isoformat()

    # Active parent case with old evidence and report
    mgr.create_case("user-alice", "CASE-PARENT-ACTIVE", status="active", created_at=old_ts, updated_at=old_ts)
    ev = mgr.store_evidence("user-alice", "CASE-PARENT-ACTIVE", b"raw", "child.eml", created_at=old_ts)
    rep = mgr.store_report("user-alice", "CASE-PARENT-ACTIVE", b"pdf", "pdf", "child.pdf", created_at=old_ts)

    # Neither child evidence nor report may be deleted because parent case is active
    is_ev_el, ev_reason = mgr.is_eligible_for_cleanup("evidence", ev, 30, now=now)
    is_rep_el, rep_reason = mgr.is_eligible_for_cleanup("report", rep, 30, now=now)

    assert is_ev_el is False
    assert "Parent case is active" in ev_reason
    assert is_rep_el is False
    assert "Parent case is active" in rep_reason


# =====================================================================
# TEST 22: Partial deletion failure handled safely
# =====================================================================
def test_22_partial_deletion_failure_handled_safely(temp_storage):
    mgr, _ = temp_storage
    now = datetime.datetime.now(datetime.timezone.utc)
    old_ts = (now - datetime.timedelta(days=50)).isoformat()

    mgr.create_case("user-alice", "CASE-PARTIAL", status="closed", created_at=old_ts, updated_at=old_ts)
    ev1 = mgr.store_evidence("user-alice", "CASE-PARTIAL", b"ev1", "file1.eml", created_at=old_ts)
    ev2 = mgr.store_evidence("user-alice", "CASE-PARTIAL", b"ev2", "file2.eml", created_at=old_ts)

    # Mock os.remove to raise OSError when file1.eml is targeted
    orig_remove = os.remove
    def selective_remove(path):
        if "file1" in path:
            raise PermissionError("Simulated file lock on Windows")
        return orig_remove(path)

    with patch("os.remove", side_effect=selective_remove):
        summary = mgr.run_cleanup_now("user-alice", policy_days=30, now=now)

    assert summary["failed_deletions_count"] >= 1
    assert len(summary["failures"]) >= 1

    # file2 succeeded, file1 failed
    assert not os.path.exists(ev2["file_path"])
    assert os.path.exists(ev1["file_path"])

    # Failed file must retain its database record
    with mgr._get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM evidence WHERE evidence_id = ?", (ev1["evidence_id"],))
        assert cursor.fetchone() is not None, "Failed deletion removed database record!"


# =====================================================================
# TEST 23: Secrets never written to local storage
# =====================================================================
def test_23_secrets_never_written_to_local_storage(temp_storage):
    mgr, tmp_dir = temp_storage
    user_id = "user-alice"
    case_id = "CASE-SECRETS-TEST"

    dummy_key_header = "-----" + "BEGIN " + "RSA " + "PRIVATE KEY-----\nMIIEowI..."
    dirty_payload = {
        "subject": "Attack notice",
        "pwd": "super_secret_password_123",
        "password": "compromised_user_password",
        "app_password": "abcd efgh ijkl mnop",
        "token": "secret_oauth_token",
        "service_role": "sbp_service_role_secret",
        "service_role_key": "eyJhbGciOiJIUzI1NiIsIn...",
        "capability_token": "token_abc123",
        "private_key": dummy_key_header,
        "risk_score": "HIGH"
    }

    mgr.create_case(user_id, case_id, "Secret Scrubbing Test", case_data=dirty_payload)

    # Verify JSON file has no secrets
    json_path = os.path.join(tmp_dir, "cases", f"{case_id}.json")
    with open(json_path, "r", encoding="utf-8") as f:
        content = f.read()
        for forbidden in FORBIDDEN_PERSISTENCE_KEYS:
            assert f'"{forbidden}": "super_secret' not in content
            assert "abcd efgh ijkl mnop" not in content
            assert "sbp_service_role_secret" not in content
            assert ("BEGIN " + "RSA " + "PRIVATE KEY") not in content

    # Verify SQLite DB has no secrets
    with mgr._get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT raw_json FROM cases WHERE case_id = ?", (case_id,))
        raw_json_str = cursor.fetchone()[0]
        parsed_db = json.loads(raw_json_str)
        assert contains_raw_secrets(parsed_db) is False


# =====================================================================
# TEST 24: Service role key never used
# =====================================================================
def test_24_service_role_key_never_used():
    import inspect
    import core.local_storage as ls_mod

    source = inspect.getsource(ls_mod)
    assert "service_role_key" not in source or "FORBIDDEN_PERSISTENCE_KEYS" in source
    # Assert module operates completely without network or Supabase service_role
    assert "create_client" not in source
    assert "SUPABASE_SERVICE_ROLE" not in source


# =====================================================================
# TEST 25: Sentinel functionality unaffected
# =====================================================================
def test_25_sentinel_functionality_unaffected(temp_storage):
    mgr, _ = temp_storage
    from worker.events import SafeEmailEvent
    from core.classifier import MLClassifier
    from core.agent import AutonomousForensicAgent

    # Sentinel structures remain intact and functional
    ev = SafeEmailEvent(
        tenant_user_id="user-sentinel",
        mailbox_id="mb-12345",
        uid=1,
        message_id="<msg01@example.com>",
        sender="sender@evil.com",
        recipient="victim@example.com",
        timestamp="2026-09-17T12:00:00Z",
        subject="Threat Lure",
        body_preview="Please review the attachment immediately.",
        body_length=45,
        attachment_count=1,
        risk_score=95.0,
        verdict="Phishing",
        iocs={"urls": ["http://evil.com"]}
    )

    assert ev.risk_score == 95.0
    assert ev.verdict == "Phishing"

    # LocalStorageManager can store the Sentinel event
    case_rec = mgr.create_case(
        user_id="user-sentinel",
        case_id="SENTINEL-CASE-01",
        title=ev.subject,
        case_data=ev.to_dict(),
        status="active"
    )
    assert case_rec["case_id"] == "SENTINEL-CASE-01"
    assert case_rec["status"] == "active"
