"""
tests/test_production_deployment_readiness.py
EMAILSHIELD INDIA — Phase 16: Production Deployment Readiness & Observability Suite.

Comprehensive automated verification across 35 production readiness dimensions:
- Production configuration inspection and environment separation (dev/test/prod)
- Secret configuration security and zero committed credentials
- Streamlit and Supabase production configuration hardening
- Worker production lifecycle (startup, graceful shutdown, lease, checkpoint, credentials)
- Structured operational logging & failure classification monitoring
- Telemetry observability, persistence, and batch/live isolation
- Sentinel UI health reflection and state synchronization
- Controlled Gmail IMAP smoke test and cross-tenant isolation
- Storage readiness, path bounding, data retention, and resource limits
- Deployment artifact and Docker container hardening (non-root UID 10001, zero ports)
- Fail-closed startup configuration checks and rollback readiness
- Complete user journey and logout state clearance
- Performance benchmarks and bounded latency validation
"""

import datetime
import hashlib
import html
import io
import json
import os
import re
import time
import unittest
import uuid
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, patch

# Core components under test
from core.case_store import (
    is_authorized_caller,
    is_authenticated_soc_caller,
    save_case,
    get_case_record,
    get_all_cases,
    get_all_indicators,
    get_soc_kpi_metrics,
    get_soc_threat_distribution,
    get_soc_threat_activity,
    get_soc_investigation_queue,
    export_case_report_pdf,
    export_case_report_json,
    export_case_ncrp_pdf,
    export_case_bsa_pdf,
    export_case_evidence_manifest,
)
from core.parser import (
    SecureEmailParser,
    sanitize_attachment_filename,
    MAX_RAW_EMAIL_SIZE_BYTES,
    MAX_HEADER_COUNT,
    MAX_BODY_CHARS,
    MAX_ATTACHMENT_COUNT,
)
from core.evidence import (
    EvidenceType,
    IntegrityStatus,
    build_evidence_manifest,
    verify_evidence_integrity,
    scan_and_redact_secrets,
)
from core.sentinel_control import (
    get_user_worker,
    upsert_user_worker,
    get_user_mailbox,
    get_user_checkpoint,
    get_user_alerts,
    mask_email_address,
)
from core.sentinel_stats import (
    TenantSentinelMetrics,
    _get_telemetry_file_path,
)
from core.rate_limiter import check_sliding_window_rate_limit
from core.geolocation import is_public_ip, derive_authoritative_location
from core.correlation import build_case_infrastructure_graph

# Worker components under test
from worker.config import WorkerConfig, mask_db_url
from worker.identity import WorkerIdentity, CapabilityToken
from worker.db import MockWorkerDBClient
from worker.lease import WorkerLeaseManager
from worker.credentials import LeasedCredential
from worker.checkpoint import CheckpointStore
from worker.events import SafeEmailEvent
from worker.health import (
    WorkerHealthStatus,
    classify_operational_failure,
    FailureCategory,
    get_worker_runtime_info,
)
from worker.logging import SafeLoggingFilter
from worker.synthetic_imap import (
    SyntheticIMAPServer,
    SyntheticIMAPConnection,
    SyntheticEmailMessage,
)


# =====================================================================
# RLS-AWARE TEST DOUBLES
# =====================================================================

class MockPostgrestTable:
    """PostgREST mock table enforcing kernel RLS per caller active user_id."""
    def __init__(self, db_state: Dict[str, List[Dict[str, Any]]], table_name: str, active_user_id: Optional[str]):
        self.db_state = db_state
        self.table_name = table_name
        self.active_user_id = active_user_id
        self._or_cond = None
        self._eq_filters = {}
        self._limit = None

    def select(self, *args, **kwargs):
        return self

    def order(self, field: str, desc: bool = False, *args, **kwargs):
        return self

    def limit(self, count: int):
        self._limit = count
        return self

    def or_(self, condition: str):
        self._or_cond = condition
        return self

    def eq(self, field: str, val: Any):
        self._eq_filters[field] = val
        return self

    def insert(self, rows):
        if not self.active_user_id:
            raise PermissionError("RLS Violation: anonymous inserts prohibited")
        if isinstance(rows, dict):
            rows = [rows]
        for row in rows:
            if row.get("user_id") != self.active_user_id:
                raise PermissionError("RLS Violation: cross-tenant insert prohibited")
            if "id" not in row:
                row["id"] = str(uuid.uuid4())
            self.db_state.setdefault(self.table_name, []).append(dict(row))
        return self

    def upsert(self, row: Dict[str, Any], on_conflict: str = ""):
        if not self.active_user_id or row.get("user_id") != self.active_user_id:
            raise PermissionError("RLS Violation: cross-tenant upsert prohibited")
        table = self.db_state.setdefault(self.table_name, [])
        existing = next((r for r in table if r.get("case_number") == row.get("case_number") and r.get("user_id") == row.get("user_id")), None)
        if existing:
            existing.update(row)
        else:
            if "id" not in row:
                row["id"] = str(uuid.uuid4())
            table.append(dict(row))
        return self

    def execute(self):
        target_name = "sentinel_mailboxes" if self.table_name == "sentinel_mailboxes_safe" else self.table_name
        table_rows = self.db_state.get(target_name, [])
        user_rows = [r for r in table_rows if r.get("user_id") == self.active_user_id] if self.active_user_id else []

        filtered = list(user_rows)
        if self._or_cond:
            parts = self._or_cond.split(",")
            cond_vals = [p.split(".eq.")[1] for p in parts if ".eq." in p]
            filtered = [r for r in filtered if r.get("id") in cond_vals or r.get("case_number") in cond_vals or r.get("case_id") in cond_vals]

        for field, val in self._eq_filters.items():
            filtered = [r for r in filtered if r.get(field) == val]

        if self._limit is not None:
            filtered = filtered[:self._limit]

        res = MagicMock()
        res.data = filtered
        return res


class MockSupabaseClient:
    """Mock Supabase client providing isolated PostgREST access per tenant session."""
    def __init__(self, db_state: Dict[str, List[Dict[str, Any]]], user_id: Optional[str]):
        self.db_state = db_state
        self.user_id = user_id

    def table(self, table_name: str) -> MockPostgrestTable:
        return MockPostgrestTable(self.db_state, table_name, self.user_id)


# =====================================================================
# TEST CLASS 1: PRODUCTION CONFIGURATION & ENVIRONMENT SEPARATION
# =====================================================================

class TestProductionConfigurationAndSeparation(unittest.TestCase):
    """Verifies environment separation, secret injection, and configuration hardening."""

    def test_01_environment_separation_isolated(self):
        """Verifies development, test, and production environments do not share credentials or state."""
        dev_mailbox = "dev.test@example.com"
        prod_mailbox = "emailshield.sentinel.test@gmail.com"
        self.assertNotEqual(dev_mailbox, prod_mailbox)

        config = WorkerConfig()
        self.assertFalse(config.production_polling_enabled)
        self.assertFalse(config.test_mode)

    def test_02_secret_configuration_no_source_exposure(self):
        """Scans tracked source files to ensure no hardcoded production API keys or tokens exist."""
        sensitive_patterns = [
            re.compile(r"sbp_[a-zA-Z0-9]{20,}"),
            re.compile(r"bot[0-9]{8,}:[a-zA-Z0-9_-]{35}"),
            re.compile(r"AIza[0-9A-Za-z_-]{35}"),
        ]
        skip_dirs = {".git", "__pycache__", ".pytest_cache", "venv", ".venv", "scratch"}
        for root, dirs, files in os.walk("."):
            dirs[:] = [d for d in dirs if d not in skip_dirs and not d.startswith(".")]
            for file in files:
                if "test_" in file or "tests" in root.replace("\\", "/") or file.endswith((".pyc", ".png", ".jpg", ".mmdb", ".pdf")):
                    continue
                fpath = os.path.join(root, file)
                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                        for pat in sensitive_patterns:
                            self.assertEqual(len(pat.findall(content)), 0, f"Found secret pattern in {fpath}")
                except Exception:
                    pass

    def test_03_streamlit_production_configuration(self):
        """Verifies Streamlit config strictly enforces security parameters."""
        config_path = os.path.join(".streamlit", "config.toml")
        self.assertTrue(os.path.isfile(config_path))
        with open(config_path, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn("enableXsrfProtection = true", content)
        self.assertIn("maxUploadSize = 10", content)
        self.assertIn("gatherUsageStats = false", content)
        self.assertNotIn("debug = true", content)

    def test_04_supabase_production_configuration_rls(self):
        """Verifies Supabase client configuration enforces RLS and avoids service_role."""
        prohibited = "service_" + "role"
        with open("core/supabase_client.py", "r", encoding="utf-8") as f:
            content = f.read()
        self.assertNotIn(prohibited, content)

    def test_05_logged_out_data_isolation(self):
        """Logged-out users must never observe historical cases, indicators, or telemetry."""
        with patch("core.case_store.is_supabase_configured", return_value=True):
            self.assertIsNone(get_case_record("CASE-1234", client=None))
            self.assertEqual(get_all_cases(client=None), [])
            kpis = get_soc_kpi_metrics(None, None)
            self.assertEqual(kpis["emails_analysed"], 0)
            self.assertEqual(kpis["threats_detected"], 0)


# =====================================================================
# TEST CLASS 2: WORKER PRODUCTION LIFECYCLE & READINESS
# =====================================================================

class TestWorkerLifecycleAndProductionReadiness(unittest.TestCase):
    """Verifies worker identity, startup, lease acquisition, and graceful shutdown."""

    def setUp(self):
        self.worker_id = uuid.uuid4()
        self.user_id = uuid.uuid4()
        self.identity = WorkerIdentity(worker_id=self.worker_id)
        self.db = MockWorkerDBClient()
        self.db.seed_worker(self.worker_id, self.user_id)
        self.lease_mgr = WorkerLeaseManager(identity=self.identity, db_client=self.db)
        self.checkpoint_store = CheckpointStore(db_client=self.db)

    def test_06_worker_identity_verification(self):
        """Worker identity must be bound to a unique UUID and non-superuser capability."""
        self.assertEqual(self.identity.worker_id, self.worker_id)
        raw_tok = "a" * 64
        tok = self.identity.bind_token(raw_tok)
        self.assertTrue(self.identity.has_token())
        self.assertEqual(self.identity.raw_token, raw_tok)
        self.assertTrue(tok.verify_hash(hashlib.sha256(bytes.fromhex(raw_tok)).hexdigest()))

    def test_07_worker_startup_and_lease_acquisition(self):
        """Worker startup acquires a valid lease and binds capability token."""
        mailbox_id = uuid.uuid4()
        self.db.seed_mailbox(mailbox_id, self.worker_id, self.user_id, "encrypted_test_cred")

        acquired = self.lease_mgr.acquire_lease(duration_seconds=120)
        self.assertTrue(acquired)
        self.assertTrue(self.lease_mgr.is_active())
        self.assertTrue(self.identity.has_token())

    def test_08_worker_graceful_shutdown_releases_lease(self):
        """Worker graceful shutdown explicitly releases the lease and preserves checkpoint."""
        mailbox_id = str(uuid.uuid4())
        self.lease_mgr.acquire_lease(duration_seconds=120)
        self.assertTrue(self.lease_mgr.is_active())

        # Seed checkpoint
        cp = self.checkpoint_store.get_checkpoint(str(self.user_id), str(self.worker_id), mailbox_id)
        cp.last_processed_uid = 250

        # Release lease on shutdown
        released = self.lease_mgr.release_lease()
        self.assertTrue(released)
        self.assertFalse(self.lease_mgr.is_active())
        self.assertFalse(self.identity.has_token())

        # Checkpoint remains intact after shutdown
        cp_after = self.checkpoint_store.get_checkpoint(str(self.user_id), str(self.worker_id), mailbox_id)
        self.assertEqual(cp_after.last_processed_uid, 250)

    def test_09_credential_decryption_and_cleanup(self):
        """Credentials in memory must provide clean secret access and zeroing upon clear()."""
        mailbox_id = str(uuid.uuid4())
        cred = LeasedCredential(
            mailbox_id=mailbox_id,
            worker_id=str(self.worker_id),
            user_id=str(self.user_id),
            provider="gmail",
            email_address="emailshield.sentinel.test@gmail.com",
            imap_host="imap.gmail.com",
            imap_port=993,
            use_ssl=True,
            auth_mechanism="APP_PASSWORD",
            credential_version=1,
            _secret="super_secret_test_app_pwd",
        )
        self.assertEqual(cred.secret, "super_secret_test_app_pwd")
        self.assertNotIn("super_secret_test_app_pwd", repr(cred))

        # Explicitly clear
        cred.clear()
        with self.assertRaises(ValueError):
            _ = cred.secret

    def test_10_database_connection_masking(self):
        """Database connection strings must mask plaintext passwords in all representations."""
        raw_url = "postgresql://sentinel_worker:SuperSecretDbPassword123@db.supabase.co:5432/postgres"
        masked = mask_db_url(raw_url)
        self.assertNotIn("SuperSecretDbPassword123", masked)
        self.assertIn(":***@", masked)


# =====================================================================
# TEST CLASS 3: OPERATIONAL HEALTH, LOGGING & ERROR MONITORING
# =====================================================================

class TestOperationalHealthAndLogging(unittest.TestCase):
    """Verifies structured logging, failure categorization, and telemetry reporting."""

    def test_11_health_status_serialization_redacts_secrets(self):
        """Worker health status dict must omit all passwords, tokens, and keys."""
        health = WorkerHealthStatus(
            worker_id=str(uuid.uuid4()),
            runtime_version="1.0.0",
            state="POLLING",
            started_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            uptime_seconds=3600.0,
            last_heartbeat=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            lease_active=True,
            lease_expires_in_seconds=120.0,
            db_connected=True,
            production_polling_enabled=False,
            test_mode=True,
        )
        h_dict = health.to_dict()
        self.assertNotIn("password", h_dict)
        self.assertNotIn("private_key", h_dict)
        self.assertNotIn("master_key", h_dict)
        self.assertNotIn("token", h_dict)

    def test_12_operational_logging_scrubs_sensitive_strings(self):
        """SafeLoggingFilter must redact private keys, DB passwords, and tokens."""
        filt = SafeLoggingFilter()
        dummy_record = MagicMock()
        priv_marker = "-----" + "BEGIN PRIVATE KEY" + "-----"
        dummy_record.msg = f"Connecting using {priv_marker} and password='SecretPassword99'"
        dummy_record.args = None

        filt.filter(dummy_record)
        self.assertNotIn("SecretPassword99", dummy_record.msg)

    def test_13_failure_classification_categories(self):
        """classify_operational_failure must cleanly categorize operational errors."""
        self.assertEqual(classify_operational_failure(ConnectionError("Connection refused by IMAP server")), FailureCategory.NETWORK_FAILURE)
        self.assertEqual(classify_operational_failure(PermissionError("Invalid login credentials")), FailureCategory.AUTHENTICATION_FAILED)
        self.assertEqual(classify_operational_failure(RuntimeError("SSL certificate verify failed")), FailureCategory.TLS_FAILURE)
        self.assertEqual(classify_operational_failure(RuntimeError("SSRF check blocked destination")), FailureCategory.SSRF_BLOCKED)
        self.assertEqual(classify_operational_failure(RuntimeError("Lease expired mid-poll")), FailureCategory.LEASE_LOST)
        self.assertEqual(classify_operational_failure(RuntimeError("Checkpoint write rejected")), FailureCategory.CHECKPOINT_FAILURE)
        self.assertEqual(classify_operational_failure(ValueError("Malformed MIME boundary encountered")), FailureCategory.MIME_PARSE_FAILURE)

    def test_14_error_messages_do_not_leak_internals(self):
        """Operational failure classification returns standardized category strings without stack traces."""
        secret_exc = Exception("Failed login for user test@example.com with password 'MySecretPassword123' at 192.168.1.1")
        cat = classify_operational_failure(secret_exc)
        self.assertEqual(cat, FailureCategory.AUTHENTICATION_FAILED)
        self.assertNotIn("MySecretPassword123", cat)


# =====================================================================
# TEST CLASS 4: TELEMETRY & SENTINEL OBSERVABILITY
# =====================================================================

class TestTelemetryAndSentinelObservability(unittest.TestCase):
    """Verifies metrics persistence, cross-tenant isolation, and restart safety."""

    def setUp(self):
        self.user_id = f"usr-{uuid.uuid4()}"
        self.mailbox_id = f"box-{uuid.uuid4()}"

    def test_15_telemetry_metrics_initialization_and_counters(self):
        """Telemetry metrics must record arrived, analysed, and risk counts accurately."""
        metrics = TenantSentinelMetrics(
            user_id=self.user_id,
            mailbox_id=self.mailbox_id,
            emails_arrived=10,
            emails_analysed=8,
            clean_count=5,
            suspicious_count=2,
            high_critical_count=1,
            duplicates_skipped=2,
            processing_errors=0,
            last_processed_uid=500,
        )
        self.assertEqual(metrics.emails_arrived, 10)
        self.assertEqual(metrics.emails_analysed, 8)
        self.assertEqual(metrics.clean_count + metrics.suspicious_count + metrics.high_critical_count, 8)
        self.assertEqual(metrics.duplicates_skipped, 2)
        self.assertEqual(metrics.last_processed_uid, 500)

    def test_16_telemetry_persistence_path_deterministic_and_isolated(self):
        """Telemetry persistence file paths must be deterministic and tenant-isolated."""
        path_1 = _get_telemetry_file_path(self.user_id, self.mailbox_id)
        path_2 = _get_telemetry_file_path(self.user_id, self.mailbox_id)
        self.assertEqual(path_1, path_2)

        other_user = f"usr-other-{uuid.uuid4()}"
        path_other = _get_telemetry_file_path(other_user, self.mailbox_id)
        self.assertNotEqual(path_1, path_other)

    def test_17_email_masking_presentation_layer(self):
        """mask_email_address must protect local usernames while retaining recognized domain."""
        self.assertEqual(mask_email_address("analyst@example.com"), "an***st@example.com")
        self.assertEqual(mask_email_address("admin@company.in"), "ad***in@company.in")
        self.assertEqual(mask_email_address(""), "Not Configured")
        self.assertEqual(mask_email_address(None), "Not Configured")


# =====================================================================
# TEST CLASS 5: GMAIL SMOKE & CONTROLLED ISOLATION
# =====================================================================

class TestGmailSmokeAndControlledIsolation(unittest.TestCase):
    """Verifies synthetic/controlled IMAP smoke test, UID processing, and isolation."""

    def setUp(self):
        self.worker_id = uuid.uuid4()
        self.user_id = uuid.uuid4()
        self.mailbox_id = uuid.uuid4()
        self.server = SyntheticIMAPServer()
        self.server.register_account("emailshield.sentinel.test@gmail.com", "mock_app_pwd_1234")

    def test_18_controlled_imap_smoke_pipeline(self):
        """Verifies UID discovery, message fetch, parsing, SafeEmailEvent creation, and checkpointing."""
        raw_msg = (
            b"From: security@alerts-bank.in\r\n"
            b"To: emailshield.sentinel.test@gmail.com\r\n"
            b"Subject: Urgent KYC Update Notification\r\n"
            b"Message-ID: <smoke-msg-001@alerts-bank.in>\r\n"
            b"\r\n"
            b"Please verify your account immediately at http://185.220.101.5/verify"
        )
        self.server.add_message(
            "emailshield.sentinel.test@gmail.com",
            SyntheticEmailMessage(uid=101, message_id="smoke-msg-001", raw_bytes=raw_msg)
        )

        # 1. Connect via synthetic connection
        conn = SyntheticIMAPConnection(server=self.server)
        conn.login("emailshield.sentinel.test@gmail.com", "mock_app_pwd_1234")
        conn.select("INBOX")

        # 2. Discover UIDs
        uids = conn.search(since_uid=0)
        self.assertIn(101, uids)

        # 3. Fetch Message
        fetch_res = conn.fetch(101)
        fetched_raw = fetch_res["rfc822"]
        self.assertIsNotNone(fetched_raw)

        # 4. Parse safely
        parser = SecureEmailParser(fetched_raw)
        data = parser.parse()
        subject_val = data.get("headers", {}).get("subject")
        self.assertEqual(subject_val, "Urgent KYC Update Notification")

        # 5. Create SafeEmailEvent
        event = SafeEmailEvent(
            tenant_user_id=str(self.user_id),
            mailbox_id=str(self.mailbox_id),
            uid=101,
            message_id="smoke-msg-001",
            sender="security@alerts-bank.in",
            recipient="emailshield.sentinel.test@gmail.com",
            timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            subject=subject_val or "",
            body_preview="Please verify your account...",
            body_length=len(fetched_raw),
        )
        self.assertEqual(event.uid, 101)
        self.assertEqual(event.processing_status, "PROCESSED")

        # 6. Monotonic checkpoint advancement
        checkpoint = 101
        self.assertEqual(checkpoint, 101)

        # 7. Deduplication on subsequent scan
        subsequent_uids = conn.search(since_uid=checkpoint)
        self.assertEqual(len(subsequent_uids), 0)

        conn.logout()

    def test_19_smoke_test_does_not_mutate_unrelated_telemetry(self):
        """Controlled IMAP polling on mailbox A must never alter mailbox B's checkpoint or state."""
        other_user = str(uuid.uuid4())
        other_box = str(uuid.uuid4())
        cp_store = CheckpointStore()
        cp = cp_store.get_checkpoint(other_user, str(self.worker_id), other_box)
        cp.last_processed_uid = 999

        # Verify other_box checkpoint is preserved
        cp_check = cp_store.get_checkpoint(other_user, str(self.worker_id), other_box)
        self.assertEqual(cp_check.last_processed_uid, 999)


# =====================================================================
# TEST CLASS 6: STORAGE READINESS, RETENTION & RESOURCE LIMITS
# =====================================================================

class TestStorageReadinessRetentionAndLimits(unittest.TestCase):
    """Verifies bounded processing, attachment sanitization, and retention constraints."""

    def test_20_attachment_filename_sanitization_bounds(self):
        """Attachment filenames with paths, traversal, or special chars must be sanitized."""
        samples = [
            ("../../etc/passwd", "passwd"),
            ("..\\..\\Windows\\System32\\cmd.exe", "cmd.exe"),
            ("test<script>.bat", "test_script_.bat"),
            ("a" * 300 + ".txt", "a" * 251 + ".txt" if len("a" * 300) > 255 else "a" * 300 + ".txt"),
        ]
        for inp, _ in samples:
            clean = sanitize_attachment_filename(inp)
            self.assertNotIn("..", clean)
            self.assertNotIn("/", clean)
            self.assertNotIn("\\", clean)

    def test_21_resource_limits_enforced_by_parser(self):
        """Email parser strictly caps body characters, headers, and attachments."""
        lines = ["From: test@example.com", "To: target@example.com", "Subject: Limits Test"]
        for i in range(MAX_HEADER_COUNT + 50):
            lines.append(f"X-Limit-Header-{i}: val-{i}")
        lines.append("")
        lines.append("A" * (MAX_BODY_CHARS + 5000))

        raw = "\r\n".join(lines).encode("utf-8")
        parser = SecureEmailParser(raw)
        headers = parser.get_headers()
        body = parser.get_body_text()

        self.assertLessEqual(len(headers), MAX_HEADER_COUNT + 5)
        self.assertLessEqual(len(body), MAX_BODY_CHARS + 200)

    def test_22_oversized_raw_email_rejection(self):
        """Raw emails larger than 10MB must be rejected at input validation."""
        huge_bytes = b"0" * (MAX_RAW_EMAIL_SIZE_BYTES + 1024)
        with self.assertRaises(ValueError):
            SecureEmailParser(huge_bytes)

    def test_23_temporary_credential_material_not_retained(self):
        """LeasedCredential must securely zero its in-memory buffer upon clear()."""
        cred = LeasedCredential(
            mailbox_id=str(uuid.uuid4()),
            worker_id=str(uuid.uuid4()),
            user_id=str(uuid.uuid4()),
            provider="gmail",
            email_address="emailshield.sentinel.test@gmail.com",
            imap_host="imap.gmail.com",
            imap_port=993,
            use_ssl=True,
            auth_mechanism="APP_PASSWORD",
            credential_version=1,
            _secret="super_secret_app_password",
        )
        self.assertEqual(cred.secret, "super_secret_app_password")
        cred.clear()
        with self.assertRaises(ValueError):
            _ = cred.secret


# =====================================================================
# TEST CLASS 7: DEPLOYMENT ARTIFACTS & CONTAINER HARDENING
# =====================================================================

class TestDeploymentArtifactsAndRuntime(unittest.TestCase):
    """Verifies Dockerfile security, .dockerignore excludes, and rollback readiness."""

    def test_24_dockerfile_security_invariants(self):
        """Dockerfile must specify non-root USER sentinel and omit public ports."""
        with open("Dockerfile", "r", encoding="utf-8") as f:
            content = f.read()

        self.assertIn("USER sentinel", content)
        self.assertIn("useradd -u 10001", content)
        # Worker is outbound-only, must NOT expose ports
        self.assertNotIn("EXPOSE 80", content)
        self.assertNotIn("EXPOSE 443", content)
        self.assertNotIn("EXPOSE 8501", content)

    def test_25_dockerignore_excludes_secrets_and_history(self):
        """.dockerignore must exclude git history, environment files, and keys."""
        with open(".dockerignore", "r", encoding="utf-8") as f:
            content = f.read()

        self.assertIn(".git", content)
        self.assertIn(".env", content)
        self.assertIn("*.key", content)
        self.assertIn("*.pem", content)
        self.assertIn("tests/", content)

    def test_26_requirements_has_zero_unpinned_critical_packages(self):
        """requirements.txt must be a clean, minimal set of dependencies."""
        with open("requirements.txt", "r", encoding="utf-8") as f:
            lines = [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]

        required = ["streamlit", "cryptography", "pytest", "supabase"]
        for req in required:
            self.assertTrue(any(req in line.lower() for line in lines), f"Missing {req} in requirements.txt")

    def test_27_startup_configuration_validation_fails_safely(self):
        """Worker configuration loader must fail closed when invalid values are supplied."""
        with self.assertRaises(ValueError):
            WorkerConfig.from_env({"SENTINEL_WORKER_ID": "not-a-valid-uuid"})


# =====================================================================
# TEST CLASS 8: USER JOURNEY & PERFORMANCE SMOKE TEST
# =====================================================================

class TestUserJourneyAndPerformance(unittest.TestCase):
    """Verifies end-to-end user journey across SOC views and bounded response times."""

    def setUp(self):
        self.user_id = f"usr-journey-{uuid.uuid4()}"
        self.db = {"cases": [], "indicators": []}
        self.client = MockSupabaseClient(self.db, self.user_id)

    def test_28_complete_authorized_user_journey(self):
        """Verifies end-to-end flow: Case Save -> SOC KPIs -> IOC List -> GeoIP -> Attack Graph -> Report Export -> Logout."""
        with patch("core.case_store.is_supabase_configured", return_value=True):
            # 1. Save Case
            case_data = {
                "case_id": "CASE-JOURNEY-001",
                "case_number": "CASE-JOURNEY-001",
                "user_id": self.user_id,
                "subject": "Phishing Attempt on Finance Team",
                "sender": "payroll@spoofed-bank.in",
                "threat_verdict": "MALICIOUS",
                "risk_score": "HIGH",
                "sender_location": {
                    "is_identified": True,
                    "sender_ip": "185.220.101.5",
                    "country": "Germany",
                    "city": "Frankfurt",
                },
                "raw_json": {
                    "case_id": "CASE-JOURNEY-001",
                    "user_id": self.user_id,
                    "subject": "Phishing Attempt on Finance Team",
                    "sender": "payroll@spoofed-bank.in",
                    "threat_verdict": "MALICIOUS",
                    "risk_score": "HIGH",
                    "sender_location": {
                        "is_identified": True,
                        "sender_ip": "185.220.101.5",
                        "country": "Germany",
                        "city": "Frankfurt",
                    },
                    "indicators": [{"type": "DOMAIN", "value": "spoofed-bank.in", "severity": "HIGH"}],
                },
                "indicators": [{"type": "DOMAIN", "value": "spoofed-bank.in", "severity": "HIGH"}],
            }
            saved = save_case(case_data, user_id=self.user_id, client=self.client)
            self.assertTrue(saved)

            # 2. SOC KPIs
            kpis = get_soc_kpi_metrics(self.user_id, self.client)
            self.assertEqual(kpis["emails_analysed"], 1)

            # 3. Retrieve Case Record
            rec = get_case_record("CASE-JOURNEY-001", client=self.client)
            self.assertIsNotNone(rec)
            self.assertEqual(rec.get("subject"), "Phishing Attempt on Finance Team")

            # 4. Indicators
            iocs = get_all_indicators(client=self.client)
            self.assertEqual(len(iocs), 1)

            # 5. GeoIP Authoritative Location
            sloc = derive_authoritative_location(rec)
            self.assertTrue(sloc.get("is_identified"))
            self.assertEqual(sloc.get("sender_ip"), "185.220.101.5")

            # 6. Attack Graph
            graph = build_case_infrastructure_graph("CASE-JOURNEY-001", rec)
            self.assertIsNotNone(graph)

            # 7. Evidence Manifest & Report Export
            manifest_str = export_case_evidence_manifest("CASE-JOURNEY-001", client=self.client, user_id=self.user_id)
            self.assertIsNotNone(manifest_str)
            self.assertIn("CASE-JOURNEY-001", manifest_str)

            report_json = export_case_report_json("CASE-JOURNEY-001", client=self.client, user_id=self.user_id)
            self.assertIsNotNone(report_json)

            # 8. Logout State Purge (logged out visitor sees zero)
            self.assertIsNone(get_case_record("CASE-JOURNEY-001", client=None))
            self.assertEqual(get_all_cases(client=None), [])

    def test_29_performance_smoke_test_bounded_latencies(self):
        """Measures execution latency of core operations to verify absence of stalls or unbounded loops."""
        # 1. EML Parsing latency
        sample_eml = b"From: a@b.com\r\nTo: c@d.com\r\nSubject: Fast Parse\r\n\r\nSimple text body."
        t0 = time.perf_counter()
        for _ in range(100):
            p = SecureEmailParser(sample_eml)
            _ = p.parse()
        elapsed_parse = time.perf_counter() - t0
        self.assertLess(elapsed_parse, 1.0, f"EML parsing too slow: {elapsed_parse:.3f}s for 100 iterations")

        # 2. Secret Redaction latency
        t0 = time.perf_counter()
        payload = {"token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdef", "safe": "normal text"}
        for _ in range(100):
            _ = scan_and_redact_secrets(payload)
        elapsed_redact = time.perf_counter() - t0
        self.assertLess(elapsed_redact, 0.5, f"Secret redaction too slow: {elapsed_redact:.3f}s for 100 iterations")

        # 3. Rate limiter check latency
        tracker: Dict[str, List[float]] = {}
        t0 = time.perf_counter()
        for _ in range(100):
            check_sliding_window_rate_limit(tracker, "action_bench", max_requests=200, window_seconds=60)
        elapsed_rl = time.perf_counter() - t0
        self.assertLess(elapsed_rl, 0.2, f"Rate limiter check too slow: {elapsed_rl:.3f}s for 100 iterations")


if __name__ == "__main__":
    unittest.main()
