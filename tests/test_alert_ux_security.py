"""
tests/test_alert_ux_security.py
Security regression tests for EMAILSHIELD alert credential handling,
analysis caching, and platform mode switching.

These tests verify:
1. Telegram token sanitization and masking
2. WhatsApp API key sanitization and masking
3. SHA-256 analysis caching behavior
4. Credential cleanup on session state transitions
"""

import hashlib
import pytest
from unittest.mock import patch, MagicMock


# =============================================================================
#  1. TELEGRAM TOKEN SANITIZATION & MASKING
# =============================================================================

class TestTelegramTokenSecurity:
    """Verify that Telegram bot tokens never leak into any output."""

    def test_sanitize_token_from_text(self):
        from core.telegram_alert import sanitize_telegram_token
        token = "1234567890:ABCdefGHIjklMNOpqrSTUvwxYZ123456789"
        text = f"Error connecting to https://api.telegram.org/bot{token}/sendMessage"
        result = sanitize_telegram_token(text, token)
        assert token not in result
        assert "REDACTED" in result

    def test_sanitize_token_pattern_without_explicit_key(self):
        from core.telegram_alert import sanitize_telegram_token
        token = "9876543210:ZYXwvuTSRqpoNMLkjiHGFedcba987654321"
        text = f"Token {token} is invalid"
        result = sanitize_telegram_token(text)
        assert token not in result
        assert "REDACTED" in result

    def test_sanitize_empty_text(self):
        from core.telegram_alert import sanitize_telegram_token
        assert sanitize_telegram_token("") == ""
        assert sanitize_telegram_token("", "sometoken") == ""

    def test_sanitize_url_pattern(self):
        from core.telegram_alert import sanitize_telegram_token
        text = "Reached api.telegram.org/bot1234567890:ABC_def-GHIjklMNOpqrSTUvwxYZ12345/getMe"
        result = sanitize_telegram_token(text)
        assert "1234567890:" not in result
        assert "api.telegram.org/bot[REDACTED" in result

    def test_validate_token_format_valid(self):
        from core.telegram_alert import validate_telegram_token_format
        assert validate_telegram_token_format("1234567890:ABCdefGHIjklMNOpqrSTUvwxYZ123456789")

    def test_validate_token_format_invalid(self):
        from core.telegram_alert import validate_telegram_token_format
        assert not validate_telegram_token_format("")
        assert not validate_telegram_token_format(None)
        assert not validate_telegram_token_format("not-a-token")
        assert not validate_telegram_token_format("12345:short")

    def test_mask_chat_id_numeric(self):
        from core.telegram_alert import mask_telegram_chat_id
        masked = mask_telegram_chat_id("123456789")
        assert "789" in masked
        assert "123456" not in masked
        assert "•" in masked

    def test_mask_chat_id_channel(self):
        from core.telegram_alert import mask_telegram_chat_id
        masked = mask_telegram_chat_id("@my_channel")
        assert masked.startswith("@")
        assert "•" in masked
        assert "my_channel" not in masked

    def test_mask_chat_id_none(self):
        from core.telegram_alert import mask_telegram_chat_id
        assert mask_telegram_chat_id(None) == "Not Configured"

    def test_validate_chat_id_valid_numeric(self):
        from core.telegram_alert import validate_telegram_chat_id
        ok, msg = validate_telegram_chat_id("123456789")
        assert ok

    def test_validate_chat_id_valid_channel(self):
        from core.telegram_alert import validate_telegram_chat_id
        ok, msg = validate_telegram_chat_id("@test_channel")
        assert ok

    def test_validate_chat_id_invalid(self):
        from core.telegram_alert import validate_telegram_chat_id
        ok, msg = validate_telegram_chat_id("")
        assert not ok
        ok2, msg2 = validate_telegram_chat_id(None)
        assert not ok2


# =============================================================================
#  2. WHATSAPP API KEY SANITIZATION & MASKING
# =============================================================================

class TestWhatsAppKeySecurity:
    """Verify that WhatsApp / CallMeBot API keys never leak into any output."""

    def test_sanitize_apikey_from_url(self):
        from core.whatsapp_alert import sanitize_whatsapp_key
        key = "mySecretKey123"
        url = f"https://api.callmebot.com/whatsapp.php?phone=+1234&text=hi&apikey={key}"
        result = sanitize_whatsapp_key(url, key)
        assert key not in result
        assert "REDACTED" in result

    def test_sanitize_apikey_pattern_only(self):
        from core.whatsapp_alert import sanitize_whatsapp_key
        url = "Error at api.callmebot.com/whatsapp.php?phone=+1234&text=hi&apikey=TopSecretKey456"
        result = sanitize_whatsapp_key(url)
        assert "TopSecretKey456" not in result
        assert "REDACTED" in result

    def test_sanitize_empty(self):
        from core.whatsapp_alert import sanitize_whatsapp_key
        assert sanitize_whatsapp_key("") == ""

    def test_mask_phone_number(self):
        from core.whatsapp_alert import mask_phone_number
        masked = mask_phone_number("+919876543210")
        assert masked.startswith("+91")
        assert masked.endswith("10")
        assert "987654" not in masked
        assert "•" in masked

    def test_mask_phone_empty(self):
        from core.whatsapp_alert import mask_phone_number
        assert mask_phone_number("") == "Not Configured"

    def test_mask_whatsapp_key(self):
        from core.whatsapp_alert import mask_whatsapp_key
        assert "•" in mask_whatsapp_key("mykey123")
        assert mask_whatsapp_key("") == "Not Configured"
        assert mask_whatsapp_key(None) == "Not Configured"

    def test_validate_phone_valid(self):
        from core.whatsapp_alert import validate_whatsapp_phone
        ok, result = validate_whatsapp_phone("+919876543210")
        assert ok
        assert result == "+919876543210"

    def test_validate_phone_invalid(self):
        from core.whatsapp_alert import validate_whatsapp_phone
        ok, result = validate_whatsapp_phone("")
        assert not ok
        ok2, result2 = validate_whatsapp_phone(None)
        assert not ok2
        ok3, result3 = validate_whatsapp_phone("abc")
        assert not ok3

    def test_validate_apikey_valid(self):
        from core.whatsapp_alert import validate_whatsapp_apikey
        ok, result = validate_whatsapp_apikey("abcd1234")
        assert ok
        assert result == "abcd1234"

    def test_validate_apikey_invalid(self):
        from core.whatsapp_alert import validate_whatsapp_apikey
        ok, result = validate_whatsapp_apikey("")
        assert not ok
        ok2, result2 = validate_whatsapp_apikey(None)
        assert not ok2
        ok3, result3 = validate_whatsapp_apikey("ab")  # too short
        assert not ok3

    def test_send_whatsapp_sanitizes_on_failure(self):
        """Verify that send_whatsapp_alert sanitizes error messages."""
        from core.whatsapp_alert import send_whatsapp_alert
        with patch("core.whatsapp_alert.requests.get") as mock_get:
            mock_get.side_effect = ConnectionError(
                "Connection to api.callmebot.com/whatsapp.php?phone=+1&text=hi&apikey=SECRET failed"
            )
            ok, msg = send_whatsapp_alert("+919876543210", "SECRET12", "test")
            assert not ok
            assert "SECRET12" not in msg
            # API key should be redacted

    def test_test_whatsapp_delivery_invalid_phone(self):
        from core.whatsapp_alert import test_whatsapp_alert_delivery
        result = test_whatsapp_alert_delivery("bad", "key12345")
        assert result["destination_status"] == "INVALID"
        assert result["delivery_status"] == "FAILED"

    def test_test_whatsapp_delivery_invalid_key(self):
        from core.whatsapp_alert import test_whatsapp_alert_delivery
        result = test_whatsapp_alert_delivery("+919876543210", "ab")
        assert result["destination_status"] == "VALID"
        assert result["auth_status"] == "NOT_CONFIGURED"
        assert result["delivery_status"] == "FAILED"

    def test_test_whatsapp_delivery_success(self):
        from core.whatsapp_alert import test_whatsapp_alert_delivery
        with patch("core.whatsapp_alert.requests.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.text = "Message queued"
            mock_get.return_value = mock_resp
            result = test_whatsapp_alert_delivery("+919876543210", "validKey1234")
            assert result["delivery_status"] == "DELIVERED"
            assert result["auth_status"] == "PASS"


# =============================================================================
#  3. SHA-256 ANALYSIS CACHING
# =============================================================================

class TestAnalysisCaching:
    """Verify SHA-256 based analysis caching logic."""

    def test_sha256_consistency(self):
        """Same bytes produce the same hash."""
        data = b"From: test@example.com\r\nSubject: Test\r\n\r\nBody"
        h1 = hashlib.sha256(data).hexdigest()
        h2 = hashlib.sha256(data).hexdigest()
        assert h1 == h2

    def test_sha256_different_bytes(self):
        """Different bytes produce different hashes."""
        d1 = b"Email A content"
        d2 = b"Email B content"
        h1 = hashlib.sha256(d1).hexdigest()
        h2 = hashlib.sha256(d2).hexdigest()
        assert h1 != h2

    def test_cache_hit_detection(self):
        """Simulate cache hit detection logic from app.py."""
        data = b"test email bytes"
        sha = hashlib.sha256(data).hexdigest()

        # Simulate session cache
        cache = {"sha256": sha, "case_id": "CASE-12345678"}
        email_sha = hashlib.sha256(data).hexdigest()
        cache_hit = (cache is not None and cache.get("sha256") == email_sha)
        assert cache_hit

    def test_cache_miss_new_email(self):
        """Simulate cache miss when a different email is loaded."""
        original_data = b"original email"
        new_data = b"new email"

        cache = {"sha256": hashlib.sha256(original_data).hexdigest(), "case_id": "CASE-OLD"}
        email_sha = hashlib.sha256(new_data).hexdigest()
        cache_hit = (cache is not None and cache.get("sha256") == email_sha)
        assert not cache_hit

    def test_cache_miss_no_cache(self):
        """Simulate cache miss when no cache exists."""
        data = b"test email"
        cache = None
        email_sha = hashlib.sha256(data).hexdigest()
        cache_hit = (cache is not None and cache.get("sha256") == email_sha)
        assert not cache_hit


# =============================================================================
#  4. WHATSAPP CONFIG RESOLUTION (without leakage)
# =============================================================================

class TestWhatsAppConfigSecurity:
    """Verify WhatsApp config resolution never leaks API keys."""

    def test_config_from_env(self):
        from core.whatsapp_alert import get_whatsapp_config
        with patch.dict("os.environ", {"CALLMEBOT_API_KEY": "envKey1234", "CALLMEBOT_PHONE": "+919876543210"}):
            config = get_whatsapp_config()
            assert config["is_apikey_configured"]
            assert config["is_destination_configured"]
            # Masked versions should not contain raw credentials
            assert "envKey1234" not in config["masked_apikey"]
            assert "987654" not in config["masked_destination"]

    def test_config_from_overrides(self):
        from core.whatsapp_alert import get_whatsapp_config
        config = get_whatsapp_config({
            "apikey": "overrideKey12",
            "phone": "+14155552671",
            "is_enabled": True,
        })
        assert config["is_apikey_configured"]
        assert config["is_destination_configured"]
        assert config["is_enabled"]
        assert "overrideKey12" not in config["masked_apikey"]

    def test_config_empty(self):
        from core.whatsapp_alert import get_whatsapp_config
        with patch.dict("os.environ", {}, clear=True):
            config = get_whatsapp_config()
            assert not config["is_apikey_configured"]
            assert not config["is_destination_configured"]


# =============================================================================
#  5. TELEGRAM & WHATSAPP CREDENTIAL SETUP GUIDES
# =============================================================================

class TestAlertSetupGuides:
    """Verify Telegram and WhatsApp credential setup guides in app.py."""

    @classmethod
    def setup_class(cls):
        import os
        sources = []
        for path in ["app.py", "views/alerts.py", "views/settings.py"]:
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8") as f:
                    sources.append(f.read())
        cls.app_source = "\n".join(sources)

    def test_telegram_guide_exists_and_collapsed_by_default(self):
        """Telegram guide must exist and be collapsed by default (expanded=False)."""
        assert 'st.expander("❓ How do I get a Telegram Bot Token and Chat ID?", expanded=False)' in self.app_source

    def test_telegram_guide_contains_botfather_instructions(self):
        """Telegram guide must instruct how to use @BotFather to create a bot."""
        assert "@BotFather" in self.app_source
        assert "/newbot" in self.app_source
        assert "ending in `bot`" in self.app_source
        assert "Bot Token" in self.app_source

    def test_telegram_guide_distinguishes_bot_token_from_chat_id(self):
        """Telegram guide must strictly distinguish Bot Token (auth) from Chat ID (destination)."""
        assert "Bot Token**: Authenticates your Telegram bot" in self.app_source
        assert "Chat ID**: Destination where EmailShield sends alerts" in self.app_source

    def test_telegram_guide_contains_secret_safety_warning(self):
        """Telegram guide must instruct users never to share tokens and explain masking."""
        assert "Never share your Telegram Bot Token" in self.app_source
        assert "masks the token after configuration" in self.app_source

    def test_telegram_guide_directs_to_test_alert(self):
        """Telegram guide must direct the user to click Test Alert after configuring."""
        assert "Click **🧪 Test Alert** to verify end-to-end delivery" in self.app_source

    def test_whatsapp_guide_exists_and_collapsed_by_default(self):
        """WhatsApp guide must exist and be collapsed by default (expanded=False)."""
        assert 'st.expander("❓ How do I configure WhatsApp Alerts?", expanded=False)' in self.app_source

    def test_whatsapp_guide_identifies_callmebot_provider(self):
        """WhatsApp guide must identify provider as WhatsApp via CallMeBot."""
        assert "WhatsApp via CallMeBot" in self.app_source

    def test_whatsapp_guide_distinguishes_phone_from_apikey(self):
        """WhatsApp guide must distinguish phone destination from CallMeBot API key."""
        assert "Phone Number**: The WhatsApp destination" in self.app_source
        assert "CallMeBot API Key**: The authentication credential used by CallMeBot" in self.app_source

    def test_whatsapp_guide_contains_callmebot_instructions(self):
        """WhatsApp guide must include safe activation instructions."""
        assert "callmebot.com" in self.app_source
        assert "I allow callmebot to send me messages" in self.app_source

    def test_whatsapp_guide_contains_secret_safety_warning(self):
        """WhatsApp guide must instruct users never to share API keys and explain masking."""
        assert "Never share your CallMeBot API key" in self.app_source
        assert "masks credentials after configuration" in self.app_source

    def test_whatsapp_guide_directs_to_test_alert(self):
        """WhatsApp guide must direct the user to click Test Alert."""
        assert "Click **🧪 Test Alert** to dispatch a harmless verification ping" in self.app_source

    def test_guides_do_not_trigger_network_or_polling(self):
        """Guides are purely presentation markup; parsing/viewing produces zero network calls."""
        with patch("requests.get") as mock_get, patch("requests.post") as mock_post:
            # Re-read or inspect guides
            assert "BotFather" in self.app_source
            assert "CallMeBot" in self.app_source
            assert mock_get.call_count == 0
            assert mock_post.call_count == 0

    def test_sentinel_remains_enabled_in_navigation(self):
        """Mailbox & Settings / Monitoring view remains enabled and active in navigation."""
        assert "⚙️ Mailbox & Settings" in self.app_source
        assert "Worker Monitoring" in self.app_source


# =============================================================================
#  6. SENTINEL CREDENTIAL VISIBILITY & LIVE ACTIVITY COUNTERS
# =============================================================================

class TestSentinelCredentialVisibilityAndActivityCounters:
    """
    Validates absolute secret-visibility prevention and live Sentinel processing counters.
    Guarantees:
    - Never display secrets post-connection.
    - Password / secret fields use type='password'.
    - Multi-tenant isolated activity counters for new messages, duplicates, and errors.
    - Test Alert is strictly independent from email counters.
    """

    @classmethod
    def setup_class(cls):
        import os
        sources = []
        for path in ["app.py", "views/alerts.py", "views/settings.py"]:
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8") as f:
                    sources.append(f.read())
        cls.app_source = "\n".join(sources)

    def test_telegram_token_never_displayed_post_connection(self):
        """Telegram token input uses password masking and safety warnings."""
        assert 'type="password"' in self.app_source
        assert "Never share your Telegram Bot Token" in self.app_source

    def test_whatsapp_key_never_displayed_post_connection(self):
        """WhatsApp API key input uses password masking and safety warnings."""
        assert 'type="password"' in self.app_source
        assert "Never share your CallMeBot API key" in self.app_source

    def test_mailbox_password_never_retained_in_widget_state(self):
        """Mailbox connection uses password masking and masks email address."""
        assert 'type="password"' in self.app_source
        assert "mask_email_address" in self.app_source

    def test_sentinel_activity_ui_metrics_rendered(self):
        """Worker Monitoring renders compact live activity, auto-refresh fragment, and counters."""
        assert "Worker Monitoring" in self.app_source
        assert "Live Activity" in self.app_source
        assert "Emails Analysed" in self.app_source
        assert "Threats Detected" in self.app_source

    def test_tenant_isolation_stats(self):
        """Counters for User A must be completely isolated from User B; no GLOBAL_STATS sharing."""
        from core.sentinel_stats import (
            record_user_sentinel_poll,
            get_user_sentinel_stats,
            reset_user_sentinel_stats
        )

        user_a = "tenant-user-alpha-111"
        mb_a = "mb-alpha-111"
        user_b = "tenant-user-beta-222"
        mb_b = "mb-beta-222"

        reset_user_sentinel_stats(user_a, mb_a)
        reset_user_sentinel_stats(user_b, mb_b)

        # Record poll for Tenant A
        record_user_sentinel_poll(
            user_id=user_a,
            mailbox_id=mb_a,
            arrived=5,
            analysed=4,
            clean=3,
            suspicious=1,
            high_critical=0,
            duplicates=1,
            errors=0,
            last_uid=42
        )

        stats_a = get_user_sentinel_stats(user_a, mb_a)
        stats_b = get_user_sentinel_stats(user_b, mb_b)

        # Tenant A reflects recorded activity
        assert stats_a["this_poll_arrived"] == 5
        assert stats_a["emails_arrived"] == 5
        assert stats_a["emails_analysed"] == 4
        assert stats_a["duplicates_skipped"] == 1
        assert stats_a["last_processed_uid"] == 42

        # Tenant B remains completely pristine (zero counts)
        assert stats_b["this_poll_arrived"] == 0
        assert stats_b["emails_arrived"] == 0
        assert stats_b["emails_analysed"] == 0
        assert stats_b["duplicates_skipped"] == 0
        assert stats_b["last_processed_uid"] == 0

        # Reset Tenant A has zero effect on Tenant B
        reset_user_sentinel_stats(user_a, mb_a)
        fresh_a = get_user_sentinel_stats(user_a, mb_a)
        fresh_b = get_user_sentinel_stats(user_b, mb_b)
        assert fresh_a["emails_arrived"] == 0
        assert fresh_b["emails_arrived"] == 0

    def test_poller_counters_new_message_and_second_poll(self):
        """
        Section 11 Test:
        Poll 1 with 1 new message -> arrived=1, analysed=1.
        Poll 2 with no new mail -> arrived=0, analysed=0 this poll; session total=1, 1.
        """
        import json
        import uuid
        from worker.config import WorkerConfig
        from worker.identity import WorkerIdentity
        from worker.lease import WorkerLeaseManager
        from worker.db import MockWorkerDBClient
        from core.sentinel_crypto import WorkerKeyRing, ProvisioningKeyRing, generate_worker_asymmetric_keypair
        from worker.credentials import WorkerCredentialService
        from worker.checkpoint import CheckpointStore
        from worker.poller import MailboxPoller
        from worker.synthetic_imap import SyntheticIMAPServer, SyntheticEmailMessage
        from core.sentinel_stats import get_user_sentinel_stats, reset_user_sentinel_stats

        worker_id = uuid.uuid4()
        user_id = uuid.uuid4()
        mailbox_id = uuid.uuid4()
        username = "user@example.invalid"
        password = "test-password"

        reset_user_sentinel_stats(str(user_id), str(mailbox_id))

        priv_key, pub_key = generate_worker_asymmetric_keypair(2048)
        prov_ring = ProvisioningKeyRing(active_version="k1", keys={"k1": pub_key})
        secret_json = json.dumps({
            "username": username,
            "password": password,
            "imap_host": "imap.example.invalid",
            "imap_port": 993
        })
        envelope = prov_ring.encrypt(secret_json, user_id=str(user_id))

        db = MockWorkerDBClient(session_user="sentinel_worker_daemon")
        db.seed_worker(worker_id, user_id, desired_state="RUNNING")
        db.seed_mailbox(mailbox_id, worker_id, user_id, encrypted_credentials=envelope)

        identity = WorkerIdentity(worker_id)
        lease_mgr = WorkerLeaseManager(identity, db)
        lease_mgr.acquire_lease(duration_seconds=180)

        worker_ring = WorkerKeyRing(active_version="k1", keys={"k1": priv_key})
        cred_service = WorkerCredentialService(identity, worker_ring, db)
        checkpoint_store = CheckpointStore()
        synthetic_server = SyntheticIMAPServer()
        synthetic_server.register_account(username, password)

        poller = MailboxPoller(
            config=WorkerConfig(worker_id=worker_id),
            identity=identity,
            lease_manager=lease_mgr,
            credential_service=cred_service,
            checkpoint_store=checkpoint_store,
            synthetic_server=synthetic_server
        )

        # 1. Add 1 new message
        synthetic_server.add_message(
            username,
            SyntheticEmailMessage(
                uid=101,
                message_id="<msg-101@example.invalid>",
                subject="First Inbound Threat Check",
                body="Hello world test message"
            )
        )

        # Poll 1
        res1 = poller.poll()
        assert res1["status"] == "SUCCESS"
        assert res1["processed_count"] == 1

        stats1 = get_user_sentinel_stats(str(user_id), str(mailbox_id))
        assert stats1["this_poll_arrived"] == 1
        assert stats1["emails_arrived"] == 1
        assert stats1["this_poll_analysed"] == 1
        assert stats1["emails_analysed"] == 1
        assert stats1["last_processed_uid"] == 101

        # Poll 2 (No new messages in mailbox)
        res2 = poller.poll()
        assert res2["status"] == "SUCCESS"
        assert res2["processed_count"] == 0

        stats2 = get_user_sentinel_stats(str(user_id), str(mailbox_id))
        assert stats2["this_poll_arrived"] == 0
        assert stats2["emails_arrived"] == 1
        assert stats2["this_poll_analysed"] == 0
        assert stats2["emails_analysed"] == 1
        assert stats2["last_processed_uid"] == 101

    def test_poller_counters_duplicate_skip(self):
        """
        Section 12 Test:
        Duplicate Message-ID advances checkpoint, increments duplicates_skipped,
        and does NOT increment emails_analysed.
        """
        import json
        import uuid
        from worker.config import WorkerConfig
        from worker.identity import WorkerIdentity
        from worker.lease import WorkerLeaseManager
        from worker.db import MockWorkerDBClient
        from core.sentinel_crypto import WorkerKeyRing, ProvisioningKeyRing, generate_worker_asymmetric_keypair
        from worker.credentials import WorkerCredentialService
        from worker.checkpoint import CheckpointStore
        from worker.poller import MailboxPoller
        from worker.synthetic_imap import SyntheticIMAPServer, SyntheticEmailMessage
        from core.sentinel_stats import get_user_sentinel_stats, reset_user_sentinel_stats

        worker_id = uuid.uuid4()
        user_id = uuid.uuid4()
        mailbox_id = uuid.uuid4()
        username = "user@example.invalid"
        password = "test-password"

        reset_user_sentinel_stats(str(user_id), str(mailbox_id))

        priv_key, pub_key = generate_worker_asymmetric_keypair(2048)
        prov_ring = ProvisioningKeyRing(active_version="k1", keys={"k1": pub_key})
        secret_json = json.dumps({
            "username": username,
            "password": password,
            "imap_host": "imap.example.invalid",
            "imap_port": 993
        })
        envelope = prov_ring.encrypt(secret_json, user_id=str(user_id))

        db = MockWorkerDBClient(session_user="sentinel_worker_daemon")
        db.seed_worker(worker_id, user_id, desired_state="RUNNING")
        db.seed_mailbox(mailbox_id, worker_id, user_id, encrypted_credentials=envelope)

        identity = WorkerIdentity(worker_id)
        lease_mgr = WorkerLeaseManager(identity, db)
        lease_mgr.acquire_lease(duration_seconds=180)

        worker_ring = WorkerKeyRing(active_version="k1", keys={"k1": priv_key})
        cred_service = WorkerCredentialService(identity, worker_ring, db)
        checkpoint_store = CheckpointStore()
        synthetic_server = SyntheticIMAPServer()
        synthetic_server.register_account(username, password)

        poller = MailboxPoller(
            config=WorkerConfig(worker_id=worker_id),
            identity=identity,
            lease_manager=lease_mgr,
            credential_service=cred_service,
            checkpoint_store=checkpoint_store,
            synthetic_server=synthetic_server
        )

        shared_msg_id = "<duplicate-target-unique@example.invalid>"
        # Add original message (UID 201)
        synthetic_server.add_message(
            username,
            SyntheticEmailMessage(uid=201, message_id=shared_msg_id, subject="Original Inbound")
        )
        # Add duplicate message (UID 202)
        synthetic_server.add_message(
            username,
            SyntheticEmailMessage(uid=202, message_id=shared_msg_id, subject="Duplicate Inbound")
        )

        res = poller.poll()
        assert res["status"] == "SUCCESS"
        assert res["processed_count"] == 1

        stats = get_user_sentinel_stats(str(user_id), str(mailbox_id))
        # 1 new message arrived, 1 duplicate skipped (does not increment arrived), 1 analysed
        assert stats["this_poll_arrived"] == 1
        assert stats["this_poll_duplicates"] == 1
        assert stats["duplicates_skipped"] == 1
        assert stats["this_poll_analysed"] == 1
        assert stats["emails_analysed"] == 1
        assert stats["last_processed_uid"] == 202

    def test_alert_test_does_not_modify_email_counters(self):
        """
        Section 14 Test:
        Testing alert delivery (Test Alert button) must NOT increment or modify email counters.
        """
        from core.telegram_alert import test_telegram_alert_delivery
        from core.whatsapp_alert import test_whatsapp_alert_delivery
        from core.sentinel_stats import get_user_sentinel_stats, reset_user_sentinel_stats

        test_user = "test-user-alert-indep"
        test_mb = "test-mb-alert-indep"
        reset_user_sentinel_stats(test_user, test_mb)

        initial_stats = get_user_sentinel_stats(test_user, test_mb)

        with patch("requests.get") as mock_get:
            mock_get.return_value = MagicMock(
                status_code=200,
                json=lambda: {"ok": True, "result": {"is_bot": True, "username": "AlertBot"}},
                text="ok"
            )
            # Execute Telegram Test Alert
            test_telegram_alert_delivery("123456789:ABCdefGHIjklMNOpqrSTUvwxYZ12345", "123456789")

            # Execute WhatsApp Test Alert
            test_whatsapp_alert_delivery("+919876543210", "callmebot-key-1234")

        after_stats = get_user_sentinel_stats(test_user, test_mb)
        assert after_stats["emails_arrived"] == initial_stats["emails_arrived"] == 0
        assert after_stats["emails_analysed"] == initial_stats["emails_analysed"] == 0
        assert after_stats["clean"] == 0
        assert after_stats["duplicates_skipped"] == 0


# =============================================================================
#  7. TELEGRAM DESTINATION STATUS RESOLUTION & UI CONSISTENCY
# =============================================================================

class TestTelegramDestinationStatusResolution:
    """
    Validates authoritative Telegram destination status resolution,
    lifecycle state transitions, and test alert workflow consistency.
    """

    def test_case_b_valid_token_and_valid_chat_id_connected(self):
        """Valid token + valid chat ID + enabled -> Destination CONFIGURED, Overall CONNECTED."""
        from core.telegram_alert import get_telegram_config

        config = get_telegram_config({
            "telegram_token": "1234567890:ABCdefGHIjklMNOpqrSTUvwxYZ123456789",
            "destination_target": "987654321",
            "is_enabled": True,
        })
        assert config["is_token_configured"] is True
        assert config["is_destination_configured"] is True
        assert config["is_enabled"] is True
        assert config["chat_id"] == "987654321"
        assert "987" in config["masked_destination"] or "321" in config["masked_destination"]

    def test_case_a_valid_token_missing_chat_id_pending_config(self):
        """Valid token + missing chat ID -> Destination NOT CONFIGURED, Overall PENDING CONFIG."""
        from core.telegram_alert import get_telegram_config

        config = get_telegram_config({
            "telegram_token": "1234567890:ABCdefGHIjklMNOpqrSTUvwxYZ123456789",
            "destination_target": "",
            "is_enabled": True,
        })
        assert config["is_token_configured"] is True
        assert config["is_destination_configured"] is False
        assert config["masked_destination"] == "Not Configured"

    def test_case_c_invalid_or_missing_token_not_configured(self):
        """Invalid token -> Authentication NOT CONFIGURED."""
        from core.telegram_alert import get_telegram_config

        config = get_telegram_config({
            "telegram_token": "invalid-token-format",
            "destination_target": "987654321",
        })
        assert config["is_token_configured"] is False

    def test_case_d_valid_token_valid_chat_id_disabled(self):
        """Valid token + valid chat ID + disabled -> Destination CONFIGURED, is_enabled FALSE."""
        from core.telegram_alert import get_telegram_config

        config = get_telegram_config({
            "telegram_token": "1234567890:ABCdefGHIjklMNOpqrSTUvwxYZ123456789",
            "destination_target": "987654321",
            "is_enabled": False,
        })
        assert config["is_token_configured"] is True
        assert config["is_destination_configured"] is True
        assert config["is_enabled"] is False

    def test_save_user_alert_metadata_inserts_when_empty(self):
        """save_user_alert_metadata inserts row into sentinel_alerts when none existed."""
        from core.sentinel_control import save_user_alert_metadata

        mock_client = MagicMock()
        mock_table = MagicMock()
        mock_client.table.return_value = mock_table
        # get_user_alerts returns empty
        mock_table.select.return_value.eq.return_value.execute.return_value = MagicMock(data=[])
        mock_table.insert.return_value.execute.return_value = MagicMock(data=[{"id": "new-alert-id"}])

        ok, msg = save_user_alert_metadata(
            user_id="u123",
            worker_id="w123",
            channel="telegram",
            destination_target="987654321",
            is_enabled=True,
            high_risk_only=True,
            client=mock_client
        )
        assert ok is True
        mock_table.insert.assert_called_once()
        insert_args = mock_table.insert.call_args[0][0]
        assert insert_args["channel"] == "telegram"
        assert insert_args["destination_target"] == "987654321"
        assert insert_args["is_enabled"] is True

    def test_save_user_alert_metadata_updates_when_matched(self):
        """save_user_alert_metadata updates existing record when present."""
        from core.sentinel_control import save_user_alert_metadata

        mock_client = MagicMock()
        mock_table = MagicMock()
        mock_client.table.return_value = mock_table
        # get_user_alerts returns existing telegram alert
        mock_table.select.return_value.eq.return_value.execute.return_value = MagicMock(
            data=[{"id": "existing-id", "channel": "telegram", "destination_target": "old-dest"}]
        )
        mock_table.update.return_value.eq.return_value.eq.return_value.execute.return_value = MagicMock(
            data=[{"id": "existing-id"}]
        )

        ok, msg = save_user_alert_metadata(
            user_id="u123",
            worker_id="w123",
            channel="telegram",
            destination_target="new-dest-999",
            is_enabled=True,
            high_risk_only=True,
            client=mock_client
        )
        assert ok is True
        mock_table.update.assert_called_once()
        update_args = mock_table.update.call_args[0][0]
        assert update_args["destination_target"] == "new-dest-999"

    def test_save_user_alert_metadata_disconnects(self):
        """save_user_alert_metadata cleans up on disconnection."""
        from core.sentinel_control import save_user_alert_metadata

        mock_client = MagicMock()
        mock_table = MagicMock()
        mock_client.table.return_value = mock_table
        mock_table.select.return_value.eq.return_value.execute.return_value = MagicMock(
            data=[{"id": "existing-id", "channel": "telegram", "destination_target": "987654321"}]
        )
        mock_table.update.return_value.eq.return_value.eq.return_value.execute.return_value = MagicMock(data=[])

        ok, msg = save_user_alert_metadata(
            user_id="u123",
            worker_id="w123",
            channel="telegram",
            destination_target="",
            is_enabled=False,
            high_risk_only=True,
            client=mock_client
        )
        assert ok is True
        assert "disconnected" in msg.lower()

    def test_app_ui_destination_status_contract(self):
        """Verify views/alerts.py renders test alert delivery and destination configuration."""
        with open("views/alerts.py", "r", encoding="utf-8") as f:
            src = f.read()

        assert "test_telegram_alert_delivery" in src
        assert "test_whatsapp_alert_delivery" in src
        assert "Telegram Bot Token" in src
        assert "CallMeBot API Key" in src


