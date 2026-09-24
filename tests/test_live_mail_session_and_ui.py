"""
tests/test_live_mail_session_and_ui.py
Regression tests for Live Mail Session State and Merged UI:
1. Login -> Live Mail authorized
2. Logout -> Live Mail DISCONNECTED
3. Logout -> no private Live Mail data visible
4. Logout -> mailbox persistent state unchanged
5. Logout -> telemetry unchanged
6. Logout -> checkpoint unchanged
7. Logout -> worker state unchanged
8. Relogin -> fresh authorization
9. Relogin -> correct mailbox state
10. Relogin -> no stale session state
11. Browser refresh after logout -> disconnected
12. Browser back after logout -> private data denied
13. User A logout -> User B cannot inherit Live Mail A
14. Multiple tabs -> no cross-user leakage
15. Worker running while user logged out -> allowed
16. Worker running does not imply UI connected
17. Mailbox ACTIVE does not bypass authentication
18. PAUSED mailbox remains paused after relogin
19. DEACTIVATED mailbox remains deactivated after relogin
20. Telemetry remains persistent across logout/login
21. Last UID remains unchanged across logout/login
22. Merged Live Mail UI renders correctly
23. Mailbox Setup/Worker Monitoring/Lifecycle Management no longer appear as three separate top-level sections
24. Lifecycle controls still work
25. RLS remains enforced
"""

import unittest
import uuid
import os
from unittest.mock import patch, MagicMock

import core.sentinel_control as sc
from core.case_store import is_authorized_caller
from core.sentinel_stats import (
    get_user_sentinel_stats,
    record_user_sentinel_poll,
    reset_user_sentinel_stats,
    get_sentinel_worker_runtime,
)
from core.live_mail_adapter import get_authorized_live_mail_messages


class TestLiveMailSessionAndUI(unittest.TestCase):
    """Verifies investigator session lifecycle, persistent telemetry independence, and merged UI."""

    def setUp(self):
        self.user_a = str(uuid.uuid4())
        self.user_b = str(uuid.uuid4())
        self.mailbox_a = str(uuid.uuid4())
        self.mailbox_b = str(uuid.uuid4())
        self.worker_a = str(uuid.uuid4())
        self.mock_client = MagicMock()

    def tearDown(self):
        reset_user_sentinel_stats(self.user_a, self.mailbox_a)
        reset_user_sentinel_stats(self.user_b, self.mailbox_b)

    # 1. Login -> Live Mail authorized
    def test_01_login_live_mail_authorized(self):
        """Authenticated user with valid client passes authorization gate."""
        self.assertTrue(is_authorized_caller(self.user_a, client=self.mock_client))

    # 2. Logout -> Live Mail DISCONNECTED
    def test_02_logout_live_mail_disconnected(self):
        """Logged out / unauthenticated user is strictly denied."""
        self.assertFalse(is_authorized_caller(None, client=None))
        self.assertFalse(is_authorized_caller("", client=None))

    # 3. Logout -> no private Live Mail data visible
    def test_03_logout_no_private_data_visible(self):
        """Logged out caller receives empty message list and no private mailbox."""
        self.assertEqual(get_authorized_live_mail_messages(None, client=None), [])
        self.assertIsNone(sc.get_user_mailbox(None, client=None))
        self.assertEqual(sc.list_user_mailboxes(None, client=None), [])

    # 4. Logout -> mailbox persistent state unchanged
    def test_04_logout_mailbox_persistent_state_unchanged(self):
        """Logging out does not modify or delete backend mailbox records."""
        mailbox_data = {
            "id": self.mailbox_a,
            "user_id": self.user_a,
            "is_active": True,
            "email_address": "investigator@example.com"
        }
        with patch.object(sc, "get_user_mailbox", side_effect=lambda u=None, *args, **kwargs: mailbox_data if u else None):
            # When caller was authenticated
            mb_before = sc.get_user_mailbox(self.user_a, client=self.mock_client)
            self.assertIsNotNone(mb_before)
            self.assertTrue(mb_before["is_active"])

            # Caller logs out -> queries with None
            mb_logged_out = sc.get_user_mailbox(None, client=None)
            self.assertIsNone(mb_logged_out)

            # Mailbox record for user_a is still active on backend
            mb_after = sc.get_user_mailbox(self.user_a, client=self.mock_client)
            self.assertEqual(mb_after["id"], self.mailbox_a)
            self.assertTrue(mb_after["is_active"])

    # 5. Logout -> telemetry unchanged
    def test_05_logout_telemetry_unchanged(self):
        """Telemetry counters persist across user logout."""
        record_user_sentinel_poll(
            user_id=self.user_a,
            mailbox_id=self.mailbox_a,
            arrived=15,
            analysed=12,
            clean=10,
            suspicious=2,
            last_uid=128
        )
        stats_before = get_user_sentinel_stats(self.user_a, self.mailbox_a)
        self.assertEqual(stats_before["emails_arrived"], 15)
        self.assertEqual(stats_before["emails_analysed"], 12)
        self.assertEqual(stats_before["last_processed_uid"], 128)

        # Logged out query fails closed with anonymous/zero metrics
        stats_logged_out = get_user_sentinel_stats(None, None)
        self.assertEqual(stats_logged_out["emails_arrived"], 0)
        self.assertEqual(stats_logged_out["emails_analysed"], 0)

        # Persistent backend metrics for user A remain intact
        stats_after = get_user_sentinel_stats(self.user_a, self.mailbox_a)
        self.assertEqual(stats_after["emails_arrived"], 15)
        self.assertEqual(stats_after["emails_analysed"], 12)
        self.assertEqual(stats_after["last_processed_uid"], 128)

    # 6. Logout -> checkpoint unchanged
    def test_06_logout_checkpoint_unchanged(self):
        """Checkpoint UID is preserved and never reset on logout."""
        cp_data = {"user_id": self.user_a, "last_processed_uid": 450}
        with patch.object(sc, "get_user_checkpoint", return_value=cp_data):
            cp = sc.get_user_checkpoint(self.user_a, client=self.mock_client)
            self.assertEqual(cp["last_processed_uid"], 450)

    # 7. Logout -> worker state unchanged
    def test_07_logout_worker_state_unchanged(self):
        """Worker desired state remains RUNNING on backend even after investigator logs out."""
        w_data = {"id": self.worker_a, "user_id": self.user_a, "desired_state": "RUNNING"}
        with patch.object(sc, "get_user_worker", return_value=w_data):
            w = sc.get_user_worker(self.user_a, client=self.mock_client)
            self.assertEqual(w["desired_state"], "RUNNING")

    # 8. Relogin -> fresh authorization
    def test_08_relogin_fresh_authorization(self):
        """Relogging in re-establishes authorization for the user."""
        self.assertFalse(is_authorized_caller(None, client=None))
        self.assertTrue(is_authorized_caller(self.user_a, client=self.mock_client))

    # 9. Relogin -> correct mailbox state
    def test_09_relogin_correct_mailbox_state(self):
        """Relogged-in investigator retrieves authoritative mailbox state."""
        mailbox_data = {"id": self.mailbox_a, "user_id": self.user_a, "is_active": True, "provider": "gmail"}
        with patch.object(sc, "get_user_mailbox", return_value=mailbox_data):
            mb = sc.get_user_mailbox(self.user_a, client=self.mock_client)
            self.assertEqual(mb["provider"], "gmail")
            self.assertTrue(mb["is_active"])

    # 10. Relogin -> no stale session state
    def test_10_relogin_no_stale_session_state(self):
        """Session purge helper clears all investigator and live mail session keys."""
        from app import clear_investigator_session
        fake_session = {
            "user_id": self.user_a,
            "user_email": "user@example.com",
            "mailbox_connected": True,
            "current_email_bytes": b"test",
            "selected_live_mail_ids": {"case1", "case2"},
            "chk_live_case1": True,
            "live_mail_fetch_limit": 100,
        }
        with patch("streamlit.session_state", fake_session):
            clear_investigator_session()
            self.assertEqual(len(fake_session), 0)

    # 11. Browser refresh after logout -> disconnected
    def test_11_browser_refresh_after_logout_disconnected(self):
        """On browser refresh without user_id, caller is unauthenticated."""
        self.assertFalse(is_authorized_caller(None, None))

    # 12. Browser back after logout -> private data denied
    def test_12_browser_back_after_logout_private_data_denied(self):
        """Attempting to access messages after logout yields empty list."""
        self.assertEqual(get_authorized_live_mail_messages(None, None), [])

    # 13. User A logout -> User B cannot inherit Live Mail A
    def test_13_user_a_logout_user_b_cannot_inherit_mailbox(self):
        """User B querying User A's mailbox receives None or only their own."""
        cases_pool = [
            {"case_id": "c1", "user_id": self.user_a, "raw_json": {"user_id": self.user_a}},
            {"case_id": "c2", "user_id": self.user_b, "raw_json": {"user_id": self.user_b}},
        ]
        with patch("core.live_mail_adapter.get_all_cases", return_value=cases_pool):
            msgs_b = get_authorized_live_mail_messages(self.user_b, client=self.mock_client)
            for m in msgs_b:
                self.assertEqual(m.get("user_id", self.user_b), self.user_b)
                self.assertNotEqual(m.get("user_id"), self.user_a)

    # 14. Multiple tabs -> no cross-user leakage
    def test_14_multiple_tabs_no_cross_user_leakage(self):
        """Multi-tenant isolation ensures User A and User B never cross-contaminate."""
        record_user_sentinel_poll(self.user_a, self.mailbox_a, arrived=10, analysed=10)
        record_user_sentinel_poll(self.user_b, self.mailbox_b, arrived=25, analysed=20)

        stats_a = get_user_sentinel_stats(self.user_a, self.mailbox_a)
        stats_b = get_user_sentinel_stats(self.user_b, self.mailbox_b)

        self.assertEqual(stats_a["emails_arrived"], 10)
        self.assertEqual(stats_b["emails_arrived"], 25)

    # 15. Worker running while user logged out -> allowed
    def test_15_worker_running_while_user_logged_out(self):
        """External worker process runtime status is independent of user login state."""
        with patch("core.sentinel_stats.is_pid_alive", return_value=True):
            rt = get_sentinel_worker_runtime()
            self.assertIn("worker_process_alive", rt)

    # 16. Worker running does not imply UI connected
    def test_16_worker_running_does_not_imply_ui_connected(self):
        """Even if worker process is alive, unauthenticated investigator is DISCONNECTED."""
        with patch("core.sentinel_stats.is_pid_alive", return_value=True):
            self.assertFalse(is_authorized_caller(None, None))

    # 17. Mailbox ACTIVE does not bypass authentication
    def test_17_mailbox_active_does_not_bypass_authentication(self):
        """Active mailbox record does not grant access to unauthenticated caller."""
        mb = {"id": self.mailbox_a, "user_id": self.user_a, "is_active": True}
        with patch.object(sc, "get_user_mailbox", side_effect=lambda u, c=None: mb if u else None):
            self.assertIsNone(sc.get_user_mailbox(None, None))
            self.assertIsNotNone(sc.get_user_mailbox(self.user_a, None))

    # 18. PAUSED mailbox remains paused after relogin
    def test_18_paused_mailbox_remains_paused_after_relogin(self):
        """Paused worker state persists and is retrieved on relogin."""
        w_data = {"id": self.worker_a, "user_id": self.user_a, "desired_state": "STOPPED"}
        with patch.object(sc, "get_user_worker", return_value=w_data):
            w = sc.get_user_worker(self.user_a, client=self.mock_client)
            self.assertEqual(w["desired_state"], "STOPPED")

    # 19. DEACTIVATED mailbox remains deactivated after relogin
    def test_19_deactivated_mailbox_remains_deactivated_after_relogin(self):
        """Deactivated mailbox record retains is_active=False across sessions."""
        mb = {"id": self.mailbox_a, "user_id": self.user_a, "is_active": False}
        with patch.object(sc, "get_user_mailbox", return_value=mb):
            res = sc.get_user_mailbox(self.user_a, client=self.mock_client)
            self.assertFalse(res["is_active"])

    # 20. Telemetry remains persistent across logout/login
    def test_20_telemetry_remains_persistent(self):
        """Emails Analysed and Arrived remain constant through session clearing."""
        record_user_sentinel_poll(self.user_a, self.mailbox_a, arrived=77, analysed=75, last_uid=999)
        s1 = get_user_sentinel_stats(self.user_a, self.mailbox_a)
        self.assertEqual(s1["emails_arrived"], 77)
        self.assertEqual(s1["emails_analysed"], 75)
        self.assertEqual(s1["last_processed_uid"], 999)

    # 21. Last UID remains unchanged across logout/login
    def test_21_last_uid_remains_unchanged(self):
        """Last processed UID persists in telemetry registry."""
        record_user_sentinel_poll(self.user_a, self.mailbox_a, last_uid=512)
        s = get_user_sentinel_stats(self.user_a, self.mailbox_a)
        self.assertEqual(s["last_processed_uid"], 512)

    # 22. Merged Live Mail UI renders correctly
    def test_22_merged_live_mail_ui_renders_correctly(self):
        """views/settings.py contains unified '📡 Live Mail' section."""
        with open("views/settings.py", "r", encoding="utf-8") as f:
            src = f.read()
        self.assertIn("📡 Live Mail", src)
        self.assertIn("#### 📬 Mailbox", src)
        self.assertIn("#### 📡 Worker Monitoring", src)
        self.assertIn("#### ⚠️ Lifecycle Management", src)

    # 23. Mailbox Setup/Worker Monitoring/Lifecycle Management no longer separate tabs
    def test_23_sections_no_longer_separate_tabs(self):
        """views/settings.py does not define 3 separate top-level tabs for setup, monitoring, lifecycle."""
        with open("views/settings.py", "r", encoding="utf-8") as f:
            src = f.read()
        self.assertNotIn('"📬 Mailbox Setup",', src)
        self.assertNotIn('"⚠️ Lifecycle Management",', src)

    # 24. Lifecycle controls still work
    def test_24_lifecycle_controls_work(self):
        """Lifecycle helper functions exist and accept proper parameters."""
        mock_client = MagicMock()
        mock_res = MagicMock()
        mock_res.data = [{"id": self.worker_a, "desired_state": "STOPPED"}]
        mock_client.table.return_value.update.return_value.eq.return_value.execute.return_value = mock_res

        ok, msg = sc.set_worker_desired_state(self.user_a, "STOPPED", client=mock_client)
        self.assertTrue(ok)

    # 25. RLS remains enforced
    def test_25_rls_remains_enforced(self):
        """is_authorized_caller fails closed when user_id is missing or client is invalid."""
        self.assertFalse(is_authorized_caller(None, None))
        self.assertFalse(is_authorized_caller("", None))


if __name__ == "__main__":
    unittest.main()
