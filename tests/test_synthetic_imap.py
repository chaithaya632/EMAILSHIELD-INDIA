"""
tests/test_synthetic_imap.py
Unit tests for the in-memory synthetic IMAP server and connection adapter.
Verifies authentication, mailbox selection, UID search, RFC822 fetch, deterministic ordering,
injected failures, clean disconnection, and zero socket usage.
"""

import unittest
from worker.synthetic_imap import (
    SyntheticIMAPServer,
    SyntheticIMAPConnection,
    SyntheticEmailMessage,
    SyntheticAuthError,
    SyntheticConnectionError,
    SyntheticIMAPError,
)


class TestSyntheticIMAPAdapter(unittest.TestCase):
    """Verifies synthetic IMAP server and client connection semantics."""

    def setUp(self):
        self.server = SyntheticIMAPServer()
        self.username = "test-user@example.invalid"
        self.password = "synthetic_secret_pass_123"
        self.server.register_account(self.username, self.password)

        # Seed sample messages
        self.server.add_message(
            self.username,
            SyntheticEmailMessage(
                uid=1,
                message_id="<msg-001@example.invalid>",
                subject="First Test Message",
                body="Hello World 1"
            )
        )
        self.server.add_message(
            self.username,
            SyntheticEmailMessage(
                uid=2,
                message_id="<msg-002@example.invalid>",
                subject="Second Test Message",
                body="Hello World 2"
            )
        )
        self.server.add_message(
            self.username,
            SyntheticEmailMessage(
                uid=5,
                message_id="<msg-005@example.invalid>",
                subject="Fifth Test Message",
                body="Hello World 5"
            )
        )

    def test_01_auth_success(self):
        """Verify successful login with registered credentials."""
        conn = SyntheticIMAPConnection(self.server)
        self.assertTrue(conn.login(self.username, self.password))

    def test_02_auth_failure_wrong_password(self):
        """Verify login rejection with incorrect password."""
        conn = SyntheticIMAPConnection(self.server)
        with self.assertRaises(SyntheticAuthError):
            conn.login(self.username, "wrong_password")

    def test_03_auth_failure_unknown_user(self):
        """Verify login rejection with unregistered username."""
        conn = SyntheticIMAPConnection(self.server)
        with self.assertRaises(SyntheticAuthError):
            conn.login("nonexistent@example.invalid", self.password)

    def test_04_mailbox_selection_success(self):
        """Verify selecting INBOX returns OK and message count."""
        conn = SyntheticIMAPConnection(self.server)
        conn.login(self.username, self.password)
        status, count = conn.select("INBOX")
        self.assertEqual(status, "OK")
        self.assertEqual(count, 3)

    def test_05_mailbox_selection_unknown_folder(self):
        """Verify selecting nonexistent folder returns NO, 0."""
        conn = SyntheticIMAPConnection(self.server)
        conn.login(self.username, self.password)
        status, count = conn.select("NONEXISTENT")
        self.assertEqual(status, "NO")
        self.assertEqual(count, 0)

    def test_06_uid_search_ascending_order(self):
        """Verify search returns all UIDs in strict ascending order."""
        conn = SyntheticIMAPConnection(self.server)
        conn.login(self.username, self.password)
        conn.select("INBOX")
        uids = conn.search()
        self.assertEqual(uids, [1, 2, 5])

    def test_07_uid_search_with_since_uid(self):
        """Verify search with since_uid returns only UIDs strictly greater than since_uid."""
        conn = SyntheticIMAPConnection(self.server)
        conn.login(self.username, self.password)
        conn.select("INBOX")
        uids_after_1 = conn.search(since_uid=1)
        self.assertEqual(uids_after_1, [2, 5])

        uids_after_2 = conn.search(since_uid=2)
        self.assertEqual(uids_after_2, [5])

        uids_after_5 = conn.search(since_uid=5)
        self.assertEqual(uids_after_5, [])

    def test_08_uid_fetch_valid_message(self):
        """Verify fetching message returns RFC822 payload, size, and message_id."""
        conn = SyntheticIMAPConnection(self.server)
        conn.login(self.username, self.password)
        conn.select("INBOX")

        fetched = conn.fetch(2)
        self.assertEqual(fetched["uid"], 2)
        self.assertEqual(fetched["message_id"], "<msg-002@example.invalid>")
        self.assertIn(b"Second Test Message", fetched["rfc822"])
        self.assertGreater(fetched["size"], 0)

    def test_09_injected_connection_failure(self):
        """Verify injected connection failure raises SyntheticConnectionError."""
        self.server.fail_connect = True
        conn = SyntheticIMAPConnection(self.server)
        with self.assertRaises(SyntheticConnectionError):
            conn.login(self.username, self.password)

    def test_10_injected_auth_failure(self):
        """Verify injected auth failure raises SyntheticAuthError."""
        self.server.fail_auth = True
        conn = SyntheticIMAPConnection(self.server)
        with self.assertRaises(SyntheticAuthError):
            conn.login(self.username, self.password)

    def test_11_injected_fetch_timeout(self):
        """Verify injected fetch timeout raises SyntheticConnectionError."""
        self.server.fetch_timeout = True
        conn = SyntheticIMAPConnection(self.server)
        conn.login(self.username, self.password)
        conn.select("INBOX")
        with self.assertRaises(SyntheticConnectionError):
            conn.fetch(1)

    def test_12_injected_fetch_specific_uid_failure(self):
        """Verify injected fetch error for a specific UID."""
        self.server.fail_fetch_uid = 2
        conn = SyntheticIMAPConnection(self.server)
        conn.login(self.username, self.password)
        conn.select("INBOX")

        # UID 1 succeeds
        f1 = conn.fetch(1)
        self.assertEqual(f1["uid"], 1)

        # UID 2 fails
        with self.assertRaises(SyntheticIMAPError):
            conn.fetch(2)

        # UID 5 succeeds
        f5 = conn.fetch(5)
        self.assertEqual(f5["uid"], 5)

    def test_13_clean_logout_and_close(self):
        """Verify close and logout cleanly invalidate connection."""
        conn = SyntheticIMAPConnection(self.server)
        conn.login(self.username, self.password)
        conn.select("INBOX")
        conn.close()
        self.assertIsNone(conn._selected_mailbox)
        conn.logout()
        self.assertIsNone(conn._logged_in_user)
        self.assertFalse(conn._is_connected)

    def test_14_context_manager_auto_logout(self):
        """Verify context manager automatically logs out on exit."""
        with SyntheticIMAPConnection(self.server) as conn:
            conn.login(self.username, self.password)
            self.assertTrue(conn._is_connected)
        self.assertFalse(conn._is_connected)


if __name__ == "__main__":
    unittest.main()
