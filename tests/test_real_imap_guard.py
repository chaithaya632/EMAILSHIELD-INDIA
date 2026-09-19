"""
tests/test_real_imap_guard.py
Verifies the Sentinel Real-Network Test Guard:
- Real connections disabled by default without explicit opt-in
- Guard requires exact match SENTINEL_ENABLE_REAL_IMAP_TEST=1
- Ineffective values ("0", "false", "true", "None") fail closed
- Socket monkeypatching proves 0 socket creations when guard is inactive
- Synthetic IMAP engine operates independently of the real-network guard
"""

import os
import socket
import unittest
from unittest.mock import patch, MagicMock

from worker.imap_client import (
    RealIMAPConnection,
    RealNetworkDeniedError,
    is_real_imap_test_enabled,
    check_real_imap_guard,
    GUARD_ENV_VAR,
)
from worker.synthetic_imap import SyntheticIMAPServer, SyntheticIMAPConnection


class TestRealIMAPGuard(unittest.TestCase):
    """Verifies that the real IMAP adapter fails closed when guard is inactive."""

    def setUp(self):
        # Save original env var state
        self._orig_guard = os.environ.get(GUARD_ENV_VAR)
        self._orig_prod = os.environ.get("SENTINEL_ENABLE_PRODUCTION_POLLING")
        os.environ.pop(GUARD_ENV_VAR, None)
        os.environ.pop("SENTINEL_ENABLE_PRODUCTION_POLLING", None)
        self._poll_file = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "local", "sentinel_production_polling.txt")
        self._poll_content = None
        if os.path.exists(self._poll_file):
            try:
                with open(self._poll_file, "r", encoding="utf-8") as f:
                    self._poll_content = f.read()
                os.remove(self._poll_file)
            except Exception:
                pass

    def tearDown(self):
        if self._orig_guard is not None:
            os.environ[GUARD_ENV_VAR] = self._orig_guard
        else:
            os.environ.pop(GUARD_ENV_VAR, None)

        if self._orig_prod is not None:
            os.environ["SENTINEL_ENABLE_PRODUCTION_POLLING"] = self._orig_prod
        else:
            os.environ.pop("SENTINEL_ENABLE_PRODUCTION_POLLING", None)

        if self._poll_content is not None:
            try:
                with open(self._poll_file, "w", encoding="utf-8") as f:
                    f.write(self._poll_content)
            except Exception:
                pass

    def test_01_guard_disabled_by_default(self):
        """When SENTINEL_ENABLE_REAL_IMAP_TEST is unset, connections are denied."""
        self.assertFalse(is_real_imap_test_enabled())
        with self.assertRaises(RealNetworkDeniedError) as ctx:
            check_real_imap_guard()
        self.assertIn("Real IMAP network connections are disabled by default", str(ctx.exception))
        self.assertIn("SENTINEL_ENABLE_REAL_IMAP_TEST=1", str(ctx.exception))

    def test_02_adapter_instantiation_raises_without_guard(self):
        """Attempting to instantiate RealIMAPConnection without guard raises RealNetworkDeniedError."""
        with self.assertRaises(RealNetworkDeniedError):
            RealIMAPConnection(host="imap.example.com")

    def test_03_invalid_guard_values_fail_closed(self):
        """Values other than exact '1' fail closed."""
        invalid_values = ["0", "false", "FALSE", "true", "TRUE", "yes", "None", "", "2", "enabled"]
        for val in invalid_values:
            os.environ[GUARD_ENV_VAR] = val
            self.assertFalse(
                is_real_imap_test_enabled(),
                f"Value '{val}' should not enable real IMAP test."
            )
            with self.assertRaises(RealNetworkDeniedError):
                check_real_imap_guard()
            with self.assertRaises(RealNetworkDeniedError):
                RealIMAPConnection(host="imap.example.com")

    def test_04_exact_guard_value_enables_connection(self):
        """When SENTINEL_ENABLE_REAL_IMAP_TEST='1', guard passes."""
        os.environ[GUARD_ENV_VAR] = "1"
        self.assertTrue(is_real_imap_test_enabled())
        # check_real_imap_guard should not raise
        check_real_imap_guard()

        # Instantiation with mocked IMAP factory succeeds past guard
        mock_imap = MagicMock()
        conn = RealIMAPConnection(
            host="imap.example.com",
            _imap_factory=lambda *a, **kw: mock_imap
        )
        self.assertEqual(conn.host, "imap.example.com")

    def test_05_zero_sockets_created_when_guard_inactive(self):
        """Proves no socket.socket is created when attempting real IMAP without guard."""
        socket_calls = []
        orig_socket = socket.socket

        def guarded_socket(*args, **kwargs):
            socket_calls.append((args, kwargs))
            return orig_socket(*args, **kwargs)

        with patch("socket.socket", side_effect=guarded_socket):
            with self.assertRaises(RealNetworkDeniedError):
                RealIMAPConnection(host="imap.example.com")

        self.assertEqual(len(socket_calls), 0, "No socket should have been instantiated!")

    def test_06_synthetic_imap_exempt_from_guard(self):
        """Synthetic IMAP functions completely normally regardless of guard state."""
        # Unset guard
        os.environ.pop(GUARD_ENV_VAR, None)

        server = SyntheticIMAPServer()
        server.register_account("test@example.invalid", "secret")
        conn = SyntheticIMAPConnection(server=server)
        self.assertTrue(conn.login("test@example.invalid", "secret"))
        status, count = conn.select("INBOX")
        self.assertEqual(status, "OK")
        conn.logout()
