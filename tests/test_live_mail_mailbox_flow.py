"""
tests/test_live_mail_mailbox_flow.py
Verifies Live Mail mailbox connection flow, state machine semantics,
and asymmetric envelope encryption integrity for EMAILSHIELD INDIA.
"""

import os
import json
import pytest
import subprocess
from unittest.mock import MagicMock, patch
from pathlib import Path

ROOT_DIR = Path(__file__).parent.parent
WEB_DIR = ROOT_DIR / "web"


class TestLiveMailMailboxSemantics:
    """Verifies Live Mail API state machine and connection invariants."""

    def test_live_mail_route_file_structure(self):
        """Verify API route files exist and maintain read-only decoupled boundaries."""
        status_route = WEB_DIR / "app" / "api" / "live-mail" / "mailbox" / "status" / "route.ts"
        connect_route = WEB_DIR / "app" / "api" / "live-mail" / "mailbox" / "connect" / "route.ts"
        test_route = WEB_DIR / "app" / "api" / "live-mail" / "mailbox" / "test" / "route.ts"
        disconnect_route = WEB_DIR / "app" / "api" / "live-mail" / "mailbox" / "disconnect" / "route.ts"
        live_mail_route = WEB_DIR / "app" / "api" / "live-mail" / "route.ts"

        assert status_route.exists(), "Mailbox status route must exist"
        assert connect_route.exists(), "Mailbox connect route must exist"
        assert test_route.exists(), "Mailbox test route must exist"
        assert disconnect_route.exists(), "Mailbox disconnect route must exist"
        assert live_mail_route.exists(), "Primary live-mail route must exist"

    def test_live_mail_telemetry_route_returns_no_mailbox_when_unlinked(self):
        """Verify live-mail route returns state: NO_MAILBOX and null telemetry when unlinked."""
        content = (WEB_DIR / "app" / "api" / "live-mail" / "route.ts").read_text(encoding="utf-8")
        assert 'state: "NO_MAILBOX"' in content
        assert "telemetry: null" in content
        assert "!mailbox || !mailbox.is_active" in content

    def test_live_mail_telemetry_does_not_contain_imap_connections(self):
        """Verify primary live-mail telemetry route does NOT make IMAP connections directly."""
        content = (WEB_DIR / "app" / "api" / "live-mail" / "route.ts").read_text(encoding="utf-8")
        assert "node-imap" not in content
        assert "imap-simple" not in content
        assert "tls.connect" not in content
        assert "net.connect" not in content

    def test_mailbox_test_enforces_ssrf_and_tls_verification(self):
        """Verify imap-test enforces imap.gmail.com:993, rejectUnauthorized: true, and TLSv1.2+."""
        content = (WEB_DIR / "lib" / "imap-test.ts").read_text(encoding="utf-8")
        assert 'host = "imap.gmail.com"' in content
        assert "port = 993" in content
        assert "rejectUnauthorized: true" in content
        assert 'minVersion: "TLSv1.2"' in content

    def test_asymmetric_credential_encryption_roundtrip(self):
        """Verify Node.js envelope generation roundtrips through Python WorkerKeyRing."""
        from core.sentinel_crypto import WorkerKeyRing, CONTEXT_MAILBOX, load_private_key_from_pem, load_private_key_from_env

        node_script = """
        const { encryptMailboxCredentialAsymmetric } = require('./web/lib/crypto/sentinel-crypto');
        const envelope = encryptMailboxCredentialAsymmetric('test-app-pass-secret-1234', 'ae1783f2-7117-40fd-aeb0-2ded6d8aec6c');
        console.log(envelope);
        """
        proc = subprocess.run(
            "npx tsx -e \"" + node_script.replace('"', '\\"').replace('\n', ' ') + "\"",
            cwd=str(ROOT_DIR),
            capture_output=True,
            text=True,
            shell=True,
            check=True
        )
        envelope = proc.stdout.strip()
        assert envelope.startswith("v2:k1:"), f"Envelope must be v2:k1 format: {envelope[:30]}"

        # Decrypt in Python worker key ring
        pem_path = ROOT_DIR / "data" / "local" / "sentinel_worker_private.pem"
        if pem_path.exists():
            priv_key = load_private_key_from_pem(pem_path.read_text(encoding="utf-8"))
        else:
            priv_key = load_private_key_from_env()

        keyring = WorkerKeyRing(keys={"k1": priv_key})
        decrypted = keyring.decrypt(
            envelope=envelope,
            user_id="ae1783f2-7117-40fd-aeb0-2ded6d8aec6c",
            purpose=CONTEXT_MAILBOX
        )
        assert decrypted == "test-app-pass-secret-1234"

    def test_frontend_ui_renders_not_connected_state_when_unlinked(self):
        """Verify Live Mail page UI renders NOT CONNECTED state when telemetry.connected is false."""
        page_content = (WEB_DIR / "app" / "live-mail" / "page.tsx").read_text(encoding="utf-8")
        assert "NOT CONNECTED" in page_content
        assert "No mailbox is linked to this account." in page_content
        assert "ConnectMailboxModal" in page_content
        assert "Connect Mailbox" in page_content
        assert "disconnectMailbox" in page_content
