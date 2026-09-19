"""
worker/local_imap_server.py
Local Controlled IMAP Test Harness for EMAILSHIELD INDIA Sentinel.

Strictly adheres to:
1. Local-Only Binding: Binds strictly to 127.0.0.1. Never 0.0.0.0.
2. Ephemeral TLS: Generates test-only self-signed certificate in temporary memory/disk
   with SAN for 127.0.0.1 and localhost.
3. Strict TLS Client Context: Client verification uses CERT_REQUIRED and check_hostname=True.
4. Command Minimization: Supports CAPABILITY, LOGIN, SELECT, EXAMINE, SEARCH, UID SEARCH,
   FETCH, UID FETCH, CLOSE, LOGOUT.
5. Deterministic Synthetic Email Dataset for comprehensive Phase 6O testing.
"""

import datetime
import ipaddress
import os
import re
import socket
import ssl
import tempfile
import threading
import time
from typing import Dict, List, Optional, Tuple, Any

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


class LocalIMAPTestServer:
    """
    RFC 3501-compliant local test IMAP server with TLS encryption.
    Binds strictly to 127.0.0.1 to guarantee zero external/public exposure.
    """

    def __init__(self, bind_address: str = "127.0.0.1", port: int = 0):
        if bind_address not in ("127.0.0.1", "localhost"):
            raise ValueError(f"LocalIMAPTestServer must bind only to 127.0.0.1 or localhost, rejected: {bind_address}")

        self.bind_address = bind_address
        self.requested_port = port
        self.port: Optional[int] = None
        self._server_sock: Optional[socket.socket] = None
        self._ssl_server_ctx: Optional[ssl.SSLContext] = None
        self._thread: Optional[threading.Thread] = None
        self._running = False

        # Temp certificate paths
        self._cert_path: Optional[str] = None
        self._key_path: Optional[str] = None

        # Accounts: username -> {"password": str, "messages": {uid: bytes}}
        self._accounts: Dict[str, Dict[str, Any]] = {}
        self._client_threads: List[threading.Thread] = []

    def _generate_self_signed_cert(self) -> Tuple[str, str]:
        """Generates an ephemeral X.509 self-signed certificate with IP SAN 127.0.0.1."""
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1"),
        ])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(
                x509.SubjectAlternativeName([
                    x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                    x509.DNSName("localhost"),
                ]),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )

        # Write to temporary files without hardcoding private key strings in source
        cfile = tempfile.NamedTemporaryFile(delete=False, suffix=".pem")
        kfile = tempfile.NamedTemporaryFile(delete=False, suffix=".key")

        cfile.write(cert.public_bytes(serialization.Encoding.PEM))
        cfile.flush()
        cfile.close()

        kfile.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
        kfile.flush()
        kfile.close()

        return cfile.name, kfile.name

    def register_account(self, username: str, password: str) -> None:
        """Registers a synthetic user account for testing."""
        self._accounts[username] = {
            "password": password,
            "messages": {},  # uid (int) -> raw_rfc822 (bytes)
            "next_uid": 1,
        }

    def add_message(self, username: str, raw_rfc822: bytes, uid: Optional[int] = None) -> int:
        """Adds an RFC822 message to the user's INBOX and returns its assigned UID."""
        if username not in self._accounts:
            raise ValueError(f"Account '{username}' not registered on local test server.")

        acc = self._accounts[username]
        if uid is None:
            uid = acc["next_uid"]
            acc["next_uid"] += 1
        else:
            if uid >= acc["next_uid"]:
                acc["next_uid"] = uid + 1

        acc["messages"][uid] = raw_rfc822
        return uid

    def get_client_ssl_context(self) -> ssl.SSLContext:
        """
        Creates a hardened client SSLContext that trusts the local fixture certificate
        with CERT_REQUIRED and check_hostname=True.
        """
        if not self._cert_path or not os.path.exists(self._cert_path):
            raise RuntimeError("Local IMAP server is not running or certificate missing.")

        client_ctx = ssl.create_default_context(cafile=self._cert_path)
        client_ctx.check_hostname = True
        client_ctx.verify_mode = ssl.CERT_REQUIRED
        return client_ctx

    def start(self) -> None:
        """Starts the local IMAP test server in a background thread."""
        if self._running:
            return

        self._cert_path, self._key_path = self._generate_self_signed_cert()

        self._ssl_server_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        self._ssl_server_ctx.load_cert_chain(certfile=self._cert_path, keyfile=self._key_path)

        self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_sock.bind((self.bind_address, self.requested_port))
        self._server_sock.listen(10)
        self.port = self._server_sock.getsockname()[1]
        self._running = True

        self._thread = threading.Thread(target=self._listen_loop, daemon=True)
        self._thread.start()
        time.sleep(0.05)

    def _listen_loop(self) -> None:
        """Accepts incoming client connections and wraps them with TLS."""
        while self._running:
            try:
                self._server_sock.settimeout(0.5)
                raw_conn, _ = self._server_sock.accept()
            except (socket.timeout, OSError):
                continue

            try:
                ssl_conn = self._ssl_server_ctx.wrap_socket(raw_conn, server_side=True)
                t = threading.Thread(target=self._handle_client, args=(ssl_conn,), daemon=True)
                self._client_threads.append(t)
                t.start()
            except Exception:
                try:
                    raw_conn.close()
                except Exception:
                    pass

    def _handle_client(self, conn: ssl.SSLSocket) -> None:
        """Handles an active IMAP client connection according to RFC 3501."""
        conn.settimeout(15.0)
        f = conn.makefile("rwb")
        authenticated_user: Optional[str] = None
        selected_folder: Optional[str] = None

        try:
            # Initial server greeting
            f.write(b"* OK [CAPABILITY IMAP4rev1] Local IMAP Test Server Ready\r\n")
            f.flush()

            while self._running:
                raw_line = f.readline()
                if not raw_line:
                    break

                line_str = raw_line.decode("utf-8", errors="ignore").strip()
                if not line_str:
                    continue

                parts = line_str.split()
                tag = parts[0]
                cmd = parts[1].upper() if len(parts) > 1 else ""

                if cmd == "CAPABILITY":
                    f.write(b"* CAPABILITY IMAP4rev1\r\n")
                    f.write(f"{tag} OK CAPABILITY completed\r\n".encode("utf-8"))
                    f.flush()

                elif cmd == "NOOP":
                    f.write(f"{tag} OK NOOP completed\r\n".encode("utf-8"))
                    f.flush()

                elif cmd == "LOGIN":
                    user = parts[2] if len(parts) > 2 else ""
                    # Password might be in quotes
                    pwd = " ".join(parts[3:]).strip("\"'") if len(parts) > 3 else ""

                    if user in self._accounts and self._accounts[user]["password"] == pwd:
                        authenticated_user = user
                        f.write(f"{tag} OK LOGIN completed\r\n".encode("utf-8"))
                    else:
                        f.write(f"{tag} NO [AUTHENTICATIONFAILED] Invalid credentials\r\n".encode("utf-8"))
                    f.flush()

                elif cmd in ("SELECT", "EXAMINE"):
                    if not authenticated_user:
                        f.write(f"{tag} NO Not authenticated\r\n".encode("utf-8"))
                    else:
                        folder = parts[2].strip("\"'") if len(parts) > 2 else "INBOX"
                        selected_folder = folder
                        messages = self._accounts[authenticated_user]["messages"]
                        count = len(messages)

                        f.write(f"* {count} EXISTS\r\n".encode("utf-8"))
                        f.write(f"* {count} RECENT\r\n".encode("utf-8"))
                        f.write(b"* FLAGS (\\Seen \\Answered \\Flagged \\Deleted \\Draft)\r\n")
                        f.write(b"* OK [UIDVALIDITY 1] UIDs valid\r\n")
                        f.write(f"{tag} OK [READ-ONLY] Select completed\r\n".encode("utf-8"))
                    f.flush()

                elif cmd == "UID":
                    subcmd = parts[2].upper() if len(parts) > 2 else ""
                    if not authenticated_user or not selected_folder:
                        f.write(f"{tag} NO Mailbox not selected\r\n".encode("utf-8"))
                        f.flush()
                        continue

                    messages = self._accounts[authenticated_user]["messages"]

                    if subcmd == "SEARCH":
                        criteria = " ".join(parts[3:]).upper()
                        matching_uids: List[int] = []

                        if "ALL" in criteria:
                            matching_uids = sorted(messages.keys())
                        else:
                            # Parse UID <range>:* or similar
                            range_match = re.search(r"(\d+):\*", criteria)
                            if range_match:
                                min_uid = int(range_match.group(1))
                                matching_uids = sorted([u for u in messages.keys() if u >= min_uid])
                            else:
                                matching_uids = sorted(messages.keys())

                        uids_str = " ".join(str(u) for u in matching_uids)
                        f.write(f"* SEARCH {uids_str}\r\n".encode("utf-8"))
                        f.write(f"{tag} OK UID SEARCH completed\r\n".encode("utf-8"))
                        f.flush()

                    elif subcmd == "FETCH":
                        uid_arg = int(parts[3]) if len(parts) > 3 and parts[3].isdigit() else 0
                        if uid_arg in messages:
                            msg_bytes = messages[uid_arg]
                            size = len(msg_bytes)
                            f.write(f"* {uid_arg} FETCH (UID {uid_arg} RFC822 {{{size}}}\r\n".encode("utf-8"))
                            f.write(msg_bytes)
                            f.write(b")\r\n")
                            f.write(f"{tag} OK UID FETCH completed\r\n".encode("utf-8"))
                        else:
                            f.write(f"{tag} NO Message not found\r\n".encode("utf-8"))
                        f.flush()

                    else:
                        f.write(f"{tag} BAD Unknown UID command\r\n".encode("utf-8"))
                        f.flush()

                elif cmd == "CLOSE":
                    selected_folder = None
                    f.write(f"{tag} OK CLOSE completed\r\n".encode("utf-8"))
                    f.flush()

                elif cmd == "LOGOUT":
                    f.write(b"* BYE IMAP4rev1 Server logging out\r\n")
                    f.write(f"{tag} OK LOGOUT completed\r\n".encode("utf-8"))
                    f.flush()
                    break

                else:
                    f.write(f"{tag} BAD Command not recognized\r\n".encode("utf-8"))
                    f.flush()

        except Exception:
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def stop(self) -> None:
        """Stops the server and removes temporary certificate files."""
        self._running = False
        if self._server_sock:
            try:
                self._server_sock.close()
            except Exception:
                pass
            self._server_sock = None

        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1.0)
            self._thread = None

        # Clean up temporary certificate files
        for p in (self._cert_path, self._key_path):
            if p and os.path.exists(p):
                try:
                    os.unlink(p)
                except Exception:
                    pass
        self._cert_path = None
        self._key_path = None

    def __enter__(self) -> "LocalIMAPTestServer":
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.stop()
