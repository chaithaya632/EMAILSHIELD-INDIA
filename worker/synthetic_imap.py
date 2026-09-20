"""
worker/synthetic_imap.py
In-Memory Synthetic IMAP Adapter for EMAILSHIELD INDIA Sentinel.
Provides a deterministic, zero-network emulation of an IMAP mail server and client connection.

CRITICAL INVARIANT:
Never imports or invokes socket, DNS, urllib, requests, or imaplib.
Zero real network calls, zero external communication.
"""

from dataclasses import dataclass, field
from email.message import EmailMessage
from typing import Dict, List, Optional, Tuple, Any


class SyntheticIMAPError(Exception):
    """Base exception for synthetic IMAP operations."""
    pass


class SyntheticAuthError(SyntheticIMAPError):
    """Raised when synthetic authentication fails."""
    pass


class SyntheticConnectionError(SyntheticIMAPError):
    """Raised on injected synthetic connection or network timeout errors."""
    pass


@dataclass
class SyntheticEmailMessage:
    """
    Deterministic synthetic email message payload.
    Supports standard RFC822 generation as well as malformed, oversized, or raw payloads.
    """
    uid: int
    message_id: str
    from_addr: str = "sender@example.invalid"
    to_addr: str = "sentinel-test-user@example.invalid"
    date: str = "Wed, 17 Sep 2026 12:00:00 +0000"
    subject: str = "Synthetic Test Subject"
    body: str = "This is a synthetic test email body."
    headers: Dict[str, str] = field(default_factory=dict)
    raw_bytes: Optional[bytes] = None

    def to_rfc822(self) -> bytes:
        """Serializes message to RFC822 bytes or returns custom raw_bytes."""
        if self.raw_bytes is not None:
            return self.raw_bytes

        msg = EmailMessage()
        if self.message_id:
            msg["Message-ID"] = self.message_id
        if self.date:
            msg["Date"] = self.date
        if self.from_addr:
            msg["From"] = self.from_addr
        if self.to_addr:
            msg["To"] = self.to_addr
        if self.subject:
            msg["Subject"] = self.subject

        for k, v in self.headers.items():
            msg[k] = v

        msg.set_content(self.body)
        return msg.as_bytes()


class SyntheticMailbox:
    """In-memory folder representing an IMAP mailbox (e.g. INBOX)."""
    def __init__(self, folder_name: str = "INBOX", uid_validity: int = 1):
        self.folder_name = folder_name
        self.uid_validity = uid_validity
        self._messages: Dict[int, SyntheticEmailMessage] = {}

    def add_message(self, msg: SyntheticEmailMessage) -> None:
        self._messages[msg.uid] = msg

    def get_message(self, uid: int) -> Optional[SyntheticEmailMessage]:
        return self._messages.get(uid)

    def list_uids(self, since_uid: Optional[int] = None) -> List[int]:
        """Returns sorted list of UIDs, optionally strictly greater than since_uid."""
        uids = sorted(self._messages.keys())
        if since_uid is not None:
            uids = [u for u in uids if u > since_uid]
        return uids

    def count(self) -> int:
        return len(self._messages)


class SyntheticIMAPServer:
    """
    In-memory synthetic IMAP server holding isolated accounts and mailboxes.
    Guarantees zero network calls and supports deterministic failure injection.
    """
    def __init__(self):
        self._accounts: Dict[str, Dict[str, Any]] = {}
        # Failure injection flags
        self.fail_auth: bool = False
        self.fail_connect: bool = False
        self.fail_select: bool = False
        self.fail_fetch_uid: Optional[int] = None
        self.fetch_timeout: bool = False

    def register_account(self, username: str, password: str) -> None:
        """Registers a synthetic account with a default INBOX."""
        self._accounts[username.strip()] = {
            "password": password,
            "mailboxes": {"INBOX": SyntheticMailbox("INBOX")},
        }

    def get_mailbox(self, username: str, folder_name: str = "INBOX") -> Optional[SyntheticMailbox]:
        acct = self._accounts.get(username.strip())
        if not acct:
            return None
        return acct["mailboxes"].get(folder_name)

    def add_message(self, username: str, msg: SyntheticEmailMessage, folder_name: str = "INBOX") -> None:
        mb = self.get_mailbox(username, folder_name)
        if mb is None:
            acct = self._accounts.setdefault(username.strip(), {
                "password": "synthetic_password",
                "mailboxes": {},
            })
            mb = SyntheticMailbox(folder_name)
            acct["mailboxes"][folder_name] = mb
        mb.add_message(msg)


class SyntheticIMAPConnection:
    """
    Minimal synthetic IMAP client interface mimicking imaplib without any socket usage.
    """
    def __init__(
        self,
        server: SyntheticIMAPServer,
        host: str = "imap.example.invalid",
        port: int = 993,
        use_ssl: bool = True
    ):
        self.server = server
        self.host = host
        self.port = port
        self.use_ssl = use_ssl

        self._logged_in_user: Optional[str] = None
        self._selected_mailbox: Optional[SyntheticMailbox] = None
        self._is_connected: bool = True

    def login(self, username: str, password: str) -> bool:
        """Authenticates against the synthetic server."""
        if not self._is_connected or self.server.fail_connect:
            raise SyntheticConnectionError("Injected synthetic connection failure.")
        if self.server.fail_auth:
            raise SyntheticAuthError("Injected synthetic authentication failure.")

        clean_user = username.strip()
        acct = self.server._accounts.get(clean_user)
        if not acct or acct["password"] != password:
            raise SyntheticAuthError(f"Synthetic authentication rejected for '{clean_user}'.")

        self._logged_in_user = clean_user
        return True

    def select(self, mailbox_name: str = "INBOX") -> Tuple[str, int]:
        """Selects a mailbox folder."""
        if not self._logged_in_user:
            raise SyntheticAuthError("Not authenticated.")
        if self.server.fail_select:
            return "NO", 0

        mb = self.server.get_mailbox(self._logged_in_user, mailbox_name)
        if not mb:
            return "NO", 0

        self._selected_mailbox = mb
        return "OK", mb.count()

    def get_uid_validity(self) -> int:
        """Returns the UIDVALIDITY for the currently selected mailbox folder."""
        return getattr(self._selected_mailbox, "uid_validity", 1) if self._selected_mailbox else 1

    def search(self, since_uid: Optional[int] = None) -> List[int]:
        """Returns ascending list of unseen message UIDs in the selected mailbox."""
        if not self._selected_mailbox:
            raise SyntheticIMAPError("No mailbox selected.")
        return self._selected_mailbox.list_uids(since_uid=since_uid)

    def fetch(self, uid: int) -> Dict[str, Any]:
        """Fetches RFC822 payload and metadata for the given UID."""
        if not self._selected_mailbox:
            raise SyntheticIMAPError("No mailbox selected.")
        if self.server.fetch_timeout:
            raise SyntheticConnectionError("Injected synthetic fetch timeout.")
        if self.server.fail_fetch_uid == uid:
            raise SyntheticIMAPError(f"Injected synthetic fetch error for UID {uid}.")

        msg = self._selected_mailbox.get_message(uid)
        if not msg:
            raise SyntheticIMAPError(f"Message with UID {uid} not found.")

        rfc822_data = msg.to_rfc822()
        return {
            "uid": uid,
            "rfc822": rfc822_data,
            "size": len(rfc822_data),
            "message_id": msg.message_id,
        }

    def close(self) -> None:
        """Closes the currently selected mailbox folder."""
        self._selected_mailbox = None

    def logout(self) -> None:
        """Logs out from the synthetic session and closes connection."""
        self._logged_in_user = None
        self._selected_mailbox = None
        self._is_connected = False

    def __enter__(self) -> "SyntheticIMAPConnection":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.logout()
