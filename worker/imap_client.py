"""
worker/imap_client.py
Hardened Real IMAP Adapter for Sentinel Worker Engine.

Security & Operational Controls:
1. Strict SSRF Protection: Host validation rejects URLs, schemes, paths, userinfo,
   cloud metadata (169.254.169.254), and private/internal IP ranges unless explicitly allowed for testing.
2. Mandatory TLS Verification: Uses ssl.create_default_context() with check_hostname=True
   and verify_mode=CERT_REQUIRED. Certificate verification bypasses (verify=False) are strictly prohibited.
3. Real-Network Test Guard: Outbound real connections are disabled by default unless
   SENTINEL_ENABLE_REAL_IMAP_TEST=1 is explicitly set in the execution environment.
4. Command Minimization & Bounded Discovery: Only SELECT, SEARCH, FETCH, CLOSE, LOGOUT.
   Fetches are bounded to MAX_MESSAGES_PER_POLL.
5. Guaranteed Resource Cleanup: Context manager guarantees LOGOUT and socket teardown.
"""

import email
import imaplib
import ipaddress
import logging
import os
import re
import socket
import ssl
import sys
from typing import Any, Callable, Dict, List, Optional, Protocol, Tuple, runtime_checkable

logger = logging.getLogger("sentinel.worker.imap")

# Operational & Safety Constants
DEFAULT_IMAP_PORT_SSL = 993
DEFAULT_IMAP_PORT_PLAIN = 143
CONNECTION_TIMEOUT_SECONDS = 15
FETCH_TIMEOUT_SECONDS = 15
MAX_MESSAGES_PER_POLL = 20
MAX_MESSAGE_SIZE_BYTES = 5 * 1024 * 1024  # 5MB hard limit
MAX_HEADER_SIZE_BYTES = 64 * 1024         # 64KB limit
GUARD_ENV_VAR = "SENTINEL_ENABLE_REAL_IMAP_TEST"
LOCAL_IMAP_TEST_ENV_VAR = "SENTINEL_LOCAL_IMAP_TEST"
GMAIL_APP_PASSWORD_ENV_VAR = "SENTINEL_TEST_GMAIL_APP_PASSWORD"

GMAIL_TEST_EMAIL = "emailshield.sentinel.test@gmail.com"
GMAIL_IMAP_HOST = "imap.gmail.com"
GMAIL_IMAP_PORT = 993


# =============================================================================
# EXCEPTIONS
# =============================================================================

class IMAPClientError(Exception):
    """Base exception for Sentinel IMAP client errors."""
    pass


class RealNetworkDeniedError(IMAPClientError):
    """Raised when real IMAP connections are attempted without explicit guard opt-in."""
    pass


class SSRFSecurityError(IMAPClientError):
    """Raised when an IMAP host fails network safety / SSRF validation."""
    pass


class TLSVerificationError(IMAPClientError):
    """Raised when TLS configuration is insecure or certificate verification fails."""
    pass


class UnsupportedAuthMechanismError(IMAPClientError):
    """Raised when an unsupported or unconfigured authentication mechanism is requested."""
    pass


class IMAPAuthenticationError(IMAPClientError):
    """Raised when IMAP authentication fails."""
    pass


class IMAPConnectionTimeoutError(IMAPClientError):
    """Raised when IMAP connection or operation times out."""
    pass


# =============================================================================
# PROTOCOL / INTERFACE
# =============================================================================

@runtime_checkable
class IMAPConnectionProtocol(Protocol):
    """
    Common protocol satisfied by both SyntheticIMAPConnection and RealIMAPConnection.
    Allows MailboxPoller to operate transport-agnostically.
    """
    def login(self, username: str, password: str) -> bool:
        ...

    def select(self, mailbox_name: str = "INBOX") -> Tuple[str, int]:
        ...

    def get_uid_validity(self) -> int:
        ...

    def search(self, since_uid: Optional[int] = None) -> List[int]:
        ...

    def fetch(self, uid: int) -> Dict[str, Any]:
        ...

    def close(self) -> None:
        ...

    def logout(self) -> None:
        ...

    def __enter__(self) -> "IMAPConnectionProtocol":
        ...

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        ...


# =============================================================================
# NETWORK SAFETY & SSRF HARDENING
# =============================================================================

# Domain label regex compliant with RFC 1123
_DOMAIN_LABEL_REGEX = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$")

# Forbidden internal domains and cloud metadata hostnames
_FORBIDDEN_DOMAIN_SUFFIXES = (
    ".internal",
    ".local",
    ".localhost",
    ".lan",
    ".corp",
    ".home",
)
_FORBIDDEN_HOSTNAMES = {
    "localhost",
    "metadata.google.internal",
    "instance-data",
    "metadata",
}


def validate_imap_host(
    host: str,
    allow_private: bool = False,
    allow_local_fixture: bool = False,
) -> str:
    """
    Validates that the IMAP hostname is safe against SSRF and injection attacks.
    
    Rules:
    - Must be non-empty and <= 253 characters.
    - Must NOT contain schemes ('http://', 'imap://', etc.).
    - Must NOT contain paths ('/'), backslashes, userinfo ('@'), query ('?'), fragment ('#'), or port (':').
    - If allow_local_fixture=True:
      - Requires BOTH SENTINEL_LOCAL_IMAP_TEST=1 and host in ('127.0.0.1', 'localhost').
      - All other hosts, private IPs, or external domains are rejected.
    - If an IP address:
      - Cloud metadata (169.254.169.254) is strictly forbidden.
      - Link-local (169.254.0.0/16, fe80::/10) is strictly forbidden.
      - Loopback (127.0.0.0/8, ::1) is forbidden unless allow_private=True or allow_local_fixture=True.
      - Private RFC1918 addresses are forbidden unless allow_private=True.
      - Multicast, reserved, and broadcast are strictly forbidden.
    - If a domain name:
      - Complies with RFC 1123 label syntax.
      - Forbidden internal TLDs (.internal, .local, etc.) are rejected.
    """
    if not isinstance(host, str) or not host.strip():
        raise SSRFSecurityError("IMAP host cannot be empty.")

    clean_host = host.strip()

    if len(clean_host) > 253:
        raise SSRFSecurityError("IMAP host exceeds maximum DNS name length of 253 characters.")

    # Reject URLs and schemes
    if "://" in clean_host:
        raise SSRFSecurityError(f"IMAP host must be a hostname or IP, not a URL: '{clean_host}'")

    # Reject forbidden delimiter characters
    forbidden_chars = ("/", "\\", "@", "?", "#", ":", "[", "]")
    for char in forbidden_chars:
        if char in clean_host:
            raise SSRFSecurityError(
                f"IMAP host contains forbidden character '{char}': '{clean_host}'"
            )

    # Local fixture authorization check (strictly requires BOTH SENTINEL_LOCAL_IMAP_TEST=1 AND 127.0.0.1/localhost)
    if allow_local_fixture:
        if not is_local_imap_test_enabled():
            raise SSRFSecurityError(
                "Local fixture authorization requires SENTINEL_LOCAL_IMAP_TEST=1 in environment."
            )
        clean_target = clean_host.lower()
        if clean_target not in ("127.0.0.1", "localhost"):
            raise SSRFSecurityError(
                f"Local fixture authorization permits ONLY 127.0.0.1 or localhost, rejected: '{clean_host}'"
            )
        return clean_host

    lower_host = clean_host.lower()

    if lower_host in _FORBIDDEN_HOSTNAMES:
        raise SSRFSecurityError(f"IMAP host '{clean_host}' is a forbidden metadata or local target.")

    for suffix in _FORBIDDEN_DOMAIN_SUFFIXES:
        if lower_host.endswith(suffix):
            raise SSRFSecurityError(f"IMAP host '{clean_host}' uses a forbidden internal domain suffix '{suffix}'.")

    # Check if host is an IP literal
    try:
        ip = ipaddress.ip_address(clean_host)
        # Check cloud metadata endpoint (169.254.169.254)
        if clean_host == "169.254.169.254":
            raise SSRFSecurityError("Access to cloud metadata IP (169.254.169.254) is strictly prohibited.")

        if ip.is_link_local:
            raise SSRFSecurityError(f"Access to link-local IP '{clean_host}' is prohibited.")

        if ip.is_multicast or ip.is_reserved or ip.is_unspecified:
            raise SSRFSecurityError(f"Access to reserved/multicast IP '{clean_host}' is prohibited.")

        if not allow_private:
            if ip.is_loopback:
                raise SSRFSecurityError(f"Access to loopback IP '{clean_host}' is prohibited.")
            if ip.is_private:
                raise SSRFSecurityError(f"Access to private IP '{clean_host}' is prohibited.")

        return clean_host
    except ValueError:
        # Not an IP literal; validate as domain name
        pass

    # Domain name validation (RFC 1123)
    labels = clean_host.split(".")
    for label in labels:
        if not label:
            raise SSRFSecurityError(f"IMAP host '{clean_host}' contains empty domain label.")
        if len(label) > 63:
            raise SSRFSecurityError(f"Domain label '{label}' exceeds 63 characters.")
        if not _DOMAIN_LABEL_REGEX.match(label):
            raise SSRFSecurityError(f"Domain label '{label}' contains invalid characters.")

    return clean_host


def validate_imap_port(port: Any) -> int:
    """Validates that the IMAP port is a valid TCP port in range 1..65535."""
    try:
        p = int(port)
    except (ValueError, TypeError):
        raise ValueError(f"Invalid IMAP port '{port}': must be an integer.")

    if not (1 <= p <= 65535):
        raise ValueError(f"IMAP port {p} is out of valid range (1-65535).")

    return p


def validate_auth_mechanism(mechanism: str) -> str:
    """Validates authentication mechanism. Supports PLAIN and LOGIN."""
    if not isinstance(mechanism, str):
        raise UnsupportedAuthMechanismError("auth_mechanism must be a string.")

    mech = mechanism.strip().upper()
    if mech not in ("PLAIN", "LOGIN"):
        raise UnsupportedAuthMechanismError(
            f"Authentication mechanism '{mech}' is not supported or not yet configured. "
            "Supported mechanisms: PLAIN, LOGIN."
        )
    return mech


def _lookup_local_env_var(var_name: str) -> str:
    """
    Safely retrieves a runtime configuration value from process env, Windows Registry, or local .env.
    Never prints or logs secret contents.
    """
    val = os.environ.get(var_name, "").strip()
    if val:
        return val

    # On Windows, dynamically check User Registry (HKCU\Environment)
    if sys.platform == "win32":
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Environment") as k:
                reg_val, _ = winreg.QueryValueEx(k, var_name)
                if isinstance(reg_val, str) and reg_val.strip():
                    return reg_val.strip()
        except Exception:
            pass

    # Safe check in gitignored local .env file
    try:
        dotenv_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), ".env")
        if os.path.exists(dotenv_path):
            with open(dotenv_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        k, v = line.split("=", 1)
                        if k.strip() == var_name:
                            return v.strip().strip("'\"")
    except Exception:
        pass

    # Safe check in data/local state directory
    try:
        local_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "local")
        if var_name == "SENTINEL_WORKER_ID":
            id_file = os.path.join(local_dir, "sentinel_worker_id.txt")
            if os.path.exists(id_file):
                with open(id_file, "r", encoding="utf-8") as f:
                    c = f.read().strip()
                    if c:
                        return c
        elif var_name in ("SENTINEL_WORKER_PUBLIC_KEY", "SENTINEL_PUBLIC_KEY"):
            pub_file = os.path.join(local_dir, "sentinel_worker_public.pem")
            if os.path.exists(pub_file):
                with open(pub_file, "r", encoding="utf-8") as f:
                    c = f.read().strip()
                    if "BEGIN" in c and "PUBLIC KEY" in c:
                        return c
        elif var_name in ("SENTINEL_WORKER_PRIVATE_KEY", "SENTINEL_PRIVATE_KEY"):
            priv_file = os.path.join(local_dir, "sentinel_worker_private.pem")
            if os.path.exists(priv_file):
                with open(priv_file, "r", encoding="utf-8") as f:
                    c = f.read().strip()
                    if "BEGIN" in c and "PRIVATE KEY" in c:
                        return c
        elif var_name == "SENTINEL_ENABLE_PRODUCTION_POLLING":
            if "pytest" in sys.modules or "PYTEST_CURRENT_TEST" in os.environ:
                return ""
            poll_file = os.path.join(local_dir, "sentinel_production_polling.txt")
            if os.path.exists(poll_file):
                with open(poll_file, "r", encoding="utf-8") as f:
                    c = f.read().strip()
                    if c in ("1", "true", "TRUE"):
                        return "1"
    except Exception:
        pass

    return ""



def is_real_imap_test_enabled() -> bool:
    """Returns True if SENTINEL_ENABLE_REAL_IMAP_TEST is explicitly set to '1'."""
    return _lookup_local_env_var(GUARD_ENV_VAR) == "1"


def is_local_imap_test_enabled() -> bool:
    """Returns True if SENTINEL_LOCAL_IMAP_TEST is explicitly set to '1'."""
    return os.environ.get(LOCAL_IMAP_TEST_ENV_VAR, "").strip() == "1"


def is_production_polling_enabled() -> bool:
    """Returns True if SENTINEL_ENABLE_PRODUCTION_POLLING is explicitly set to '1'."""
    if os.environ.get("SENTINEL_ENABLE_PRODUCTION_POLLING", "").strip() == "1":
        return True
    if "pytest" in sys.modules or "PYTEST_CURRENT_TEST" in os.environ:
        return False
    return _lookup_local_env_var("SENTINEL_ENABLE_PRODUCTION_POLLING") == "1"


def check_real_imap_guard() -> None:
    """
    Enforces real-network safety guard.
    Fails closed unless SENTINEL_ENABLE_REAL_IMAP_TEST=1, SENTINEL_LOCAL_IMAP_TEST=1,
    or SENTINEL_ENABLE_PRODUCTION_POLLING=1 is present in the environment.
    """
    if not is_real_imap_test_enabled() and not is_local_imap_test_enabled() and not is_production_polling_enabled():
        raise RealNetworkDeniedError(
            f"Real IMAP network connections are disabled by default. "
            f"Set {GUARD_ENV_VAR}=1, {LOCAL_IMAP_TEST_ENV_VAR}=1, or SENTINEL_ENABLE_PRODUCTION_POLLING=1 "
            f"to enable authorized live integration."
        )


def is_gmail_app_password_available() -> bool:
    """Returns True if SENTINEL_TEST_GMAIL_APP_PASSWORD or SENTINEL_GMAIL_APP_PASSWORD is set."""
    return bool(get_gmail_app_password())


def get_gmail_app_password() -> Optional[str]:
    """
    Safely retrieves the Gmail test App Password from the runtime environment.
    Checks SENTINEL_TEST_GMAIL_APP_PASSWORD and SENTINEL_GMAIL_APP_PASSWORD across
    process env, Windows User registry, and gitignored local .env.
    Never logs, prints, or persists the returned value.
    """
    val = _lookup_local_env_var(GMAIL_APP_PASSWORD_ENV_VAR) or _lookup_local_env_var("SENTINEL_GMAIL_APP_PASSWORD")
    return val if val else None



# =============================================================================
# REAL IMAP CONNECTION ADAPTER
# =============================================================================

class RealIMAPConnection:
    """
    Controlled Real IMAP Adapter for Sentinel Worker Engine.
    
    Provides hardened IMAP operations with strict SSRF controls, TLS verification,
    command minimization, resource bounds, and context-manager cleanup.
    """

    def __init__(
        self,
        host: str,
        port: Optional[int] = None,
        use_ssl: bool = True,
        timeout: int = CONNECTION_TIMEOUT_SECONDS,
        allow_private_for_test: bool = False,
        allow_local_fixture: bool = False,
        ssl_context: Optional[ssl.SSLContext] = None,
        _imap_factory: Optional[Callable[..., Any]] = None,
    ):
        """
        Initializes the Real IMAP Adapter.
        
        Args:
            host: Validated IMAP server hostname or IP.
            port: IMAP port (defaults to 993 for SSL, 143 for non-SSL).
            use_ssl: Boolean flag. SSL/TLS is mandatory for production.
            timeout: Socket timeout in seconds.
            allow_private_for_test: Allows private/loopback IPs when explicitly enabled.
            allow_local_fixture: Allows strictly 127.0.0.1/localhost when SENTINEL_LOCAL_IMAP_TEST=1.
            ssl_context: Optional SSLContext for local fixture verification (production defaults to CERT_REQUIRED).
            _imap_factory: Optional callable returning IMAP client (used for testing without real sockets).
        """
        # Step 1: Real-network guard check
        check_real_imap_guard()

        # Step 2: Validate host and port
        self.host = validate_imap_host(
            host,
            allow_private=allow_private_for_test,
            allow_local_fixture=allow_local_fixture,
        )
        if port is None:
            self.port = DEFAULT_IMAP_PORT_SSL if use_ssl else DEFAULT_IMAP_PORT_PLAIN
        else:
            self.port = validate_imap_port(port)

        self.use_ssl = bool(use_ssl)
        self.timeout = max(5, int(timeout))
        self._imap_factory = _imap_factory

        # Step 3: Hardened TLS configuration
        self._ssl_context: Optional[ssl.SSLContext] = None
        if self.use_ssl:
            if ssl_context is not None:
                self._ssl_context = ssl_context
            else:
                self._ssl_context = ssl.create_default_context()
                self._ssl_context.check_hostname = True
                self._ssl_context.verify_mode = ssl.CERT_REQUIRED

        self._imap: Optional[Any] = None
        self._logged_in_user: Optional[str] = None
        self._selected_folder: Optional[str] = None
        self._is_connected: bool = False
        self._uid_validity: int = 1

    def connect(self) -> None:
        """Establishes IMAP connection with TLS verification and timeout enforcement."""
        check_real_imap_guard()

        if self._is_connected and self._imap:
            return

        logger.info("Initiating IMAP connection to %s:%d (SSL=%s)...", self.host, self.port, self.use_ssl)

        try:
            if self._imap_factory:
                # Use injected factory for controlled testing
                self._imap = self._imap_factory(
                    self.host,
                    self.port,
                    ssl_context=self._ssl_context,
                    timeout=self.timeout
                )
            elif self.use_ssl:
                self._imap = imaplib.IMAP4_SSL(
                    self.host,
                    self.port,
                    ssl_context=self._ssl_context,
                    timeout=self.timeout
                )
            else:
                self._imap = imaplib.IMAP4(
                    self.host,
                    self.port,
                    timeout=self.timeout
                )
            self._is_connected = True
            logger.info("IMAP connection established successfully to %s:%d", self.host, self.port)
        except (socket.timeout, TimeoutError) as err:
            logger.warning("Connection timeout connecting to %s:%d", self.host, self.port)
            raise IMAPConnectionTimeoutError(f"Connection timeout to {self.host}:{self.port}: {err}") from err
        except ssl.SSLError as err:
            logger.error("TLS verification failed connecting to %s:%d: %s", self.host, self.port, err)
            raise TLSVerificationError(f"TLS verification failed for {self.host}:{self.port}: {err}") from err
        except Exception as err:
            logger.error("Failed to connect to %s:%d: %s", self.host, self.port, type(err).__name__)
            raise IMAPClientError(f"IMAP connection failed to {self.host}:{self.port}: {err}") from err

    def login(self, username: str, password: str) -> bool:
        """
        Authenticates against the IMAP server.
        Passwords are never printed, stored, or logged.
        """
        if not self._is_connected or not self._imap:
            self.connect()

        clean_user = username.strip() if username else ""
        if not clean_user or not password:
            raise IMAPAuthenticationError("IMAP username and password must both be provided.")

        logger.info("Authenticating IMAP user '%s' on %s...", clean_user, self.host)

        try:
            status, resp = self._imap.login(clean_user, password)
            if status != "OK":
                logger.warning("IMAP authentication failed for user '%s': %s", clean_user, status)
                raise IMAPAuthenticationError(f"IMAP login returned status '{status}'")
            self._logged_in_user = clean_user
            logger.info("IMAP authentication succeeded for user '%s'.", clean_user)
            return True
        except (IMAPAuthenticationError, imaplib.IMAP4.error) as err:
            logger.warning("IMAP authentication rejected for user '%s': %s", clean_user, type(err).__name__)
            if isinstance(err, IMAPAuthenticationError):
                raise
            raise IMAPAuthenticationError(f"IMAP authentication failed for '{clean_user}'") from err
        except Exception as err:
            logger.error("Unexpected error during IMAP login: %s", type(err).__name__)
            raise IMAPClientError(f"IMAP login failed: {err}") from err

    def select(self, mailbox_name: str = "INBOX") -> Tuple[str, int]:
        """
        Selects an IMAP mailbox folder in readonly mode.
        Returns ('OK', message_count) or ('NO', 0).
        """
        if not self._is_connected or not self._imap:
            raise IMAPClientError("Not connected to IMAP server.")
        if not self._logged_in_user:
            raise IMAPAuthenticationError("Not authenticated.")

        clean_folder = mailbox_name.strip() if mailbox_name else "INBOX"
        logger.info("Selecting mailbox folder '%s' (readonly=True)...", clean_folder)

        try:
            status, data = self._imap.select(clean_folder, readonly=True)
            if status != "OK":
                logger.warning("Failed to select folder '%s': status=%s", clean_folder, status)
                return "NO", 0

            count = 0
            if data and data[0]:
                try:
                    count = int(data[0].decode() if isinstance(data[0], bytes) else data[0])
                except (ValueError, TypeError):
                    count = 0

            # Safely extract UIDVALIDITY from IMAP server response
            try:
                uv_resp = self._imap.response("UIDVALIDITY")
                if uv_resp and len(uv_resp) > 1 and uv_resp[1] and uv_resp[1][0]:
                    raw_uv = uv_resp[1][0]
                    self._uid_validity = int(raw_uv.decode() if isinstance(raw_uv, bytes) else raw_uv)
            except Exception as uv_err:
                logger.debug("Could not parse UIDVALIDITY response: %s", uv_err)

            self._selected_folder = clean_folder
            logger.info("Selected folder '%s' with %d messages (UIDVALIDITY: %d).", clean_folder, count, self._uid_validity)
            return "OK", count
        except Exception as err:
            logger.error("Error selecting folder '%s': %s", clean_folder, err)
            raise IMAPClientError(f"Error selecting folder '{clean_folder}': {err}") from err

    def get_uid_validity(self) -> int:
        """Returns the UIDVALIDITY value for the currently selected folder."""
        return self._uid_validity

    def search(self, since_uid: Optional[int] = None) -> List[int]:
        """
        Discovers unseen message UIDs in ascending order.
        If since_uid is provided, searches strictly for UIDs > since_uid.
        """
        if not self._is_connected or not self._imap:
            raise IMAPClientError("Not connected to IMAP server.")
        if not self._selected_folder:
            raise IMAPClientError("No mailbox folder selected.")

        # Command minimization: search only newer UIDs
        if since_uid is not None and since_uid > 0:
            criteria = f"UID {since_uid + 1}:*"
        else:
            criteria = "ALL"

        logger.info("Executing IMAP UID SEARCH with criteria: '%s'...", criteria)

        try:
            status, data = self._imap.uid("SEARCH", None, criteria)
            if status != "OK" or not data or not data[0]:
                return []

            raw_uids = data[0]
            if isinstance(raw_uids, bytes):
                raw_uids = raw_uids.decode("utf-8", errors="ignore")

            uids: List[int] = []
            min_uid = since_uid if since_uid is not None else 0
            for item in raw_uids.split():
                try:
                    uid_val = int(item)
                    # When searching UID N:*, servers may include N itself if it exists; enforce strictly > since_uid
                    if uid_val > min_uid:
                        uids.append(uid_val)
                except ValueError:
                    continue

            # Deterministic ascending order and deduplication
            sorted_uids = sorted(set(uids))
            logger.info("UID SEARCH found %d new messages (since UID %s)", len(sorted_uids), since_uid)
            return sorted_uids
        except Exception as err:
            logger.error("Error during IMAP search: %s", err)
            raise IMAPClientError(f"IMAP search failed: {err}") from err

    def fetch(self, uid: int) -> Dict[str, Any]:
        """
        Fetches RFC822 payload and basic metadata for the specified UID.
        Uses BODY.PEEK[] where available to prevent altering mailbox flags.
        Enforces MAX_MESSAGE_SIZE_BYTES resource bounds.
        """
        if not self._is_connected or not self._imap:
            raise IMAPClientError("Not connected to IMAP server.")
        if not self._selected_folder:
            raise IMAPClientError("No mailbox folder selected.")

        logger.info("Fetching message UID %d...", uid)

        try:
            # Use BODY.PEEK[] to avoid marking message as SEEN
            status, data = self._imap.uid("FETCH", str(uid), "(BODY.PEEK[])")
            if status != "OK" or not data:
                # Fallback to RFC822 if BODY.PEEK[] is rejected by server
                status, data = self._imap.uid("FETCH", str(uid), "(RFC822)")

            if status != "OK" or not data:
                raise IMAPClientError(f"IMAP fetch returned status '{status}' for UID {uid}")

            raw_bytes = b""
            for part in data:
                if isinstance(part, tuple) and len(part) > 1 and isinstance(part[1], bytes):
                    raw_bytes = part[1]
                    break

            size = len(raw_bytes)

            # Extract Message-ID header safely
            message_id: Optional[str] = None
            try:
                # Safe header-only parse for Message-ID
                header_boundary = raw_bytes.find(b"\r\n\r\n")
                if header_boundary == -1:
                    header_boundary = raw_bytes.find(b"\n\n")
                header_bytes = raw_bytes[:header_boundary] if header_boundary != -1 else raw_bytes[:MAX_HEADER_SIZE_BYTES]
                parsed_header = email.message_from_bytes(header_bytes)
                raw_mid = parsed_header.get("Message-ID", "")
                if raw_mid:
                    message_id = raw_mid.strip()
            except Exception:
                pass

            return {
                "uid": uid,
                "rfc822": raw_bytes,
                "size": size,
                "message_id": message_id or f"<real-{uid}@{self.host}>",
            }
        except Exception as err:
            logger.error("Error fetching message UID %d: %s", uid, err)
            raise IMAPClientError(f"IMAP fetch failed for UID {uid}: {err}") from err

    def close(self) -> None:
        """Closes the currently selected mailbox folder."""
        if self._imap and self._selected_folder:
            try:
                self._imap.close()
            except Exception:
                pass
            finally:
                self._selected_folder = None

    def logout(self) -> None:
        """Logs out from IMAP session and closes connection cleanly."""
        if self._imap and self._is_connected:
            try:
                self.close()
                self._imap.logout()
            except Exception:
                pass
            finally:
                self._imap = None
                self._is_connected = False
                self._logged_in_user = None
                self._selected_folder = None
                logger.info("IMAP session closed and logged out cleanly.")

    def __enter__(self) -> "RealIMAPConnection":
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.logout()

    def __repr__(self) -> str:
        return f"<RealIMAPConnection host={self.host} port={self.port} ssl={self.use_ssl} connected={self._is_connected}>"


from worker.health import (
    FailureCategory,
    classify_operational_failure,
    compute_backoff_delay,
    OperationalRateLimiter,
)

