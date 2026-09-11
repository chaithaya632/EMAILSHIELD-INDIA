import imaplib
import email
import email.policy
import datetime
import re
import socket
from typing import Dict, Any, List, Optional, Tuple

PROVIDER_CONFIGS = {
    "Gmail": {"host": "imap.gmail.com", "port": 993},
    "Outlook / Office 365": {"host": "outlook.office365.com", "port": 993},
    "Yahoo Mail": {"host": "imap.mail.yahoo.com", "port": 993},
    "Zoho Mail": {"host": "imap.zoho.com", "port": 993},
    "Custom / Corporate": {"host": "", "port": 993}
}

# 15s default network socket timeout to guarantee the app never hangs
socket.setdefaulttimeout(15.0)

def get_provider_host(provider_name: str, email_addr: str = "") -> str:
    """Resolve standard IMAP host with intelligent regional routing for Zoho."""
    if provider_name == "Zoho Mail":
        clean_email = email_addr.strip().lower()
        if clean_email.endswith(".in") or "@zoho.in" in clean_email:
            return "imap.zoho.in"
        return "imap.zoho.com"
    return PROVIDER_CONFIGS.get(provider_name, {}).get("host", "")

def test_imap_connection(email_addr: str, password: str, host: str, port: int = 993) -> Tuple[bool, str]:
    """Test connection and credentials against an IMAP server with a 10s timeout."""
    hosts_to_try = [host] if host else []
    if "zoho" in (host or "").lower() or "zoho" in email_addr.lower():
        for candidate in ["imap.zoho.com", "imap.zoho.in", "imappro.zoho.com"]:
            if candidate not in hosts_to_try:
                hosts_to_try.append(candidate)

    if not hosts_to_try:
        hosts_to_try = [host]

    last_err = ""
    for try_host in hosts_to_try:
        try:
            mail = imaplib.IMAP4_SSL(try_host, port, timeout=10.0)
            clean_pwd = password.replace(" ", "").strip()
            mail.login(email_addr.strip(), clean_pwd)
            try:
                mail.logout()
            except Exception:
                pass
            return True, "Authentication successful! Connected to mailbox."
        except Exception as e:
            last_err = str(e)

    return False, f"Connection error: {last_err}"

def fetch_imap_emails(
    email_addr: str,
    password: str,
    host: str,
    port: int = 993,
    max_results: Optional[int] = 50,
    query: Optional[str] = None
) -> List[Dict[str, str]]:
    """
    Fetches emails from INBOX via standard IMAP using lightning-fast range queries.
    Uses BODY.PEEK to fetch only header metadata without marking emails as read.
    Guaranteed non-blocking with socket timeouts and contiguous range optimization.
    """
    clean_pwd = password.replace(" ", "").strip()
    mail = imaplib.IMAP4_SSL(host, port, timeout=15.0)
    try:
        mail.login(email_addr.strip(), clean_pwd)
        status, select_data = mail.select("INBOX", readonly=True)
        if status != "OK":
            return []

        # Search criteria
        search_criteria = "ALL"
        if query and "newer_than:1d" in query:
            since_date = (datetime.date.today() - datetime.timedelta(days=1)).strftime("%d-%b-%Y")
            search_criteria = f'(SINCE "{since_date}")'

        status, messages = mail.search(None, search_criteria)
        if (status != "OK" or not messages or not messages[0]) and search_criteria != "ALL":
            # Fallback to ALL if date search yielded nothing
            status, messages = mail.search(None, "ALL")

        if status != "OK" or not messages or not messages[0]:
            return []

        msg_ids = messages[0].split()
        if not msg_ids:
            return []

        # Safe limit cap to prevent browser/thread freeze on massive inboxes
        effective_limit = max_results if (max_results and max_results > 0) else 50
        effective_limit = min(effective_limit, 300)

        # Take the most recent messages (which are at the end of msg_ids) in ascending order
        target_ids = msg_ids[-effective_limit:]
        if not target_ids:
            return []

        results_map: Dict[str, Dict[str, str]] = {}

        # Check if contiguous sequence numbers (standard for ALL search)
        first_id = int(target_ids[0])
        last_id = int(target_ids[-1])
        is_contiguous = (last_id - first_id + 1 == len(target_ids))

        if is_contiguous:
            # Single ultra-fast range fetch: e.g. "951:1000" in 1 roundtrip
            range_str = f"{first_id}:{last_id}"
            try:
                res, data = mail.fetch(range_str, '(BODY.PEEK[HEADER.FIELDS (SUBJECT FROM DATE)])')
                if res == "OK" and data:
                    _parse_fetch_items(data, results_map)
            except Exception:
                pass
        else:
            # Non-contiguous IDs: chunk in ascending batches of 50
            chunk_size = 50
            for i in range(0, len(target_ids), chunk_size):
                chunk = target_ids[i:i + chunk_size]
                try:
                    chunk_set = b','.join(chunk)
                    res, data = mail.fetch(chunk_set, '(BODY.PEEK[HEADER.FIELDS (SUBJECT FROM DATE)])')
                    if res == "OK" and data:
                        _parse_fetch_items(data, results_map)
                except Exception:
                    continue

        # Reassemble in reverse chronological order (newest emails first)
        results = []
        for mid in target_ids[::-1]:
            mid_str = mid.decode('utf-8', errors='ignore')
            if mid_str in results_map:
                results.append(results_map[mid_str])

        return results

    finally:
        try:
            mail.logout()
        except Exception:
            pass

def _parse_fetch_items(data: list, out_map: Dict[str, Dict[str, str]]) -> None:
    """Helper to parse IMAP tuple responses into clean header dictionaries."""
    for item in data:
        if isinstance(item, tuple) and len(item) == 2:
            try:
                meta_line = item[0].decode('utf-8', errors='ignore')
                match = re.match(r'^\s*(\d+)', meta_line)
                if not match:
                    continue
                mid_str = match.group(1)
                raw_header = item[1]
                msg_obj = email.message_from_bytes(raw_header, policy=email.policy.default)
                
                subject = str(msg_obj.get("Subject", "No Subject")).strip() or "No Subject"
                sender = str(msg_obj.get("From", "Unknown Sender")).strip() or "Unknown Sender"
                date_val = str(msg_obj.get("Date", "Unknown Date")).strip() or "Unknown Date"

                out_map[mid_str] = {
                    "id": mid_str,
                    "snippet": subject[:60],
                    "subject": subject,
                    "sender": sender,
                    "date": date_val
                }
            except Exception:
                continue

def fetch_imap_raw_email(
    email_addr: str,
    password: str,
    host: str,
    port: int = 993,
    msg_id: str = "1"
) -> bytes:
    """Fetches the complete raw RFC822 bytes of a specific email by ID with a 15s timeout."""
    clean_pwd = password.replace(" ", "").strip()
    mail = imaplib.IMAP4_SSL(host, port, timeout=15.0)
    try:
        mail.login(email_addr.strip(), clean_pwd)
        mail.select("INBOX", readonly=True)
        res, data = mail.fetch(msg_id.encode('utf-8'), '(RFC822)')
        if res == "OK" and data:
            for response_part in data:
                if isinstance(response_part, tuple):
                    return response_part[1]
        return b""
    finally:
        try:
            mail.logout()
        except Exception:
            pass
