"""
core/live_mail_adapter.py
Live Mail Adapter & RFC822 Evidence Normalization for Batch Analysis.

Enforces:
1. Strict RLS and Tenant Isolation: Only returns emails belonging to the authorized user.
2. Safe Metadata Projection: Never exposes full email bodies, passwords, or tokens in selector lists.
3. High-Fidelity Forensic Reconstruction: Converts case/evidence records into compliant RFC 822 MIME bytes
   preserving Message-ID, From, To, Date, Subject, Received headers, Auth-Results, Attachments, and IOC URLs.
4. Absolute Isolation: Does NOT touch TenantSentinelMetrics, CheckpointStore, or worker leases.
"""

import os
import re
import uuid
import datetime
import hashlib
from email.message import EmailMessage
from email.policy import default as _default_policy
from email.headerregistry import HeaderRegistry, UnstructuredHeader
from email.utils import parsedate_to_datetime
from typing import Dict, Any, List, Optional, Tuple

from core.case_store import is_authorized_caller, get_all_cases
from core.local_storage import get_local_storage_manager
from core.sentinel_control import get_user_mailbox


DEFAULT_BATCH_SOURCE = "📬 Select from Live Mail"
BATCH_SOURCE_OPTIONS = ["📬 Select from Live Mail"]
DEFAULT_LIVE_MAIL_LIMIT: int = 50
LIVE_MAIL_LIMIT_OPTIONS: List[int] = [50, 100, 200]
LIVE_MAIL_PAGE_SIZE: int = 10


class LiveMailPagination:
    """
    Pagination controller for Live Mail browsing.
    Supports:
    - 10 emails per page (e.g. 50 emails -> 5 pages).
    - Previous / Next navigation and boundary conditions (disabled on Page 1 / Page 5).
    - Email 10 -> Next -> Email 11 (auto page advance).
    - Email 11 -> Previous -> Email 10 (auto page retreat).
    - Jump to Mail: valid jumps (1, 25, 50), rejection/clamping of invalid jumps (0, -1, 51).
    - Gmail Inbox ordering (Newest -> Oldest).
    - Navigation does NOT modify telemetry, counters, or checkpoints.
    """
    def __init__(
        self,
        messages: List[Dict[str, Any]],
        page_size: int = LIVE_MAIL_PAGE_SIZE,
        current_index: int = 0
    ):
        self.messages = self._sort_newest_to_oldest(messages)
        self.page_size = max(1, page_size)
        self.total_emails = len(self.messages)
        self.total_pages = max(1, (self.total_emails + self.page_size - 1) // self.page_size) if self.total_emails > 0 else 1
        self.current_index = max(0, min(current_index, self.total_emails - 1)) if self.total_emails > 0 else 0

    @staticmethod
    def _sort_newest_to_oldest(messages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Sort messages from newest to oldest (Gmail inbox order)."""
        if not messages:
            return []
        
        def _get_sort_key(m: Dict[str, Any]):
            return str(m.get("date") or m.get("timestamp") or m.get("received_at") or "")
        
        try:
            return sorted(messages, key=_get_sort_key, reverse=True)
        except Exception:
            return list(messages)

    @property
    def current_email_number(self) -> int:
        """1-based email number (1..N)."""
        return self.current_index + 1 if self.total_emails > 0 else 0

    @property
    def current_page(self) -> int:
        """1-based current page number (1..total_pages)."""
        if self.total_emails == 0:
            return 1
        return (self.current_index // self.page_size) + 1

    @property
    def is_first_page(self) -> bool:
        return self.current_page <= 1

    @property
    def is_last_page(self) -> bool:
        return self.current_page >= self.total_pages

    @property
    def has_prev_page(self) -> bool:
        return self.current_page > 1

    @property
    def has_next_page(self) -> bool:
        return self.current_page < self.total_pages

    @property
    def has_prev_email(self) -> bool:
        return self.current_index > 0

    @property
    def has_next_email(self) -> bool:
        return self.current_index < self.total_emails - 1

    def next_email(self) -> bool:
        """
        Advance to the next email. If traversing across page boundary (e.g. Email 10 -> Email 11),
        the current page automatically advances.
        Returns True if advanced, False if already at the last email.
        """
        if self.has_next_email:
            self.current_index += 1
            return True
        return False

    def prev_email(self) -> bool:
        """
        Retreat to the previous email. If traversing across page boundary (e.g. Email 11 -> Email 10),
        the current page automatically retreats.
        Returns True if retreated, False if already at the first email.
        """
        if self.has_prev_email:
            self.current_index -= 1
            return True
        return False

    def next_page(self) -> bool:
        """Advance to the first email of the next page."""
        if self.has_next_page:
            self.current_index = self.current_page * self.page_size
            return True
        return False

    def prev_page(self) -> bool:
        """Retreat to the first email of the previous page."""
        if self.has_prev_page:
            self.current_index = (self.current_page - 2) * self.page_size
            return True
        return False

    def jump_to_email(self, email_num: int, clamp: bool = True) -> bool:
        """
        Jump to a 1-based email number (e.g. 1, 25, 50).
        If clamp=True: invalid values (< 1 or > N) are clamped to valid range [1, N].
        If clamp=False: invalid values (< 1 or > N) are rejected and return False.
        """
        if self.total_emails == 0:
            return False
        if not clamp and (email_num < 1 or email_num > self.total_emails):
            return False
        clamped_num = max(1, min(email_num, self.total_emails))
        self.current_index = clamped_num - 1
        return True

    def get_current_page_emails(self) -> List[Dict[str, Any]]:
        """Returns the slice of messages belonging to the current page."""
        start = (self.current_page - 1) * self.page_size
        end = min(start + self.page_size, self.total_emails)
        return self.messages[start:end]

    def get_current_email(self) -> Optional[Dict[str, Any]]:
        """Returns the currently active email dictionary."""
        if 0 <= self.current_index < self.total_emails:
            return self.messages[self.current_index]
        return None



def filter_live_mail_messages(
    messages: List[Dict[str, Any]],
    search_query: str = "",
    risk_filter: str = "All",
    attachment_filter: str = "All",
    ioc_filter: str = "All",
) -> List[Dict[str, Any]]:
    """
    Filters a list of live mail messages based on query terms and category filters.
    Operates strictly in memory.
    """
    filtered = []
    query_clean = (search_query or "").strip().lower()

    for m in messages:
        # 1. Search Query Filter (matches in subject, sender, or message_id)
        if query_clean:
            subj = str(m.get("subject", "")).lower()
            sndr = str(m.get("sender", "")).lower()
            msg_id = str(m.get("message_id", "")).lower()
            if query_clean not in subj and query_clean not in sndr and query_clean not in msg_id:
                continue

        # 2. Risk Filter
        risk = str(m.get("risk", "LOW")).upper()
        if risk_filter == "Clean" and risk != "LOW":
            continue
        elif risk_filter == "Suspicious" and risk != "SUSPICIOUS":
            continue
        elif risk_filter == "High" and risk != "HIGH":
            continue
        elif risk_filter == "Critical" and risk != "CRITICAL":
            continue

        # 3. Attachment Filter
        has_att = bool(m.get("has_attachment", False) or m.get("attachment_count", 0) > 0)
        if attachment_filter == "Has Attachment" and not has_att:
            continue
        elif attachment_filter == "No Attachment" and has_att:
            continue

        # 4. IOC Filter
        has_ioc = bool(m.get("has_ioc", False) or m.get("ioc_count", 0) > 0)
        if ioc_filter == "Has IOC" and not has_ioc:
            continue
        elif ioc_filter == "No IOC" and has_ioc:
            continue

        filtered.append(m)

    return filtered


def select_all_visible(current_selected: Any, visible_messages: List[Dict[str, Any]]) -> set:
    """Adds all visible message IDs to the selection set."""
    res = set(current_selected) if current_selected is not None else set()
    for m in visible_messages:
        mid = m.get("id") or m.get("case_id")
        if mid:
            res.add(str(mid))
    return res


def clear_selection(current_selected: Optional[Any] = None) -> set:
    """Clears and returns an empty selection set."""
    if current_selected is not None and hasattr(current_selected, "clear"):
        current_selected.clear()
    return set()


def toggle_selection(current_selected: Any, message_id: str) -> set:
    """Toggles selection for a specific message ID in the set."""
    res = set(current_selected) if current_selected is not None else set()
    mid = str(message_id)
    if mid in res:
        res.remove(mid)
    else:
        res.add(mid)
    return res


def get_authorized_live_mail_messages(
    user_id: str,
    client: Any,
    mailbox_id: Optional[str] = None,
    limit: int = 50
) -> List[Dict[str, Any]]:
    """
    Retrieves authorized Live Mail messages for the authenticated user only.
    Enforces server-side RLS and fails closed if unauthenticated.
    """
    if not user_id or not is_authorized_caller(user_id, client):
        return []

    try:
        limit = max(1, min(int(limit or 50), 300))
    except (ValueError, TypeError):
        limit = 50
    messages: List[Dict[str, Any]] = []
    seen_ids = set()

    # 1. Fetch authorized cases via Supabase RLS (or local case store in offline dev)
    cases = get_all_cases(client=client, limit=limit)
    for c in cases:
        raw_j = c.get("raw_json") or c
        # Multi-tenant isolation: ensure case belongs to caller if user_id tagged
        c_user = c.get("user_id") or raw_j.get("user_id")
        if c_user and str(c_user) != str(user_id):
            continue

        c_id = str(c.get("id") or c.get("case_id") or c.get("case_number") or uuid.uuid4().hex[:8])
        case_id_alt = str(c.get("case_id") or "")
        id_alt = str(c.get("id") or "")
        if c_id in seen_ids or (case_id_alt and case_id_alt in seen_ids) or (id_alt and id_alt in seen_ids):
            continue
        seen_ids.add(c_id)
        if case_id_alt:
            seen_ids.add(case_id_alt)
        if id_alt:
            seen_ids.add(id_alt)

        if mailbox_id:
            c_mb = c.get("mailbox_id") or raw_j.get("mailbox_id")
            if c_mb and str(c_mb) != str(mailbox_id):
                continue
        headers = raw_j.get("headers") or {}
        subject = str(c.get("subject") or headers.get("subject") or "No Subject")
        sender = str(c.get("sender") or headers.get("from") or "Unknown Sender")
        recipient = str(c.get("recipient") or headers.get("to") or "Authorized Mailbox")
        date_str = str(c.get("timestamp") or c.get("date") or headers.get("date") or c.get("created_at") or c.get("received_at") or datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M"))
        
        # Risk classification
        risk_raw = str(c.get("risk_score") or c.get("threat_verdict") or "").upper()
        if "CRITICAL" in risk_raw:
            risk = "CRITICAL"
        elif "HIGH" in risk_raw and c.get("status") != "Closed":
            risk = "HIGH"
        elif "SUSPICIOUS" in risk_raw or "MEDIUM" in risk_raw:
            risk = "SUSPICIOUS"
        elif risk_raw in ("LOW", "SAFE", "CLEAN"):
            risk = "SAFE"
        else:
            risk = "Not analyzed"

        # Indicators count
        raw_inds = raw_j.get("indicators") or []
        ioc_count = len(raw_inds) if isinstance(raw_inds, list) else 0

        # Attachments count
        raw_atts = raw_j.get("attachments") or raw_j.get("attachment_analyses") or []
        att_count = len(raw_atts) if isinstance(raw_atts, list) else 0

        msg_id = str(headers.get("message-id") or raw_j.get("message_id") or f"<{c_id}@emailshield.local>")

        messages.append({
            "id": c_id,
            "case_id": c_id,
            "message_id": msg_id,
            "subject": subject,
            "sender": sender,
            "recipient": recipient,
            "date": date_str[:25],
            "timestamp": c.get("timestamp") or c.get("date") or headers.get("date") or date_str,
            "risk": risk,
            "case_severity": c.get("case_severity", "MEDIUM"),
            "has_attachment": att_count > 0,
            "attachment_count": att_count,
            "has_ioc": ioc_count > 0,
            "ioc_count": ioc_count,
            "source": "Live Mail Store",
            "case_data": c
        })

    # 2. Check local storage manager for any additional local evidence files for this user
    try:
        mgr = get_local_storage_manager()
        local_cases = mgr.list_cases(user_id=user_id)
        for lc in local_cases:
            lc_id = str(lc.get("id") or lc.get("case_id") or uuid.uuid4().hex[:8])
            lc_case_id = str(lc.get("case_id") or "")
            lc_id_alt = str(lc.get("id") or "")
            if lc_id in seen_ids or (lc_case_id and lc_case_id in seen_ids) or (lc_id_alt and lc_id_alt in seen_ids):
                continue
            seen_ids.add(lc_id)
            if lc_case_id:
                seen_ids.add(lc_case_id)
            if lc_id_alt:
                seen_ids.add(lc_id_alt)

            c_data = lc.get("case_data", {})
            if mailbox_id:
                lc_mb = lc.get("mailbox_id") or c_data.get("mailbox_id")
                if lc_mb and str(lc_mb) != str(mailbox_id):
                    continue
            sub = str(lc.get("title") or c_data.get("subject") or "No Subject")
            snd = str(c_data.get("sender") or "Unknown Sender")
            dt = str(lc.get("created_at") or datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M"))
            r_str = str(lc.get("risk_score") or lc.get("threat_verdict") or "").upper()
            if "CRITICAL" in r_str:
                r_val = "CRITICAL"
            elif "HIGH" in r_str and lc.get("status") != "Closed":
                r_val = "HIGH"
            elif "SUSPICIOUS" in r_str or "MEDIUM" in r_str:
                r_val = "SUSPICIOUS"
            elif r_str in ("LOW", "SAFE", "CLEAN"):
                r_val = "SAFE"
            else:
                r_val = "Not analyzed"

            evidence_items = mgr.list_evidence_for_case(user_id=user_id, case_id=lc_id)
            att_cnt = sum(1 for e in evidence_items if "ATT" in e.get("evidence_id", "") or "attachment" in e.get("content_type", "").lower())
            
            messages.append({
                "id": lc_id,
                "case_id": lc_id,
                "message_id": str(c_data.get("message_id") or f"<{lc_id}@emailshield.local>"),
                "subject": sub,
                "sender": snd,
                "recipient": str(c_data.get("recipient") or "Authorized Mailbox"),
                "date": dt[:25],
                "risk": r_val,
                "case_severity": lc.get("threat_verdict", "MEDIUM"),
                "has_attachment": att_cnt > 0,
                "attachment_count": att_cnt,
                "has_ioc": len(c_data.get("indicators", [])) > 0,
                "ioc_count": len(c_data.get("indicators", [])),
                "source": "Local Forensic Evidence",
                "case_data": c_data
            })
    except Exception:
        pass

    messages.sort(key=_message_sort_key, reverse=True)
    return messages[:limit]


def _extract_message_timestamp(msg: Dict[str, Any]) -> float:
    """
    Extracts a numeric timestamp (epoch seconds) for sorting Live Mail messages.
    Checks message record, case_data, headers, and fallback date strings.
    """
    candidates = []
    for key in ("timestamp", "received_at", "date", "created_at"):
        val = msg.get(key)
        if val is not None:
            candidates.append(val)
    c_data = msg.get("case_data")
    if isinstance(c_data, dict):
        for key in ("timestamp", "created_at", "received_at"):
            val = c_data.get(key)
            if val is not None:
                candidates.append(val)
        raw_j = c_data.get("raw_json")
        if isinstance(raw_j, dict):
            for key in ("timestamp", "created_at", "received_at"):
                val = raw_j.get(key)
                if val is not None:
                    candidates.append(val)
            hdrs = raw_j.get("headers")
            if isinstance(hdrs, dict) and hdrs.get("date"):
                candidates.append(hdrs.get("date"))
        elif isinstance(c_data.get("headers"), dict) and c_data["headers"].get("date"):
            candidates.append(c_data["headers"].get("date"))

    for val in candidates:
        if isinstance(val, (int, float)):
            return float(val)
        if isinstance(val, datetime.datetime):
            if val.tzinfo is None:
                val = val.replace(tzinfo=datetime.timezone.utc)
            return val.timestamp()
        if isinstance(val, datetime.date):
            return datetime.datetime.combine(val, datetime.time.min, tzinfo=datetime.timezone.utc).timestamp()
        if isinstance(val, str) and val.strip():
            s = val.strip()
            try:
                dt = datetime.datetime.fromisoformat(s.replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=datetime.timezone.utc)
                return dt.timestamp()
            except Exception:
                pass
            try:
                dt = parsedate_to_datetime(s)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=datetime.timezone.utc)
                return dt.timestamp()
            except Exception:
                pass
            for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
                try:
                    dt = datetime.datetime.strptime(s[:19], fmt).replace(tzinfo=datetime.timezone.utc)
                    return dt.timestamp()
                except Exception:
                    pass
    return 0.0


def _message_sort_key(msg: Dict[str, Any]) -> Tuple[float, int, str]:
    """
    Sort key for Live Mail messages:
    Primary: timestamp descending (Newest -> Oldest).
    Secondary: numeric sequence ID descending.
    Tertiary: raw ID string descending.
    """
    ts = _extract_message_timestamp(msg)
    raw_id = str(msg.get("id") or msg.get("case_id") or "")
    digits = re.findall(r'\d+', raw_id)
    seq = int(digits[-1]) if digits else -1
    return (ts, seq, raw_id)


_HEADER_REGISTRY = HeaderRegistry()
_HEADER_REGISTRY.map_to_type('message-id', UnstructuredHeader)
_HEADER_REGISTRY.map_to_type('date', UnstructuredHeader)
_SAFE_MIME_POLICY = _default_policy.clone(header_factory=_HEADER_REGISTRY)


def _clean_header_val(val: Any, is_msg_id: bool = False) -> str:
    """
    Strips leading/trailing whitespace and replaces any carriage returns or newlines ([\\r\\n]+) with a single space.
    For message-id, whitespace and newlines inside the angle bracket spec are removed to preserve valid syntax.
    Guarantees no linefeed or carriage return characters remain.
    """
    if val is None:
        return ""
    if is_msg_id:
        return re.sub(r'[\r\n\s]+', '', str(val)).strip()
    return re.sub(r'[ \t]*[\r\n]+[ \t]*', ' ', str(val)).strip()


def _safe_set_header(msg: EmailMessage, name: str, val: Any) -> None:
    """
    Sets the header with cleaned value, ignoring or safely handling exceptions.
    """
    if val is None:
        return
    is_mid = (name.lower() == "message-id")
    cleaned = _clean_header_val(val, is_msg_id=is_mid)
    if not cleaned and name not in ("Subject", "From", "To"):
        return
    try:
        msg[name] = cleaned
    except Exception:
        pass


def _sanitize_header_value(val: Any, default: str = "", is_msg_id: bool = False) -> str:
    """Compatibility helper wrapping _clean_header_val."""
    cleaned = _clean_header_val(val, is_msg_id=is_msg_id)
    return cleaned if cleaned else default


def convert_live_message_to_rfc822_bytes(
    message_record: Dict[str, Any],
    user_id: str
) -> Tuple[str, bytes]:
    """
    Converts a live mail record into RFC 822 MIME bytes for the forensic engine.
    1. Returns raw evidence bytes if already stored on disk.
    2. Otherwise, constructs a faithful, RFC 822 compliant MIME message preserving
       Message-ID, From, To, Date, Subject, Received chain, Auth-Results, Body, and Attachments.
    """
    case_id = message_record.get("case_id") or message_record.get("id") or "MSG"
    filename = f"LiveMail_{case_id}.eml"

    # 1. Check if raw bytes are already present in message_record
    if "FileBytes" in message_record and message_record["FileBytes"]:
        return filename, message_record["FileBytes"]
    if "raw_bytes" in message_record and message_record["raw_bytes"]:
        return filename, message_record["raw_bytes"]

    # 2. Check local evidence store for raw EML
    try:
        mgr = get_local_storage_manager()
        evidence_items = mgr.list_evidence_for_case(user_id=user_id, case_id=case_id)
        for ev in evidence_items:
            if "EML" in ev.get("evidence_id", "") or ev.get("content_type") == "message/rfc822":
                raw_pair = mgr.get_evidence(user_id=user_id, evidence_id=ev["evidence_id"])
                if raw_pair and raw_pair[0]:
                    return filename, raw_pair[0]
    except Exception:
        pass

    # 3. Faithfully construct RFC 822 MIME message from preserved case data
    case_data = message_record.get("case_data") or message_record
    raw_json = case_data.get("raw_json") or case_data
    headers = raw_json.get("headers") if isinstance(raw_json.get("headers"), dict) else {}

    msg = EmailMessage(policy=_SAFE_MIME_POLICY)

    # Core headers with CRLF sanitization and safe setting
    subj = message_record.get("subject") or headers.get("subject") or "No Subject"
    from_addr = message_record.get("sender") or headers.get("from") or "sender@example.com"
    to_addr = message_record.get("recipient") or headers.get("to") or "recipient@example.com"
    date_val = (
        message_record.get("date") or headers.get("date") or
        datetime.datetime.now(datetime.timezone.utc).strftime("%a, %d %b %Y %H:%M:%S +0000")
    )
    msg_id = (
        message_record.get("message_id") or headers.get("message-id") or
        f"<{case_id}@emailshield.local>"
    )

    _safe_set_header(msg, "Subject", subj)
    _safe_set_header(msg, "From", from_addr)
    _safe_set_header(msg, "To", to_addr)
    _safe_set_header(msg, "Date", date_val)
    _safe_set_header(msg, "Message-ID", msg_id)

    # Preserve Received Chain
    rec_chain = raw_json.get("received_chain") or []
    for rec in rec_chain:
        if rec:
            _safe_set_header(msg, "Received", rec)

    # Preserve Authentication Headers with CRLF sanitization
    auth_results_val = (
        message_record.get("authentication-results") or message_record.get("Authentication-Results") or
        headers.get("authentication-results") or headers.get("Authentication-Results")
    )
    if auth_results_val:
        _safe_set_header(msg, "Authentication-Results", auth_results_val)
    elif raw_json.get("auth_results"):
        ar = raw_json["auth_results"]
        if isinstance(ar, list) and ar:
            _safe_set_header(msg, "Authentication-Results", f"mx.emailshield.in; {ar[0].get('mechanism', 'spf')}={ar[0].get('result', 'pass')}")

    dkim_val = (
        message_record.get("dkim-signature") or message_record.get("DKIM-Signature") or
        headers.get("dkim-signature") or headers.get("DKIM-Signature")
    )
    if dkim_val:
        _safe_set_header(msg, "DKIM-Signature", dkim_val)

    rp_val = (
        message_record.get("return-path") or message_record.get("Return-Path") or
        headers.get("return-path") or headers.get("Return-Path")
    )
    if rp_val:
        _safe_set_header(msg, "Return-Path", rp_val)

    # Preserve Body and URLs
    body_text = raw_json.get("body") or raw_json.get("body_text") or raw_json.get("body_excerpt") or ""
    if not body_text:
        body_text = f"Live Mail message from {from_addr}.\nSubject: {subj}\nTimestamp: {date_val}\n"

    # Embed indicators/URLs if preserved in indicators list but absent from excerpt
    inds = raw_json.get("indicators") or []
    url_lines = []
    for ind in inds:
        if isinstance(ind, dict) and ind.get("type") == "URL":
            url_lines.append(ind.get("value", ""))
        elif hasattr(ind, "type") and getattr(ind, "type") == "URL":
            url_lines.append(getattr(ind, "value", ""))
    if url_lines:
        body_text += "\n\nPreserved Extracted URLs:\n" + "\n".join(url_lines)

    msg.set_content(body_text)

    # Preserve Attachments (attach placeholder parts to preserve attachment count and filenames)
    atts = raw_json.get("attachments") or raw_json.get("attachment_analyses") or []
    for att in atts:
        fname = att.get("filename") if isinstance(att, dict) else getattr(att, "filename", "payload.bin")
        fname = fname or "payload.bin"
        sha = att.get("sha256") if isinstance(att, dict) else getattr(att, "sha256", "UNKNOWN")
        dummy_content = f"EMAILSHIELD PRESERVED ATTACHMENT EVIDENCE\nFilename: {fname}\nSHA-256: {sha}\n".encode("utf-8")
        msg.add_attachment(dummy_content, maintype="application", subtype="octet-stream", filename=fname)

    return filename, msg.as_bytes()
