"""
worker/poller.py
Safe Mailbox Polling Engine for EMAILSHIELD INDIA Sentinel.
Orchestrates synthetic IMAP connection, incremental UID checkpointing, Message-ID
deduplication, resource bounding, malformed message handling, and lease integration.

CRITICAL INVARIANT:
Zero real network calls. Operates strictly with SyntheticIMAPConnection.
"""

import email
import hashlib
import json
import time
from email.header import decode_header
from typing import Optional, Dict, List, Any, Callable

from worker.config import WorkerConfig
from worker.identity import WorkerIdentity
from worker.lease import WorkerLeaseManager
from worker.credentials import WorkerCredentialService, LeasedCredential
from worker.synthetic_imap import (
    SyntheticIMAPServer,
    SyntheticIMAPConnection,
    SyntheticIMAPError,
    SyntheticAuthError,
    SyntheticConnectionError,
)
from worker.checkpoint import CheckpointStore, MailboxCheckpoint
from worker.events import SafeEmailEvent
from worker.imap_client import IMAPConnectionProtocol, RealIMAPConnection
from worker.logging import get_worker_logger

logger = get_worker_logger("sentinel.worker.poller")

# Resource Bounds
MAX_MESSAGE_SIZE_BYTES = 5 * 1024 * 1024  # 5 MB
MAX_MESSAGES_PER_POLL = 20
MAX_POLL_RETRIES = 3
POLL_TIMEOUT_SECONDS = 30.0
MAX_BODY_PREVIEW_LENGTH = 500


def safe_decode_header(header_value: Optional[str]) -> str:
    """Safely decodes RFC2047 MIME encoded headers into clean unicode."""
    if not header_value:
        return ""
    try:
        decoded_parts = decode_header(header_value)
        result = []
        for part, encoding in decoded_parts:
            if isinstance(part, bytes):
                result.append(part.decode(encoding or "utf-8", errors="replace"))
            else:
                result.append(str(part))
        return "".join(result).strip()
    except Exception:
        return str(header_value)


class MailboxPoller:
    """
    Worker polling engine executing incremental synthetic IMAP scans.
    """
    def __init__(
        self,
        config: WorkerConfig,
        identity: WorkerIdentity,
        lease_manager: WorkerLeaseManager,
        credential_service: WorkerCredentialService,
        checkpoint_store: CheckpointStore,
        synthetic_server: Optional[SyntheticIMAPServer] = None,
        imap_adapter_factory: Optional[Callable[..., IMAPConnectionProtocol]] = None,
        forensic_agent: Optional[Any] = None,
    ):
        self.config = config
        self.identity = identity
        self.lease_manager = lease_manager
        self.credential_service = credential_service
        self.checkpoint_store = checkpoint_store
        self.synthetic_server = synthetic_server
        self.imap_adapter_factory = imap_adapter_factory
        self.forensic_agent = forensic_agent

    def poll(self, folder_name: str = "INBOX", skip_historical: Optional[bool] = None) -> Dict[str, Any]:
        """
        Executes one incremental poll cycle for the worker's assigned mailbox.
        
        Enforces:
        - Active worker lease verification (fails closed if unleased or expired).
        - Concurrent poll lock per mailbox (returns POLL_ALREADY_RUNNING).
        - Safe credential retrieval and decryption.
        - Incremental UID scanning and Message-ID deduplication.
        - Initial synchronization skipping historical mail when skip_historical is True.
        - Mid-poll lease loss detection (halts checkpoint advancement).
        - Clean IMAP logout and lock release.
        """
        # 1. Lease check
        if not self.lease_manager.is_active():
            logger.warning("Polling rejected: worker %s does not hold an active lease.", self.identity.worker_id)
            raise PermissionError("Worker does not hold an active lease.")

        # 2. Retrieve and decrypt synthetic credentials
        with self.credential_service.fetch_and_decrypt() as cred:
            mailbox_id = cred.mailbox_id
            tenant_user_id = cred.user_id

            # Parse synthetic credential secret
            try:
                secret_dict = json.loads(cred.secret)
                username = secret_dict.get("username", cred.email_address)
                password = secret_dict.get("password", "")
                imap_host = secret_dict.get("imap_host", cred.imap_host)
                imap_port = secret_dict.get("imap_port", cred.imap_port)
            except Exception:
                username = cred.email_address
                password = cred.secret
                imap_host = cred.imap_host
                imap_port = cred.imap_port

            # 3. Concurrency lock
            if not self.checkpoint_store.acquire_poll_lock(mailbox_id):
                logger.info("Poll already running for mailbox %s.", mailbox_id)
                return {
                    "status": "POLL_ALREADY_RUNNING",
                    "mailbox_id": mailbox_id,
                    "processed_count": 0,
                    "events": []
                }

            events: List[SafeEmailEvent] = []
            conn: Optional[IMAPConnectionProtocol] = None
            try:
                # 4. Connect to IMAP adapter (Synthetic or Real)
                if self.imap_adapter_factory:
                    conn = self.imap_adapter_factory(
                        host=imap_host,
                        port=imap_port,
                        use_ssl=cred.use_ssl
                    )
                elif self.synthetic_server:
                    conn = SyntheticIMAPConnection(
                        server=self.synthetic_server,
                        host=imap_host,
                        port=imap_port,
                        use_ssl=cred.use_ssl
                    )
                else:
                    conn = RealIMAPConnection(
                        host=imap_host,
                        port=imap_port,
                        use_ssl=cred.use_ssl
                    )
                conn.login(username, password)

                # 5. Select mailbox
                status, count = conn.select(folder_name)
                if status != "OK":
                    logger.error("Failed to select folder %s for mailbox %s", folder_name, mailbox_id)
                    return {"status": "FOLDER_NOT_FOUND", "mailbox_id": mailbox_id, "processed_count": 0, "events": []}

                # 6. Checkpoint inspection & UIDVALIDITY verification
                cp = self.checkpoint_store.get_checkpoint(
                    user_id=tenant_user_id,
                    worker_id=str(self.identity.worker_id),
                    mailbox_id=mailbox_id,
                    folder_name=folder_name
                )
                if self.config.production_polling_enabled and not cp.has_polled:
                    self.checkpoint_store.seed_from_telemetry(
                        tenant_user_id, str(self.identity.worker_id), mailbox_id, folder_name
                    )

                # Check UIDVALIDITY stability across polls
                conn_uid_validity = getattr(conn, "get_uid_validity", lambda: 1)()
                if cp.has_polled and cp.uid_validity != conn_uid_validity:
                    logger.warning(
                        "Mailbox %s: IMAP UIDVALIDITY changed from %d to %d. Re-establishing baseline to avoid reprocessing.",
                        mailbox_id, cp.uid_validity, conn_uid_validity
                    )
                    all_uids_on_reset = conn.search(since_uid=0)
                    highest_baseline = max(all_uids_on_reset) if all_uids_on_reset else 0
                    cp.uid_validity = conn_uid_validity
                    cp.last_processed_uid = highest_baseline
                    self.checkpoint_store.advance_checkpoint(
                        user_id=tenant_user_id,
                        worker_id=str(self.identity.worker_id),
                        mailbox_id=mailbox_id,
                        uid=highest_baseline,
                        folder_name=folder_name
                    )
                elif not cp.has_polled:
                    cp.uid_validity = conn_uid_validity

                last_uid = cp.last_processed_uid

                # 7. Search unseen UIDs
                all_unseen_uids = conn.search(since_uid=last_uid)

                # Initial sync: skip historical messages when requested or in production polling
                effective_skip = self.config.production_polling_enabled if skip_historical is None else bool(skip_historical)
                if effective_skip and last_uid == 0 and not cp.has_polled:
                    highest_baseline_uid = max(all_unseen_uids) if all_unseen_uids else 0
                    logger.info(
                        "Mailbox %s: Initial synchronization. Skipping %d historical messages; setting baseline checkpoint UID %d.",
                        mailbox_id, len(all_unseen_uids), highest_baseline_uid
                    )
                    cp.has_polled = True
                    cp.last_processed_uid = highest_baseline_uid
                    self.checkpoint_store.advance_checkpoint(
                        user_id=tenant_user_id,
                        worker_id=str(self.identity.worker_id),
                        mailbox_id=mailbox_id,
                        uid=highest_baseline_uid,
                        folder_name=folder_name
                    )
                    poll_time_now = time.strftime("%H:%M:%S")
                    self.checkpoint_store.record_poll_stats(
                        user_id=tenant_user_id,
                        worker_id=str(self.identity.worker_id),
                        mailbox_id=mailbox_id,
                        arrived=0,
                        analysed=0,
                        clean=0,
                        suspicious=0,
                        high_critical=0,
                        duplicates=0,
                        errors=0,
                        last_uid=highest_baseline_uid,
                        poll_time_str=poll_time_now,
                        folder_name=folder_name
                    )
                    try:
                        from core.sentinel_stats import record_user_sentinel_poll
                        record_user_sentinel_poll(
                            user_id=tenant_user_id,
                            mailbox_id=mailbox_id,
                            arrived=0,
                            analysed=0,
                            clean=0,
                            suspicious=0,
                            high_critical=0,
                            duplicates=0,
                            errors=0,
                            last_uid=highest_baseline_uid,
                            poll_time_str=poll_time_now,
                            highest_observed_uid=highest_baseline_uid,
                            last_successful_imap_poll=poll_time_now,
                            last_poll_result="Initial sync complete (0 new messages)",
                        )
                    except Exception:
                        pass
                    stats_dict = self.checkpoint_store.get_stats(
                        user_id=tenant_user_id,
                        worker_id=str(self.identity.worker_id),
                        mailbox_id=mailbox_id,
                        folder_name=folder_name
                    )
                    return {
                        "status": "INITIAL_SYNC_COMPLETE",
                        "mailbox_id": mailbox_id,
                        "processed_count": 0,
                        "events": [],
                        "stats": stats_dict
                    }

                uids_to_process = all_unseen_uids[:MAX_MESSAGES_PER_POLL]

                logger.info(
                    "SAFE_DIAG_BOUNDARY_1: detected new UIDs=%s, min_uid=%d, user_hash=%s",
                    uids_to_process, last_uid, hashlib.sha256(tenant_user_id.encode()).hexdigest()[:8]
                )

                logger.info(
                    "Mailbox %s: Found %d unseen UIDs (since UID %d). Processing %d messages...",
                    mailbox_id, len(all_unseen_uids), last_uid, len(uids_to_process)
                )

                # 8. Deterministic processing in ascending UID order
                poll_arrived = 0
                poll_analysed = 0
                poll_clean = 0
                poll_suspicious = 0
                poll_high_critical = 0
                poll_duplicates = 0
                poll_errors = 0
                poll_recent_events: List[Dict[str, Any]] = []
                highest_uid = last_uid

                for uid in uids_to_process:
                    # Critical: Proactive mid-poll lease renewal while still active
                    if self.lease_manager is not None:
                        remaining_time = self.lease_manager.time_until_expiry()
                        renewal_threshold = getattr(self.config, "renewal_interval_seconds", 30)
                        renewal_ext = getattr(self.config, "renewal_extension_seconds", 120)
                        if self.lease_manager.is_active() and remaining_time < renewal_threshold:
                            logger.info(
                                "Renewing worker lease mid-poll (remaining: %ds, threshold: %ds)...",
                                int(remaining_time), renewal_threshold
                            )
                            self.lease_manager.renew_lease(renewal_ext)

                        if not self.lease_manager.is_active():
                            logger.warning("Lease expired during active polling of mailbox %s. Aborting further processing.", mailbox_id)
                            return {
                                "status": "LEASE_EXPIRED_MID_POLL",
                                "mailbox_id": mailbox_id,
                                "processed_count": len(events),
                                "events": events
                            }

                    # Fetch message
                    fetched = conn.fetch(uid)

                    # Critical: Mid-poll lease check after fetch (before processing or checkpointing)
                    if self.lease_manager is not None and not self.lease_manager.is_active():
                        logger.warning("Lease expired during active polling of mailbox %s (post-fetch). Aborting further processing.", mailbox_id)
                        return {
                            "status": "LEASE_EXPIRED_MID_POLL",
                            "mailbox_id": mailbox_id,
                            "processed_count": len(events),
                            "events": events
                        }

                    raw_bytes = fetched.get("rfc822", b"")
                    size = len(raw_bytes)

                    # Resource limit: check message size
                    if size > MAX_MESSAGE_SIZE_BYTES:
                        logger.warning("UID %d in mailbox %s exceeds size limit (%d bytes).", uid, mailbox_id, size)
                        poll_errors += 1
                        poll_arrived += 1
                        highest_uid = max(highest_uid, uid)
                        evt = SafeEmailEvent(
                            tenant_user_id=tenant_user_id,
                            mailbox_id=mailbox_id,
                            uid=uid,
                            message_id=fetched.get("message_id") or f"<oversized-{uid}@{mailbox_id}>",
                            sender="",
                            recipient="",
                            timestamp="",
                            subject="[OVERSIZED_MESSAGE]",
                            body_preview="[Content omitted: exceeds maximum size threshold]",
                            body_length=size,
                            processing_status="OVERSIZED",
                            error_code="ERR_MESSAGE_TOO_LARGE"
                        )
                        events.append(evt)
                        self.checkpoint_store.advance_checkpoint(
                            user_id=tenant_user_id,
                            worker_id=str(self.identity.worker_id),
                            mailbox_id=mailbox_id,
                            uid=uid,
                            message_id=evt.message_id,
                            folder_name=folder_name
                        )
                        continue

                    # Safe parsing of email payload
                    try:
                        parsed_msg = email.message_from_bytes(raw_bytes)
                    except Exception as parse_err:
                        logger.warning("Malformed email payload for UID %d: %s", uid, type(parse_err).__name__)
                        poll_errors += 1
                        poll_arrived += 1
                        highest_uid = max(highest_uid, uid)
                        evt = SafeEmailEvent(
                            tenant_user_id=tenant_user_id,
                            mailbox_id=mailbox_id,
                            uid=uid,
                            message_id=f"<malformed-{uid}@{mailbox_id}>",
                            sender="",
                            recipient="",
                            timestamp="",
                            subject="[MALFORMED_EMAIL]",
                            body_preview="",
                            body_length=size,
                            processing_status="ERROR",
                            error_code="ERR_MALFORMED_MIME"
                        )
                        events.append(evt)
                        self.checkpoint_store.advance_checkpoint(
                            user_id=tenant_user_id,
                            worker_id=str(self.identity.worker_id),
                            mailbox_id=mailbox_id,
                            uid=uid,
                            message_id=evt.message_id,
                            folder_name=folder_name
                        )
                        continue

                    # Extract metadata safely
                    msg_id = safe_decode_header(parsed_msg.get("Message-ID", "")).strip()
                    if not msg_id:
                        msg_id = f"<synthetic-generated-{uid}@{mailbox_id}>"

                    # Secondary Message-ID deduplication check
                    if self.checkpoint_store.is_duplicate_message_id(mailbox_id, msg_id):
                        logger.info("UID %d has duplicate Message-ID %s. Skipping duplicate event.", uid, msg_id)
                        poll_duplicates += 1
                        highest_uid = max(highest_uid, uid)
                        # Advance checkpoint past this UID so it is not scanned again
                        self.checkpoint_store.advance_checkpoint(
                            user_id=tenant_user_id,
                            worker_id=str(self.identity.worker_id),
                            mailbox_id=mailbox_id,
                            uid=uid,
                            message_id=msg_id,
                            folder_name=folder_name
                        )
                        continue

                    subject = safe_decode_header(parsed_msg.get("Subject", "")).strip()
                    sender = safe_decode_header(parsed_msg.get("From", "")).strip()
                    recipient = safe_decode_header(parsed_msg.get("To", "")).strip()
                    date_str = safe_decode_header(parsed_msg.get("Date", "")).strip()

                    # Extract text preview
                    body_text = ""
                    attachment_count = 0
                    try:
                        if parsed_msg.is_multipart():
                            for part in parsed_msg.walk():
                                ctype = part.get_content_type()
                                cdisp = str(part.get("Content-Disposition", ""))
                                if "attachment" in cdisp:
                                    attachment_count += 1
                                elif ctype == "text/plain" and not body_text:
                                    payload = part.get_payload(decode=True)
                                    if payload:
                                        body_text = payload.decode("utf-8", errors="replace")
                        else:
                            payload = parsed_msg.get_payload(decode=True)
                            if payload:
                                body_text = payload.decode("utf-8", errors="replace")
                    except Exception:
                        body_text = "[Error decoding body content]"

                    preview = body_text[:MAX_BODY_PREVIEW_LENGTH]

                    risk_score = None
                    verdict = None
                    extracted_iocs = None
                    forensic_error_occurred = False
                    if self.forensic_agent is not None:
                        try:
                            from core.parser import SecureEmailParser
                            from core.indicators import extract_all_indicators
                            parsed_email = SecureEmailParser(raw_bytes).parse()
                            body_plus_hdrs = parsed_email.get("body", "") + " " + str(parsed_email.get("headers", {}))
                            extracted_iocs = extract_all_indicators(body_plus_hdrs)
                            investigation = self.forensic_agent.run_investigation(parsed_email, extracted_iocs)
                            risk_score = investigation.get("risk_score")
                            verdict = investigation.get("verdict") or investigation.get("ml_pred") or str(risk_score)
                        except Exception as forensic_err:
                            logger.warning("Forensic investigation error for UID %d: %s", uid, forensic_err)
                            forensic_error_occurred = True

                    if forensic_error_occurred:
                        poll_errors += 1
                        poll_arrived += 1
                        highest_uid = max(highest_uid, uid)
                        event = SafeEmailEvent(
                            tenant_user_id=tenant_user_id,
                            mailbox_id=mailbox_id,
                            uid=uid,
                            message_id=msg_id,
                            sender=sender,
                            recipient=recipient,
                            timestamp=date_str,
                            subject=subject,
                            body_preview=preview,
                            body_length=len(body_text),
                            attachment_count=attachment_count,
                            processing_status="ERROR",
                            error_code="ERR_FORENSIC_FAILED",
                            risk_score=None,
                            verdict="ERROR",
                            iocs=None,
                        )
                        events.append(event)
                        poll_recent_events.append({
                            "category": "Error",
                            "subject": subject or "(No Subject)",
                            "time": date_str or time.strftime("%H:%M:%S"),
                            "sender": sender or "Unknown",
                            "verdict": "Forensic Analysis Failed",
                        })
                        self.checkpoint_store.advance_checkpoint(
                            user_id=tenant_user_id,
                            worker_id=str(self.identity.worker_id),
                            mailbox_id=mailbox_id,
                            uid=uid,
                            message_id=msg_id,
                            date_str=date_str,
                            folder_name=folder_name
                        )
                        continue

                    event = SafeEmailEvent(
                        tenant_user_id=tenant_user_id,
                        mailbox_id=mailbox_id,
                        uid=uid,
                        message_id=msg_id,
                        sender=sender,
                        recipient=recipient,
                        timestamp=date_str,
                        subject=subject,
                        body_preview=preview,
                        body_length=len(body_text),
                        attachment_count=attachment_count,
                        processing_status="PROCESSED",
                        risk_score=risk_score,
                        verdict=verdict,
                        iocs=extracted_iocs,
                    )
                    events.append(event)
                    poll_arrived += 1
                    poll_analysed += 1
                    highest_uid = max(highest_uid, uid)

                    # Categorize risk classification
                    score_str = str(risk_score).upper() if risk_score is not None else ""
                    verdict_str = str(verdict).upper() if verdict is not None else ""
                    if "HIGH" in score_str or "CRITICAL" in score_str or "HIGH" in verdict_str or "CRITICAL" in verdict_str:
                        poll_high_critical += 1
                        event_cat = "High Risk"
                    elif "SUSPICIOUS" in score_str or "MEDIUM" in score_str or "SUSPICIOUS" in verdict_str:
                        poll_suspicious += 1
                        event_cat = "Suspicious"
                    else:
                        poll_clean += 1
                        event_cat = "Clean"

                    poll_recent_events.append({
                        "category": event_cat,
                        "subject": subject or "(No Subject)",
                        "time": date_str or time.strftime("%H:%M:%S"),
                        "sender": sender or "Unknown",
                        "verdict": verdict or event_cat,
                    })

                    # Advance checkpoint strictly upon successful processing
                    self.checkpoint_store.advance_checkpoint(
                        user_id=tenant_user_id,
                        worker_id=str(self.identity.worker_id),
                        mailbox_id=mailbox_id,
                        uid=uid,
                        message_id=msg_id,
                        date_str=date_str,
                        folder_name=folder_name
                    )

                poll_time_now = time.strftime("%H:%M:%S")
                self.checkpoint_store.record_poll_stats(
                    user_id=tenant_user_id,
                    worker_id=str(self.identity.worker_id),
                    mailbox_id=mailbox_id,
                    arrived=poll_arrived,
                    analysed=poll_analysed,
                    clean=poll_clean,
                    suspicious=poll_suspicious,
                    high_critical=poll_high_critical,
                    duplicates=poll_duplicates,
                    errors=poll_errors,
                    last_uid=highest_uid,
                    poll_time_str=poll_time_now,
                    folder_name=folder_name
                )
                if poll_arrived > 0:
                    poll_result_str = f"{poll_arrived} new message(s)"
                elif poll_errors > 0:
                    poll_result_str = "ERROR"
                else:
                    poll_result_str = "0 new messages"

                try:
                    from core.sentinel_stats import record_user_sentinel_poll
                    record_user_sentinel_poll(
                        user_id=tenant_user_id,
                        mailbox_id=mailbox_id,
                        arrived=poll_arrived,
                        analysed=poll_analysed,
                        clean=poll_clean,
                        suspicious=poll_suspicious,
                        high_critical=poll_high_critical,
                        duplicates=poll_duplicates,
                        errors=poll_errors,
                        last_uid=highest_uid,
                        poll_time_str=poll_time_now,
                        highest_observed_uid=highest_uid,
                        last_successful_imap_poll=poll_time_now,
                        last_poll_result=poll_result_str,
                        recent_events=poll_recent_events,
                    )
                except Exception:
                    pass

                stats_dict = self.checkpoint_store.get_stats(
                    user_id=tenant_user_id,
                    worker_id=str(self.identity.worker_id),
                    mailbox_id=mailbox_id,
                    folder_name=folder_name
                )

                return {
                    "status": "SUCCESS",
                    "mailbox_id": mailbox_id,
                    "processed_count": len(events),
                    "events": events,
                    "stats": stats_dict
                }
            finally:
                if conn:
                    try:
                        conn.close()
                    except Exception:
                        pass
                    try:
                        conn.logout()
                    except Exception:
                        pass
                self.checkpoint_store.release_poll_lock(mailbox_id)
