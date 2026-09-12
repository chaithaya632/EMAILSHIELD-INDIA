import time
import threading
import datetime
import uuid
import re
import urllib.parse
from typing import Dict, Any, List, Optional, Tuple
import requests

from core.parser import SecureEmailParser
from core.indicators import extract_all_indicators
from core.auth_claims import parse_auth_results, evaluate_auth_and_alignment
from core.geolocation import get_geolocation
from core.risk import evaluate_rules, calculate_hybrid_risk
from core.domain_reputation import get_domain_reputation
from core.url_forensics import analyze_all_urls, defang_url
from core.lookalike import detect_lookalike_domain
from core.bec_detector import detect_bec_and_impersonation
from core.attachments import analyze_all_attachments
from core.relay_tracer import analyze_relay_transit
from core.ai_reasoning import generate_forensic_reasoning
from core.case_store import save_case
from core.schemas import (
    CaseReport, Indicator, GeolocationInfo, AuthEvidence,
    RuleFinding, MLAssessment, EventTimeline
)
from core.mailbox_connector import fetch_imap_emails, fetch_imap_raw_email
from core.gmail_integration import fetch_recent_emails, fetch_raw_email

# =====================================================================
# 1. MOBILE ALERT DISPATCHERS (WhatsApp & Telegram)
# =====================================================================

def format_threat_alert_text(threat_info: Dict[str, Any]) -> str:
    """Formats an urgent, clean security warning with markdown/emojis."""
    risk = threat_info.get("risk_score", "HIGH")
    subject = threat_info.get("subject", "No Subject")
    sender = threat_info.get("sender", "Unknown Sender")
    score = threat_info.get("risk_score_numeric", 85)
    reasons = threat_info.get("risk_reasons", [])
    now_str = datetime.datetime.now().strftime("%d-%b-%Y %I:%M %p")

    reason_lines = "\n".join([f"• {r}" for r in reasons[:3]]) if reasons else "• Critical phishing heuristics identified."

    alert_msg = (
        f"🚨 *EMAILSHIELD CRITICAL SECURITY ALERT* 🚨\n\n"
        f"⚠️ *Malicious Email Detected in Your Mailbox!*\n"
        f"━━━━━━━━━━━━━━━━━━━━━━\n"
        f"📧 *Sender*: {sender}\n"
        f"📌 *Subject*: \"{subject[:55]}\"\n"
        f"🎯 *Verdict*: 🔴 {risk} RISK ({score}/100)\n\n"
        f"🔍 *Key Forensic Findings*:\n"
        f"{reason_lines}\n\n"
        f"🛡️ *Recommended Protective Actions*:\n"
        f"❌ DO NOT click any links inside this email.\n"
        f"❌ DO NOT disclose passwords, OTPs, or financial details.\n"
        f"🗑️ Action: Delete or quarantine this message immediately.\n"
        f"━━━━━━━━━━━━━━━━━━━━━━\n"
        f"🕒 Time: {now_str} | _EmailShield Live Sentinel_"
    )
    return alert_msg

def send_whatsapp_alert(phone: str, apikey: str, text: str) -> Tuple[bool, str]:
    """
    Dispatches a direct WhatsApp notification via the 100% free CallMeBot API.
    Phone format: international with country code, e.g. +919876543210
    """
    clean_phone = re.sub(r'[^\d+]', '', phone.strip())
    if not clean_phone.startswith('+'):
        clean_phone = '+' + clean_phone

    clean_key = apikey.strip()
    if not clean_phone or len(clean_phone) < 10:
        return False, "Invalid phone number format. Must include country code (e.g. +91XXXXXXXXXX)."
    if not clean_key:
        return False, "CallMeBot API key is required."

    encoded_text = urllib.parse.quote(text)
    url = f"https://api.callmebot.com/whatsapp.php?phone={clean_phone}&text={encoded_text}&apikey={clean_key}"

    try:
        resp = requests.get(url, timeout=12.0)
        if resp.status_code == 200:
            if "error" in resp.text.lower():
                return False, f"CallMeBot Error: {resp.text.strip()[:100]}"
            return True, "WhatsApp alert successfully delivered to phone."
        return False, f"HTTP {resp.status_code}: {resp.text[:100]}"
    except Exception as e:
        return False, f"WhatsApp dispatch failed: {str(e)}"

def send_telegram_alert(bot_token: str, chat_id: str, text: str) -> Tuple[bool, str]:
    """
    Dispatches an instant alert notification via the official Telegram Bot API.
    """
    token = bot_token.strip()
    cid = chat_id.strip()

    if not token or ":" not in token:
        return False, "Invalid Telegram Bot Token format."
    if not cid:
        return False, "Telegram Chat ID is required."

    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {
        "chat_id": cid,
        "text": text,
        "parse_mode": "Markdown"
    }

    try:
        resp = requests.post(url, json=payload, timeout=12.0)
        data = resp.json()
        if resp.status_code == 200 and data.get("ok"):
            return True, "Telegram alert successfully delivered."
        err_desc = data.get("description", resp.text[:100])
        if "chat not found" in err_desc.lower():
            return False, (
                "Telegram error: 'Chat not found'.\n"
                "👉 Fix: Open your bot in Telegram and click 'START' (bots cannot message you until you press Start).\n"
                "👉 Also ensure Chat ID is your numeric ID (from @userinfobot), not your @username."
            )
        return False, f"Telegram error: {err_desc}"
    except Exception as e:
        return False, f"Telegram dispatch failed: {str(e)}"

def send_test_alert(channel: str, config: Dict[str, str]) -> Tuple[bool, str]:
    """Sends an immediate test ping so the user can verify their phone notification setup."""
    now_str = datetime.datetime.now().strftime("%I:%M:%S %p")
    test_msg = (
        f"✅ *EMAILSHIELD SENTINEL TEST PING*\n\n"
        f"Your mobile notification link is *ACTIVE and VERIFIED*! 🎉\n"
        f"Live Mailbox Sentinel will alert your phone immediately whenever a phishing or malware email arrives.\n"
        f"━━━━━━━━━━━━━━━━━━━━━━\n"
        f"🕒 Verified at: {now_str} | _EmailShield India_"
    )
    if channel.lower() == "whatsapp":
        return send_whatsapp_alert(config.get("whatsapp_phone", ""), config.get("whatsapp_apikey", ""), test_msg)
    elif channel.lower() == "telegram":
        return send_telegram_alert(config.get("telegram_token", ""), config.get("telegram_chat_id", ""), test_msg)
    return False, f"Unknown notification channel '{channel}'."


# =====================================================================
# 2. SENTINEL THREAD-SAFE STATE & MANAGER
# =====================================================================

class SentinelState:
    def __init__(self):
        self.is_running: bool = False
        self.poll_interval_seconds: int = 50
        self.last_checked_time: Optional[datetime.datetime] = None
        self.next_check_countdown: int = 50
        
        # Checkpoint: identifying the last analyzed email
        self.checkpoint_id: Optional[str] = None
        self.checkpoint_subject: Optional[str] = None
        self.checkpoint_sender: Optional[str] = None
        self.checkpoint_date: Optional[str] = None
        
        # Statistics
        self.total_scanned: int = 0
        self.clean_count: int = 0
        self.suspicious_count: int = 0
        self.phishing_count: int = 0
        self.alerts_sent: int = 0
        
        # Activity History Log (newest first, max 50 entries)
        self.recent_activity: List[Dict[str, Any]] = []
        self.status_message: str = "Sentinel is stopped."
        self.error_log: List[str] = []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_running": self.is_running,
            "poll_interval": self.poll_interval_seconds,
            "last_checked_time": self.last_checked_time.strftime("%d-%b %H:%M:%S") if self.last_checked_time else "Never",
            "next_check_countdown": self.next_check_countdown,
            "checkpoint_id": self.checkpoint_id or "None (Not Initialized)",
            "checkpoint_subject": self.checkpoint_subject or "N/A",
            "checkpoint_sender": self.checkpoint_sender or "N/A",
            "checkpoint_date": self.checkpoint_date or "N/A",
            "total_scanned": self.total_scanned,
            "clean_count": self.clean_count,
            "suspicious_count": self.suspicious_count,
            "phishing_count": self.phishing_count,
            "alerts_sent": self.alerts_sent,
            "status_message": self.status_message,
            "recent_activity": list(self.recent_activity[:25]),
            "error_log": list(self.error_log[-10:])
        }


class SentinelManager:
    """
    Singleton Manager that controls the background polling thread,
    tracks the 'last analyzed email' checkpoint, runs forensic investigations on new mail,
    and coordinates WhatsApp/Telegram mobile alerts.
    """
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(SentinelManager, cls).__new__(cls)
                cls._instance.state = SentinelState()
                cls._instance._thread: Optional[threading.Thread] = None
                cls._instance._stop_event = threading.Event()
                cls._instance.config: Dict[str, Any] = {}
                cls._instance.ml_classifier = None
            return cls._instance

    def is_active(self) -> bool:
        return self.state.is_running

    def get_state_summary(self) -> Dict[str, Any]:
        with self._lock:
            return self.state.to_dict()

    def start(
        self,
        mailbox_type: str,
        mailbox_creds: Dict[str, Any],
        alert_config: Dict[str, Any],
        ml_classifier: Any,
        poll_interval: int = 50
    ) -> Tuple[bool, str]:
        """Starts the background sentinel daemon thread."""
        with self._lock:
            if self.state.is_running:
                return True, "Sentinel is already running."

            self.config = {
                "mailbox_type": mailbox_type,
                "mailbox_creds": mailbox_creds,
                "alert_config": alert_config
            }
            self.ml_classifier = ml_classifier
            self.state.poll_interval_seconds = max(15, poll_interval)
            self._stop_event.clear()
            self.state.is_running = True
            self.state.status_message = "Initializing mailbox checkpoint..."

            # Initialize checkpoint with the top email so we don't back-scan older inbox mail
            try:
                latest_emails = self._fetch_recent_headers(limit=5)
                if latest_emails:
                    top_msg = latest_emails[0]
                    self.state.checkpoint_id = str(top_msg.get("id"))
                    self.state.checkpoint_subject = top_msg.get("subject", "No Subject")
                    self.state.checkpoint_sender = top_msg.get("sender", "Unknown")
                    self.state.checkpoint_date = top_msg.get("date", "Unknown")
                    self.state.status_message = f"Synchronized at: {self.state.checkpoint_subject[:35]}..."
                else:
                    self.state.status_message = "Mailbox empty or connected. Ready for new arrivals."
            except Exception as e:
                self.state.error_log.append(f"Checkpoint init warning: {str(e)}")
                self.state.status_message = "Connected. Awaiting incoming emails."

            # Spawn daemon thread
            self._thread = threading.Thread(target=self._worker_loop, daemon=True)
            self._thread.start()
            return True, "Live Mailbox Sentinel activated. Polling every 50 seconds."

    def stop(self) -> Tuple[bool, str]:
        """Gracefully halts the background sentinel thread."""
        with self._lock:
            if not self.state.is_running:
                return True, "Sentinel is already stopped."

            self._stop_event.set()
            self.state.is_running = False
            self.state.status_message = "Sentinel stopped by user."
            return True, "Live Mailbox Sentinel stopped."

    # -----------------------------------------------------------------
    # WORKER LOOP
    # -----------------------------------------------------------------

    def _worker_loop(self):
        """Main execution thread loop ticking every 50 seconds."""
        while not self._stop_event.is_set():
            cycle_start = time.time()
            try:
                self._execute_scan_cycle()
            except Exception as e:
                with self._lock:
                    err = f"Sentinel scan error: {str(e)}"
                    self.state.error_log.append(err)
                    self.state.status_message = f"Warning: {str(e)[:60]}"

            # Responsive sleep countdown (checks _stop_event every 1s)
            poll_time = self.state.poll_interval_seconds
            for remaining in range(poll_time, 0, -1):
                if self._stop_event.is_set():
                    break
                self.state.next_check_countdown = remaining
                time.sleep(1.0)

        with self._lock:
            self.state.is_running = False
            self.state.status_message = "Sentinel stopped."

    def _execute_scan_cycle(self):
        """Executes one 50-second inspection cycle against the mailbox."""
        with self._lock:
            self.state.last_checked_time = datetime.datetime.now()
            self.state.status_message = "Checking for new emails..."

        latest_emails = self._fetch_recent_headers(limit=10)
        if not latest_emails:
            with self._lock:
                self.state.status_message = "No emails found or mailbox idle."
            return

        # Determine which emails are newer than the last analyzed checkpoint
        new_emails = self._identify_unseen_emails(latest_emails)

        if not new_emails:
            with self._lock:
                self.state.status_message = f"Synchronized. No new mail since '{str(self.state.checkpoint_subject)[:25]}'."
            return

        with self._lock:
            self.state.status_message = f"Analyzing {len(new_emails)} new email(s)..."

        # Process new emails in chronological order (oldest to newest)
        for msg_item in reversed(new_emails):
            if self._stop_event.is_set():
                break
            try:
                self._analyze_and_record_email(msg_item)
            except Exception as e:
                with self._lock:
                    self.state.error_log.append(f"Failed to analyze email {msg_item.get('id')}: {str(e)}")

        with self._lock:
            self.state.status_message = f"Active. Last check clean at {datetime.datetime.now().strftime('%H:%M:%S')}."

    def _identify_unseen_emails(self, fetched_list: List[Dict[str, str]]) -> List[Dict[str, str]]:
        """
        Compares the incoming list of emails against the checkpoint.
        Returns only emails that arrived after the last analyzed checkpoint.
        """
        checkpoint = self.state.checkpoint_id
        if not checkpoint:
            # If no checkpoint was established, establish it at the latest email
            if fetched_list:
                self.state.checkpoint_id = str(fetched_list[0].get("id"))
                self.state.checkpoint_subject = fetched_list[0].get("subject", "No Subject")
            return []

        # Check if the top email is identical to our checkpoint
        if str(fetched_list[0].get("id")) == checkpoint:
            return []  # No new emails!

        # Find where the checkpoint is in the fetched list
        new_items = []
        checkpoint_found = False
        for msg in fetched_list:
            if str(msg.get("id")) == checkpoint:
                checkpoint_found = True
                break
            new_items.append(msg)

        if not checkpoint_found:
            # If checkpoint fell off the top list, process the newest 3 emails
            return fetched_list[:3]

        return new_items

    def _fetch_recent_headers(self, limit: int = 10) -> List[Dict[str, str]]:
        """Pulls recent header metadata without reading or changing read status."""
        m_type = self.config.get("mailbox_type", "IMAP")
        creds = self.config.get("mailbox_creds", {})

        if m_type == "IMAP":
            return fetch_imap_emails(
                email_addr=creds.get("email", ""),
                password=creds.get("pwd", ""),
                host=creds.get("host", ""),
                port=993,
                max_results=limit
            )
        else:
            return fetch_recent_emails(max_results=limit)

    def _fetch_raw_bytes(self, msg_id: str) -> bytes:
        """Fetches complete raw RFC822 bytes for the specified message ID."""
        m_type = self.config.get("mailbox_type", "IMAP")
        creds = self.config.get("mailbox_creds", {})

        if m_type == "IMAP":
            return fetch_imap_raw_email(
                email_addr=creds.get("email", ""),
                password=creds.get("pwd", ""),
                host=creds.get("host", ""),
                port=993,
                msg_id=msg_id
            )
        else:
            return fetch_raw_email(msg_id)

    def _analyze_and_record_email(self, msg_item: Dict[str, str]):
        """Runs full deep forensic pipeline, calculates risk, updates state, and fires alerts."""
        msg_id = str(msg_item.get("id"))
        raw_bytes = self._fetch_raw_bytes(msg_id)
        if not raw_bytes:
            return

        # 1. Parse email
        parser = SecureEmailParser(raw_bytes)
        parsed_data = parser.parse()
        headers = parsed_data.get("headers", {})
        body = parsed_data.get("body", "")
        subject = str(headers.get("subject", msg_item.get("subject", "No Subject")))
        sender = str(headers.get("from", msg_item.get("sender", "Unknown")))
        received_chain = parsed_data.get("received_chain", [])

        # 2. Extract IOCs
        raw_iocs = extract_all_indicators(body + " " + str(headers))
        public_ips = raw_iocs.get("ipv4", [])

        # 3. Auth Claims & Alignment (SPF/DKIM/DMARC)
        auth_alignment = evaluate_auth_and_alignment(headers)

        # 4. Domain Reputation & RDAP Age
        domain_rep = get_domain_reputation(sender)

        # 5. Lookalike Detection
        lookalike_res = detect_lookalike_domain(domain_rep.domain)

        # 6. Attachment Forensics
        raw_attachments = parsed_data.get("attachments", [])
        attachment_analyses = analyze_all_attachments(raw_attachments)

        # 7. BEC & Financial Wire Fraud Telemetry
        bec_telemetry = detect_bec_and_impersonation(headers, body, attachment_analyses, auth_alignment=auth_alignment)

        # 8. URL Forensics & Defanging
        urls_found = raw_iocs.get("urls", [])
        url_analyses = analyze_all_urls(urls_found) if urls_found else []

        # 9. Relay Transit
        relay_transit = analyze_relay_transit(received_chain)

        # 10. ML Classification
        ml_pred = {"probability": 0.0, "assessment": "Benign"}
        if self.ml_classifier:
            ml_pred = self.ml_classifier.predict(subject, body)
        ml_prob = ml_pred.get("probability", 0.0)

        # 11. Unified Rule Matrix & Hybrid Risk Scoring
        rule_results = evaluate_rules(
            parsed_data,
            domain_rep=domain_rep,
            url_analyses=url_analyses,
            auth_alignment=auth_alignment,
            attachment_analyses=attachment_analyses,
            lookalike_analysis=lookalike_res,
            bec_telemetry=bec_telemetry,
            relay_transit=relay_transit
        )
        rule_findings = [RuleFinding(**r) for r in rule_results]
        risk_score, reasons = calculate_hybrid_risk(rule_results, ml_prob, auth_alignment=auth_alignment)

        # Numeric score estimate for alerts
        score_val = 15
        if risk_score == "HIGH":
            score_val = int(75 + min(25, len(reasons) * 8))
        elif risk_score == "SUSPICIOUS":
            score_val = 50

        # Update statistics & checkpoint
        with self._lock:
            self.state.total_scanned += 1
            if risk_score == "HIGH":
                self.state.phishing_count += 1
            elif risk_score == "SUSPICIOUS":
                self.state.suspicious_count += 1
            else:
                self.state.clean_count += 1

            # Advance checkpoint to this email!
            self.state.checkpoint_id = msg_id
            self.state.checkpoint_subject = subject
            self.state.checkpoint_sender = sender
            self.state.checkpoint_date = str(msg_item.get("date", datetime.datetime.now().strftime("%Y-%m-%d %H:%M")))

        alert_dispatched = False
        alert_details = ""

        # 12. Alert Dispatcher (Fires ONLY on HIGH / CRITICAL risks)
        if risk_score == "HIGH":
            # Save automatically into Case Store
            case_id = f"CASE-{uuid.uuid4().hex[:8].upper()}"
            threat_payload = {
                "case_id": case_id,
                "subject": subject,
                "sender": sender,
                "risk_score": risk_score,
                "risk_score_numeric": score_val,
                "risk_reasons": reasons
            }

            alert_text = format_threat_alert_text(threat_payload)
            alert_cfg = self.config.get("alert_config", {})

            # Dispatch WhatsApp
            if alert_cfg.get("whatsapp_enabled"):
                phone = alert_cfg.get("whatsapp_phone", "")
                key = alert_cfg.get("whatsapp_apikey", "")
                w_ok, w_msg = send_whatsapp_alert(phone, key, alert_text)
                if w_ok:
                    alert_dispatched = True
                    alert_details += "WhatsApp Sent. "
                else:
                    self.state.error_log.append(f"WhatsApp alert error: {w_msg}")

            # Dispatch Telegram
            if alert_cfg.get("telegram_enabled"):
                token = alert_cfg.get("telegram_token", "")
                chat_id = alert_cfg.get("telegram_chat_id", "")
                t_ok, t_msg = send_telegram_alert(token, chat_id, alert_text)
                if t_ok:
                    alert_dispatched = True
                    alert_details += "Telegram Sent. "
                else:
                    self.state.error_log.append(f"Telegram alert error: {t_msg}")

            if alert_dispatched:
                with self._lock:
                    self.state.alerts_sent += 1

        # Record into recent activity feed
        activity_entry = {
            "timestamp": datetime.datetime.now().strftime("%H:%M:%S"),
            "subject": subject,
            "sender": sender,
            "verdict": risk_score,
            "score": score_val,
            "reasons": reasons[:2],
            "alert_sent": alert_dispatched,
            "alert_channel": alert_details.strip() or ("None" if risk_score != "HIGH" else "Failed")
        }

        with self._lock:
            self.state.recent_activity.insert(0, activity_entry)
            if len(self.state.recent_activity) > 50:
                self.state.recent_activity.pop()

# Global singleton instance
sentinel_manager = SentinelManager()
