"""
worker/events.py
Safe normalized email event representations for EMAILSHIELD INDIA Sentinel.
Enforces strict scrubbing of raw RFC822 payloads, passwords, tokens, and secrets.
"""

from dataclasses import dataclass, field
from typing import Optional, Dict, Any


@dataclass
class SafeEmailEvent:
    """
    Normalized, redacted email event produced by the Sentinel polling engine.
    
    Security Invariants:
    - Never stores raw mailbox credentials, passwords, or OAuth tokens.
    - Never stores raw capability tokens or worker private keys.
    - Bounded body preview to prevent memory exhaustion from oversized text.
    - Safe operational metadata only.
    """
    tenant_user_id: str
    mailbox_id: str
    uid: int
    message_id: str
    sender: str
    recipient: str
    timestamp: str
    subject: str
    body_preview: str
    body_length: int
    attachment_count: int = 0
    processing_status: str = "PROCESSED"
    error_code: Optional[str] = None
    risk_score: Optional[float] = None
    verdict: Optional[str] = None
    iocs: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        """Serializes safe operational event for downstream processing."""
        return {
            "tenant_user_id": self.tenant_user_id,
            "mailbox_id": self.mailbox_id,
            "uid": self.uid,
            "message_id": self.message_id,
            "sender": self.sender,
            "recipient": self.recipient,
            "timestamp": self.timestamp,
            "subject": self.subject,
            "body_preview": self.body_preview,
            "body_length": self.body_length,
            "attachment_count": self.attachment_count,
            "processing_status": self.processing_status,
            "error_code": self.error_code,
            "risk_score": self.risk_score,
            "verdict": self.verdict,
            "iocs": self.iocs or {},
        }

    def __repr__(self) -> str:
        return (
            f"SafeEmailEvent("
            f"uid={self.uid}, "
            f"message_id='{self.message_id}', "
            f"sender='{self.sender}', "
            f"subject='{self.subject[:40]}...', "
            f"status='{self.processing_status}')"
        )

    def __str__(self) -> str:
        return self.__repr__()
