import email
from email.message import Message
import hashlib
from typing import Dict, Any, List

from email.header import decode_header

def calculate_sha256(raw_bytes: Any) -> str:
    if raw_bytes is None:
        return ""
    if isinstance(raw_bytes, str):
        raw_bytes = raw_bytes.encode('utf-8', errors='replace')
    return hashlib.sha256(raw_bytes).hexdigest()

def decode_mime_words(raw_header: Any) -> str:
    """Safely decodes RFC 2047 MIME encoded words into a normalized unicode string."""
    if not raw_header:
        return ""
    if not isinstance(raw_header, str):
        raw_header = str(raw_header)
        
    if "=?" not in raw_header:
        return raw_header.strip()
        
    try:
        decoded_fragments = decode_header(raw_header)
        parts = []
        for fragment, charset in decoded_fragments:
            if isinstance(fragment, bytes):
                try:
                    parts.append(fragment.decode(charset or 'utf-8', errors='replace'))
                except Exception:
                    parts.append(fragment.decode('latin1', errors='replace'))
            else:
                parts.append(str(fragment))
        result = "".join(parts).replace("\r", " ").replace("\n", " ")
        import re
        return re.sub(r'\s+', ' ', result).strip()
    except Exception:
        return raw_header.strip()

class SecureEmailParser:
    def __init__(self, raw_bytes: Any):
        if raw_bytes is None:
            raw_bytes = b""
        elif isinstance(raw_bytes, str):
            raw_bytes = raw_bytes.encode('utf-8', errors='replace')
        self.raw_bytes = raw_bytes
        self.sha256 = calculate_sha256(raw_bytes)
        self.msg: Message = email.message_from_bytes(raw_bytes)
        self.defects = self.msg.defects

    def get_headers(self) -> Dict[str, Any]:
        """Extract all headers into a dictionary, decoding RFC 2047 MIME words and handling duplicates."""
        headers = {}
        for k, v in self.msg.items():
            k_lower = k.lower()
            decoded_val = decode_mime_words(v) if isinstance(v, str) else v
            if k_lower in headers:
                if isinstance(headers[k_lower], list):
                    headers[k_lower].append(decoded_val)
                else:
                    headers[k_lower] = [headers[k_lower], decoded_val]
            else:
                headers[k_lower] = decoded_val
        return headers

    def get_body_text(self) -> str:
        """Extract text/plain and text/html securely."""
        body = ""
        for part in self.msg.walk():
            if part.get_content_type() in ["text/plain", "text/html"]:
                charset = part.get_content_charset() or "utf-8"
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        body += payload.decode(charset, errors="replace") + "\n"
                except Exception:
                    pass
        return body.strip()

    def get_attachments_metadata(self) -> List[Dict[str, str]]:
        """List attachments without executing or extracting them."""
        attachments = []
        for part in self.msg.walk():
            if part.get_content_maintype() == "multipart":
                continue
            if part.get("Content-Disposition") is None:
                continue
            
            filename = part.get_filename()
            if filename:
                payload = part.get_payload(decode=True)
                size = len(payload) if payload else 0
                sha256 = calculate_sha256(payload) if payload else None
                attachments.append({
                    "filename": filename,
                    "content_type": part.get_content_type(),
                    "size_bytes": size,
                    "sha256": sha256
                })
        return attachments

    def parse(self) -> Dict[str, Any]:
        return {
            "sha256": self.sha256,
            "headers": self.get_headers(),
            "received_chain": self._extract_received_chain(),
            "body": self.get_body_text(),
            "attachments": self.get_attachments_metadata(),
            "defects": [str(d) for d in self.defects]
        }

    def _extract_received_chain(self) -> List[str]:
        headers = self.get_headers()
        received = headers.get("received", [])
        if isinstance(received, str):
            received = [received]
        return received
