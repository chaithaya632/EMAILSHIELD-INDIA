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

import os
import re

MAX_RAW_EMAIL_SIZE_BYTES = 10 * 1024 * 1024  # 10MB hard limit for raw uploaded email
MAX_HEADER_COUNT = 250                       # Maximum number of headers inspected
MAX_HEADER_VALUE_LEN = 32 * 1024             # 32KB limit per header value
MAX_BODY_CHARS = 1024 * 1024                 # 1MB limit for extracted plain/HTML text
MAX_ATTACHMENT_COUNT = 25                    # Maximum attachment metadata entries
MAX_ATTACHMENT_SIZE_BYTES = 10 * 1024 * 1024 # 10MB limit per attachment payload
MAX_MIME_PARTS = 100                         # Maximum MIME tree parts walked


def sanitize_attachment_filename(filename: str) -> str:
    """Sanitize attachment filename to prevent path traversal or unsafe characters."""
    if not filename or not isinstance(filename, str):
        return "attachment.bin"
    normalized = filename.replace("\\", "/")
    base = os.path.basename(normalized)
    clean = re.sub(r'[^a-zA-Z0-9_.-]', '_', base).strip('._')
    return clean or "attachment.bin"


class SecureEmailParser:
    def __init__(self, raw_bytes: Any):
        if raw_bytes is None:
            raw_bytes = b""
        elif isinstance(raw_bytes, str):
            raw_bytes = raw_bytes.encode('utf-8', errors='replace')
        if len(raw_bytes) > MAX_RAW_EMAIL_SIZE_BYTES:
            raise ValueError(
                f"Email payload exceeds maximum allowed size ({len(raw_bytes)} bytes > {MAX_RAW_EMAIL_SIZE_BYTES} bytes)."
            )
        self.raw_bytes = raw_bytes
        self.sha256 = calculate_sha256(raw_bytes)
        try:
            self.msg: Message = email.message_from_bytes(raw_bytes)
            self.defects = list(self.msg.defects)
        except Exception as err:
            self.msg = email.message_from_bytes(b"")
            self.defects = [f"MalformedEmailPayload: {type(err).__name__}"]

    def get_headers(self) -> Dict[str, Any]:
        """Extract all headers into a dictionary, decoding RFC 2047 MIME words and handling duplicates."""
        headers = {}
        for count, (k, v) in enumerate(self.msg.items()):
            if count >= MAX_HEADER_COUNT:
                headers["x-sentinel-parser-warning"] = "Header count threshold reached; remaining headers truncated."
                break
            k_lower = k.lower()
            if isinstance(v, str) and len(v) > MAX_HEADER_VALUE_LEN:
                v = v[:MAX_HEADER_VALUE_LEN]
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
        """Extract text/plain and text/html securely with bounded memory allocation."""
        body = ""
        walk_count = 0
        for part in self.msg.walk():
            walk_count += 1
            if walk_count > MAX_MIME_PARTS:
                break
            if part.get_content_type() in ["text/plain", "text/html"]:
                charset = part.get_content_charset() or "utf-8"
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        decoded = payload.decode(charset, errors="replace")
                        if len(body) + len(decoded) > MAX_BODY_CHARS:
                            remaining_chars = max(0, MAX_BODY_CHARS - len(body))
                            body += decoded[:remaining_chars] + "\n[TRUNCATED: Body size limit exceeded]\n"
                            break
                        body += decoded + "\n"
                except Exception:
                    pass
        return body.strip()

    def get_attachments_metadata(self) -> List[Dict[str, str]]:
        """List attachments without executing or extracting them, strictly bounded."""
        attachments = []
        walk_count = 0
        for part in self.msg.walk():
            walk_count += 1
            if walk_count > MAX_MIME_PARTS or len(attachments) >= MAX_ATTACHMENT_COUNT:
                break
            if part.get_content_maintype() == "multipart":
                continue
            if part.get("Content-Disposition") is None:
                continue
            
            raw_filename = part.get_filename()
            if raw_filename:
                clean_filename = sanitize_attachment_filename(raw_filename)
                try:
                    payload = part.get_payload(decode=True)
                except Exception:
                    payload = b""
                if payload and len(payload) > MAX_ATTACHMENT_SIZE_BYTES:
                    size = len(payload)
                    sha256 = calculate_sha256(payload[: 1024 * 1024])
                else:
                    size = len(payload) if payload else 0
                    sha256 = calculate_sha256(payload) if payload else None
                attachments.append({
                    "filename": clean_filename,
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

