"""
worker/logging.py
Safe logging infrastructure for EMAILSHIELD INDIA Sentinel External Worker Runtime.
Enforces redaction of capability tokens, private keys, connection strings,
passwords, and ciphertext envelopes from all worker log streams.
"""

import logging
import re
from typing import Any


# Patterns for sensitive data redaction
RE_RSA_PRIVATE_KEY = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----",
    re.MULTILINE
)
RE_DB_CONN_STRING = re.compile(
    r"(postgres(?:ql)?://[^:\s]+):(.+)@([^/@\s]+(?::\d+)?(?:/[^\s?]*)?)",
    re.IGNORECASE
)
RE_CIPHERTEXT_V1 = re.compile(r"\bv1:[0-9a-fA-F]{24}:[0-9a-fA-F]{34,}\b")
RE_CIPHERTEXT_V2 = re.compile(
    r"\bv2:[a-zA-Z0-9_\-]+:[a-zA-Z0-9_\-]+={0,2}:[a-zA-Z0-9_\-]+={0,2}:[a-zA-Z0-9_\-]+={0,2}\b"
)
RE_HEX_64 = re.compile(r"\b[0-9a-fA-F]{64}\b")
RE_PASSWORD_PARAM = re.compile(r"(password\s*[:=]\s*['\"]?)([^'\"\s,]+)(['\"]?)", re.IGNORECASE)
RE_TOKEN_PARAM = re.compile(r"(lease_token\s*[:=]\s*['\"]?)([^'\"\s,]+)(['\"]?)", re.IGNORECASE)


class SafeLoggingFilter(logging.Filter):
    """
    Log filter that intercepts log records and scrubs any sensitive credentials,
    capability tokens, private keys, database passwords, or ciphertext payloads.
    """
    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = self.redact_message(record.msg)
        if record.args:
            if isinstance(record.args, dict):
                record.args = {k: self.redact_value(v) for k, v in record.args.items()}
            elif isinstance(record.args, tuple):
                record.args = tuple(self.redact_value(v) for v in record.args)
            elif isinstance(record.args, list):
                record.args = [self.redact_value(v) for v in record.args]
        return True

    @classmethod
    def redact_message(cls, text: str) -> str:
        if not isinstance(text, str):
            return text
        
        # 1. Private keys
        text = RE_RSA_PRIVATE_KEY.sub("[REDACTED_RSA_PRIVATE_KEY]", text)
        # 2. Database connection strings
        text = RE_DB_CONN_STRING.sub(r"\1:***@\3", text)
        # 3. v1 and v2 ciphertexts
        text = RE_CIPHERTEXT_V1.sub("[REDACTED_V1_CIPHERTEXT]", text)
        text = RE_CIPHERTEXT_V2.sub("[REDACTED_V2_CIPHERTEXT]", text)
        # 4. Explicit password / token parameters
        text = RE_PASSWORD_PARAM.sub(r"\1***\3", text)
        text = RE_TOKEN_PARAM.sub(r"\1***\3", text)
        # 5. Raw 64-hex capability tokens and sha256 hashes
        text = RE_HEX_64.sub("[REDACTED_HEX_64]", text)
        return text

    @classmethod
    def redact_value(cls, val: Any) -> Any:
        if isinstance(val, str):
            return cls.redact_message(val)
        if isinstance(val, bytes):
            return b"[REDACTED_BYTES]"
        return val


def get_worker_logger(name: str = "sentinel.worker", level: int = logging.INFO) -> logging.Logger:
    """Configures and returns a worker logger equipped with SafeLoggingFilter."""
    logger = logging.getLogger(name)
    logger.setLevel(level)

    # Avoid duplicate handlers if already configured
    if not any(isinstance(f, SafeLoggingFilter) for f in logger.filters):
        logger.addFilter(SafeLoggingFilter())

    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            "[%(asctime)s] [%(name)s] [%(levelname)s] %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S"
        )
        handler.setFormatter(formatter)
        handler.addFilter(SafeLoggingFilter())
        logger.addHandler(handler)

    return logger
