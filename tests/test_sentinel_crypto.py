"""
tests/test_sentinel_crypto.py
Comprehensive unit and security regression tests for Sentinel AES-256-GCM crypto utilities.
Verifies key validation, envelope format, AAD context binding, tampering detection,
zero plaintext leaks, and fail-closed security properties.
"""

import os
import unittest
import base64
import inspect
from core.sentinel_crypto import (
    encrypt_secret,
    decrypt_secret,
    validate_master_key,
    load_master_key_from_env,
    InvalidKeyError,
    KeyNotFoundError,
    PayloadFormatError,
    UnsupportedVersionError,
    DecryptionError,
    CONTEXT_MAILBOX,
    CONTEXT_ALERT,
    MASTER_KEY_LENGTH_BYTES,
)


class TestSentinelCrypto(unittest.TestCase):
    """Rigorous verification of core/sentinel_crypto.py."""

    def setUp(self):
        # Generate clean 32-byte test key for each test
        self.master_key = os.urandom(MASTER_KEY_LENGTH_BYTES)

    def test_01_valid_32_byte_key_accepted(self):
        """Verify that an exact 32-byte bytes key is accepted by validate_master_key."""
        self.assertIsNone(validate_master_key(self.master_key))
        bytearray_key = bytearray(self.master_key)
        self.assertIsNone(validate_master_key(bytearray_key))

    def test_02_missing_key_rejected(self):
        """Verify that None, empty, or non-bytes master key is rejected."""
        with self.assertRaises(InvalidKeyError):
            validate_master_key(None)
        with self.assertRaises(InvalidKeyError):
            validate_master_key(b"")
        with self.assertRaises(InvalidKeyError):
            validate_master_key("not_bytes_string_32_chars_123456")

    def test_03_invalid_key_length_rejected(self):
        """Verify that keys with length != 32 bytes are rejected."""
        invalid_lengths = [1, 15, 16, 31, 33, 48, 64, 128]
        for length in invalid_lengths:
            with self.assertRaises(InvalidKeyError, msg=f"Key length {length} was unexpectedly accepted"):
                validate_master_key(os.urandom(length))

    def test_04_invalid_key_encoding_rejected(self):
        """Verify that malformed hex or base64 environment keys are rejected."""
        env_var = "TEST_INVALID_KEY_ENV"
        
        # Malformed hex (invalid characters)
        os.environ[env_var] = "zz" * 32
        with self.assertRaises(InvalidKeyError):
            load_master_key_from_env(env_var)

        # Invalid length hex (30 hex chars instead of 64)
        os.environ[env_var] = "aa" * 15
        with self.assertRaises(InvalidKeyError):
            load_master_key_from_env(env_var)

        # Cleanup
        os.environ.pop(env_var, None)

    def test_05_encrypt_decrypt_round_trip(self):
        """Verify standard plaintext encryption and successful decryption."""
        plaintext = "super_secret_app_password_abcd_1234"
        envelope = encrypt_secret(plaintext, self.master_key)
        self.assertTrue(envelope.startswith("v1:"))

        decrypted = decrypt_secret(envelope, self.master_key)
        self.assertEqual(decrypted, plaintext)

    def test_06_unicode_plaintext_round_trip(self):
        """Verify non-ASCII, Unicode, emoji, and multi-byte text encryption/decryption."""
        test_strings = [
            "पासवर्ड_सुरक्षा_12345",  # Hindi / Devanagari
            "パスワード_安全_98765",  # Japanese
            "🔐🛡️ Super-Secret-Key-with-Emojis 🚀",
            "München-Über-Größe-Secret!@#$%^&*()_+",
            "Complex \n Multiline \t Tabbed \r\n Secret with symbols \\ / \" '",
        ]
        for s in test_strings:
            envelope = encrypt_secret(s, self.master_key)
            decrypted = decrypt_secret(envelope, self.master_key)
            self.assertEqual(decrypted, s)

    def test_07_empty_plaintext_behavior(self):
        """Verify that empty string produces a valid authenticated envelope and decrypts back to empty."""
        envelope = encrypt_secret("", self.master_key)
        self.assertTrue(envelope.startswith("v1:"))
        
        decrypted = decrypt_secret(envelope, self.master_key)
        self.assertEqual(decrypted, "")

    def test_08_nondeterministic_encryption_with_fresh_nonces(self):
        """Verify that repeated encryption of the identical plaintext produces distinct ciphertexts."""
        secret = "static_mailbox_app_password"
        envelopes = [encrypt_secret(secret, self.master_key) for _ in range(10)]

        # All 10 envelopes must be strictly distinct
        self.assertEqual(len(set(envelopes)), 10)

        # All 10 must extract distinct nonces
        nonces = [e.split(":")[1] for e in envelopes]
        self.assertEqual(len(set(nonces)), 10)

        # All 10 must decrypt back to the original secret
        for e in envelopes:
            self.assertEqual(decrypt_secret(e, self.master_key), secret)

    def test_09_wrong_key_rejected(self):
        """Verify that decryption with a mismatched 32-byte key fails authentication."""
        plaintext = "confidential_mailbox_credential"
        envelope = encrypt_secret(plaintext, self.master_key)

        wrong_key = os.urandom(MASTER_KEY_LENGTH_BYTES)
        with self.assertRaises(DecryptionError):
            decrypt_secret(envelope, wrong_key)

    def test_10_tampered_ciphertext_rejected(self):
        """Verify that flipping even a single bit in the ciphertext or tag fails authentication."""
        plaintext = "tamper_resistance_test"
        envelope = encrypt_secret(plaintext, self.master_key)

        version, b64_nonce, b64_ct = envelope.split(":")
        ct_bytes = bytearray(base64.urlsafe_b64decode(b64_ct + "=="))

        # Flip the last byte (part of authentication tag)
        ct_bytes[-1] ^= 0x01
        tampered_b64_ct = base64.urlsafe_b64encode(ct_bytes).decode("ascii")
        tampered_envelope = f"{version}:{b64_nonce}:{tampered_b64_ct}"

        with self.assertRaises(DecryptionError):
            decrypt_secret(tampered_envelope, self.master_key)

    def test_11_tampered_nonce_rejected(self):
        """Verify that altering the nonce causes authentication failure."""
        plaintext = "nonce_tamper_test"
        envelope = encrypt_secret(plaintext, self.master_key)

        version, b64_nonce, b64_ct = envelope.split(":")
        nonce_bytes = bytearray(base64.urlsafe_b64decode(b64_nonce + "=="))

        # Flip a byte in the nonce
        nonce_bytes[0] ^= 0x01
        tampered_b64_nonce = base64.urlsafe_b64encode(nonce_bytes).decode("ascii")
        tampered_envelope = f"{version}:{tampered_b64_nonce}:{b64_ct}"

        with self.assertRaises(DecryptionError):
            decrypt_secret(tampered_envelope, self.master_key)

    def test_12_malformed_envelope_rejected(self):
        """Verify that invalid envelope structures raise PayloadFormatError."""
        malformed_examples = [
            "not_an_envelope",
            "v1",
            "v1:only_two_parts",
            "v1:part2:part3:extra_part4",
            "v1:invalid!!base64:invalid!!base64",
            f"v1:{base64.urlsafe_b64encode(b'short').decode('ascii')}:validct",  # Nonce too short
            f"v1:{base64.urlsafe_b64encode(os.urandom(12)).decode('ascii')}:{base64.urlsafe_b64encode(b'short_tag').decode('ascii')}",  # Tag too short
            "",
            "   ",
        ]
        for malformed in malformed_examples:
            with self.assertRaises((PayloadFormatError, UnsupportedVersionError)):
                decrypt_secret(malformed, self.master_key)

    def test_13_unsupported_version_rejected(self):
        """Verify that envelopes with unknown versions raise UnsupportedVersionError."""
        nonce = base64.urlsafe_b64encode(os.urandom(12)).decode("ascii")
        ct = base64.urlsafe_b64encode(os.urandom(32)).decode("ascii")

        for bad_ver in ["v0", "v2", "v99", "custom", "legacy"]:
            envelope = f"{bad_ver}:{nonce}:{ct}"
            with self.assertRaises(UnsupportedVersionError):
                decrypt_secret(envelope, self.master_key)

    def test_14_wrong_aad_context_rejected(self):
        """Verify that encryption with AAD requires matching AAD on decryption."""
        plaintext = "credential_bound_to_mailbox"
        
        # Encrypt with mailbox context
        envelope = encrypt_secret(plaintext, self.master_key, context=CONTEXT_MAILBOX)

        # Attempt to decrypt with wrong context (alert context)
        with self.assertRaises(DecryptionError):
            decrypt_secret(envelope, self.master_key, context=CONTEXT_ALERT)

        # Attempt to decrypt without context
        with self.assertRaises(DecryptionError):
            decrypt_secret(envelope, self.master_key, context=None)

    def test_15_correct_aad_context_succeeds(self):
        """Verify that decryption succeeds when correct context is provided."""
        mailbox_cred = "mailbox_secure_password"
        alert_token = "123456789:ABCdefGHIjklMNOpqrSTUvwxYZ"

        env_mailbox = encrypt_secret(mailbox_cred, self.master_key, context=CONTEXT_MAILBOX)
        env_alert = encrypt_secret(alert_token, self.master_key, context=CONTEXT_ALERT)

        self.assertEqual(decrypt_secret(env_mailbox, self.master_key, context=CONTEXT_MAILBOX), mailbox_cred)
        self.assertEqual(decrypt_secret(env_alert, self.master_key, context=CONTEXT_ALERT), alert_token)

    def test_16_plaintext_not_present_in_ciphertext(self):
        """Verify that plaintext substrings do not appear in the base64 ciphertext envelope."""
        sensitive_string = "HighlySensitiveP@ssword123456!"
        envelope = encrypt_secret(sensitive_string, self.master_key)

        self.assertNotIn(sensitive_string, envelope)
        self.assertNotIn(sensitive_string.encode("utf-8"), base64.urlsafe_b64decode(envelope.split(":")[2] + "=="))

    def test_17_no_key_hardcoded_in_source(self):
        """Inspect source code of core/sentinel_crypto.py to verify no master key is hardcoded."""
        import core.sentinel_crypto as sc
        source = inspect.getsource(sc)

        # Check for suspicious hardcoded 32-byte hex keys or secrets
        self.assertNotIn("SENTINEL_MASTER_KEY =", source)
        self.assertNotIn("MASTER_KEY =", source)
        self.assertNotIn("password123", source.lower())

    def test_18_no_plaintext_credential_logging(self):
        """Verify that core/sentinel_crypto contains no print or logging calls."""
        import core.sentinel_crypto as sc
        source = inspect.getsource(sc)

        self.assertNotIn("print(", source)
        self.assertNotIn("logging.info", source)
        self.assertNotIn("logging.debug", source)
        self.assertNotIn("logger.", source)

    def test_19_env_key_loading_fails_closed(self):
        """Verify that load_master_key_from_env fails closed when variable is missing or empty."""
        test_var = "TEST_MISSING_SENTINEL_KEY"
        
        # Unset
        os.environ.pop(test_var, None)
        with self.assertRaises(KeyNotFoundError):
            load_master_key_from_env(test_var)

        # Empty string
        os.environ[test_var] = ""
        with self.assertRaises(KeyNotFoundError):
            load_master_key_from_env(test_var)

        # Valid 64-hex key loads correctly
        sample_hex = self.master_key.hex()
        os.environ[test_var] = sample_hex
        loaded = load_master_key_from_env(test_var)
        self.assertEqual(loaded, self.master_key)

        # Valid Base64 key loads correctly
        sample_b64 = base64.urlsafe_b64encode(self.master_key).decode("ascii")
        os.environ[test_var] = sample_b64
        loaded_b64 = load_master_key_from_env(test_var)
        self.assertEqual(loaded_b64, self.master_key)

        # Cleanup
        os.environ.pop(test_var, None)

    def test_20_existing_non_sentinel_crypto_unaffected(self):
        """Verify that core/session_vault.py remains intact and independently functional."""
        from core.session_vault import _derive_key, SALT_LENGTH
        salt = os.urandom(SALT_LENGTH)
        derived = _derive_key(salt)
        self.assertIsInstance(derived, bytes)
        self.assertEqual(len(derived), 44)  # Fernet key is 32 bytes base64 encoded -> 44 chars


if __name__ == "__main__":
    unittest.main()
