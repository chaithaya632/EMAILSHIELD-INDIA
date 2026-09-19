"""
core/sentinel_crypto.py
Authenticated Cryptographic Utilities for EMAILSHIELD INDIA Sentinel.
Implements AES-256-GCM envelope encryption with context binding (AAD),
randomized 96-bit nonces, versioned payloads, and strict fail-closed key validation.
"""

import os
import base64
from typing import Optional, Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidTag

# =====================================================================
# Constants & Envelopes
# =====================================================================
ENVELOPE_VERSION = "v1"
ENVELOPE_VERSION_V2 = "v2"
DEFAULT_KEY_VERSION = "k1"
DEFAULT_RSA_KEY_SIZE = 2048
NONCE_LENGTH_BYTES = 12       # 96-bit standard nonce recommended by NIST SP 800-38D
TAG_LENGTH_BYTES = 16         # 128-bit standard GCM authentication tag
MASTER_KEY_LENGTH_BYTES = 32  # 256-bit AES key
DEK_LENGTH_BYTES = 32         # 256-bit ephemeral Data Encryption Key

# Context identifiers for Associated Authenticated Data (AAD)
CONTEXT_MAILBOX = "sentinel_mailbox_credentials"
CONTEXT_ALERT = "sentinel_alert_dispatch_config"


# =====================================================================
# Exception Hierarchy
# =====================================================================
class SentinelCryptoError(Exception):
    """Base exception for all Sentinel cryptographic operations."""
    pass


class InvalidKeyError(SentinelCryptoError):
    """Raised when master key is invalid, incorrect length, or corrupted."""
    pass


class KeyNotFoundError(InvalidKeyError):
    """Raised when master key environment variable is missing or empty."""
    pass


class PayloadFormatError(SentinelCryptoError):
    """Raised when ciphertext envelope structure is malformed or invalid."""
    pass


class UnsupportedVersionError(PayloadFormatError):
    """Raised when ciphertext envelope version is not supported."""
    pass


class DecryptionError(SentinelCryptoError):
    """Raised when ciphertext authentication or decryption fails."""
    pass


class UnknownKeyVersionError(SentinelCryptoError):
    """Raised when an envelope specifies a key version unknown to the keyring."""
    pass


class KeyRotationError(SentinelCryptoError):
    """Raised when a key rotation operation is invalid or encounters an error."""
    pass


# =====================================================================
# Key Validation & Loading
# =====================================================================
def validate_master_key(master_key: bytes) -> None:
    """
    Validates that a master key is an exact 32-byte (256-bit) bytes object.
    Fails closed with InvalidKeyError if type or length is incorrect.
    """
    if not isinstance(master_key, (bytes, bytearray)):
        raise InvalidKeyError("Master key must be a bytes object.")
    if len(master_key) != MASTER_KEY_LENGTH_BYTES:
        raise InvalidKeyError(
            f"Master key must be exactly {MASTER_KEY_LENGTH_BYTES} bytes (256 bits). "
            f"Provided key length: {len(master_key)} bytes."
        )


def load_master_key_from_env(env_var: str = "SENTINEL_MASTER_KEY") -> bytes:
    """
    Retrieves and parses the 256-bit master key from an environment variable.
    Supports:
      1. 64-character hexadecimal string
      2. 44-character standard or URL-safe Base64 string
      3. Raw 32-byte string encoded as UTF-8
    Fails closed with KeyNotFoundError or InvalidKeyError.
    Never prints or logs the key value.
    """
    raw_val = os.environ.get(env_var)
    if not raw_val:
        raise KeyNotFoundError(f"Master key environment variable '{env_var}' is not set or empty.")

    raw_str = raw_val.strip()

    # Attempt 1: Hexadecimal string (64 hex characters)
    if len(raw_str) == 64:
        try:
            key_bytes = bytes.fromhex(raw_str)
            if len(key_bytes) == MASTER_KEY_LENGTH_BYTES:
                return key_bytes
        except ValueError:
            pass

    # Attempt 2: Base64 string (44 characters with padding, or 43 without)
    if len(raw_str) in (43, 44):
        try:
            padded = raw_str + "=" * ((4 - len(raw_str) % 4) % 4)
            key_bytes = base64.urlsafe_b64decode(padded)
            if len(key_bytes) == MASTER_KEY_LENGTH_BYTES:
                return key_bytes
        except Exception:
            pass
        try:
            key_bytes = base64.b64decode(raw_str)
            if len(key_bytes) == MASTER_KEY_LENGTH_BYTES:
                return key_bytes
        except Exception:
            pass

    # Attempt 3: Exact 32 raw bytes passed as latin1/utf-8
    key_bytes = raw_str.encode("utf-8")
    if len(key_bytes) == MASTER_KEY_LENGTH_BYTES:
        return key_bytes

    raise InvalidKeyError(
        f"Malformed master key in '{env_var}'. Key must represent exactly "
        f"{MASTER_KEY_LENGTH_BYTES} bytes (e.g., 64-character hex or 44-character base64)."
    )


# =====================================================================
# Authenticated Encryption & Decryption (AES-256-GCM)
# =====================================================================
def encrypt_secret(plaintext: str, master_key: bytes, context: Optional[str] = None) -> str:
    """
    Encrypts a plaintext string using AES-256-GCM with a fresh random 96-bit nonce.
    Binds the ciphertext to an optional Associated Authenticated Data (AAD) context.
    Returns a versioned envelope string:
        v1:<base64_nonce>:<base64_ciphertext_and_tag>

    Empty plaintext string is supported and produces a valid authenticated envelope.
    """
    if not isinstance(plaintext, str):
        raise TypeError("Plaintext must be a string.")

    validate_master_key(master_key)

    nonce = os.urandom(NONCE_LENGTH_BYTES)
    data = plaintext.encode("utf-8")
    aad = context.encode("utf-8") if context is not None else None

    aesgcm = AESGCM(master_key)
    ct_and_tag = aesgcm.encrypt(nonce, data, aad)

    b64_nonce = base64.urlsafe_b64encode(nonce).decode("ascii")
    b64_ct = base64.urlsafe_b64encode(ct_and_tag).decode("ascii")

    return f"{ENVELOPE_VERSION}:{b64_nonce}:{b64_ct}"


def decrypt_secret(envelope: str, master_key: bytes, context: Optional[str] = None) -> str:
    """
    Decrypts a versioned AES-256-GCM ciphertext envelope and verifies authentication tag.
    Verifies Associated Authenticated Data (AAD) context if specified.
    Fails closed on wrong key, corrupted ciphertext, altered nonce, or mismatched context.
    Returns the original plaintext string.
    """
    if not isinstance(envelope, str) or not envelope.strip():
        raise PayloadFormatError("Envelope must be a non-empty string.")

    validate_master_key(master_key)

    parts = envelope.strip().split(":")
    if len(parts) != 3:
        raise PayloadFormatError(
            f"Invalid ciphertext envelope structure: expected 3 colon-delimited segments, got {len(parts)}."
        )

    version, b64_nonce, b64_ct = parts

    if version != ENVELOPE_VERSION:
        raise UnsupportedVersionError(
            f"Unsupported ciphertext envelope version '{version}'. Supported versions: ['{ENVELOPE_VERSION}']."
        )

    try:
        # Add padding if stripped
        padded_nonce = b64_nonce + "=" * ((4 - len(b64_nonce) % 4) % 4)
        nonce = base64.urlsafe_b64decode(padded_nonce)
    except Exception as e:
        raise PayloadFormatError(f"Nonce decoding failed: {e}")

    if len(nonce) != NONCE_LENGTH_BYTES:
        raise PayloadFormatError(
            f"Invalid nonce length: expected {NONCE_LENGTH_BYTES} bytes, got {len(nonce)}."
        )

    try:
        padded_ct = b64_ct + "=" * ((4 - len(b64_ct) % 4) % 4)
        ct_and_tag = base64.urlsafe_b64decode(padded_ct)
    except Exception as e:
        raise PayloadFormatError(f"Ciphertext decoding failed: {e}")

    if len(ct_and_tag) < TAG_LENGTH_BYTES:
        raise PayloadFormatError(
            f"Ciphertext payload length ({len(ct_and_tag)} bytes) is shorter than the required "
            f"{TAG_LENGTH_BYTES}-byte authentication tag."
        )

    aad = context.encode("utf-8") if context is not None else None
    aesgcm = AESGCM(master_key)

    try:
        decrypted_bytes = aesgcm.decrypt(nonce, ct_and_tag, aad)
    except InvalidTag:
        raise DecryptionError(
            "Decryption failed: cryptographic authentication tag verification failed. "
            "Invalid key, corrupted ciphertext, altered nonce, or mismatched context."
        )
    except Exception as e:
        raise DecryptionError(f"Decryption failed: {str(e)}")

    try:
        return decrypted_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raise DecryptionError("Decrypted payload is not valid UTF-8 text.")


# =====================================================================
# Asymmetric Key Management & Envelope Cryptography (Phase 4B)
# =====================================================================
def generate_worker_asymmetric_keypair(key_size: int = DEFAULT_RSA_KEY_SIZE) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """
    Generates a cryptographically strong RSA keypair for worker envelope encryption.
    Default key size: 2048 bits with public exponent 65537.
    """
    if key_size < 2048:
        raise InvalidKeyError(f"RSA key size must be at least 2048 bits (got {key_size}).")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )
    return private_key, private_key.public_key()


generate_rsa_keypair = generate_worker_asymmetric_keypair


def export_public_key_pem(public_key: rsa.RSAPublicKey) -> str:
    """Exports an RSA public key to standard PEM format (SubjectPublicKeyInfo)."""
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise InvalidKeyError("Key must be an instance of rsa.RSAPublicKey.")
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("ascii")


def export_private_key_pem(private_key: rsa.RSAPrivateKey) -> str:
    """Exports an RSA private key to unencrypted PKCS#8 PEM format."""
    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise InvalidKeyError("Key must be an instance of rsa.RSAPrivateKey.")
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode("ascii")


def load_public_key_from_pem(pem_str: str) -> rsa.RSAPublicKey:
    """Loads an RSA public key from a PEM string. Fails closed with InvalidKeyError."""
    if not isinstance(pem_str, str) or not pem_str.strip():
        raise InvalidKeyError("Public key PEM string cannot be empty.")
    try:
        key = serialization.load_pem_public_key(pem_str.strip().encode("ascii"))
        if not isinstance(key, rsa.RSAPublicKey):
            raise InvalidKeyError("Key is not an RSA public key.")
        return key
    except Exception as e:
        raise InvalidKeyError(f"Failed to parse public key PEM: {e}")


def load_private_key_from_pem(pem_str: str) -> rsa.RSAPrivateKey:
    """Loads an RSA private key from an unencrypted PKCS#8 PEM string. Fails closed."""
    if not isinstance(pem_str, str) or not pem_str.strip():
        raise InvalidKeyError("Private key PEM string cannot be empty.")
    try:
        key = serialization.load_pem_private_key(pem_str.strip().encode("ascii"), password=None)
        if not isinstance(key, rsa.RSAPrivateKey):
            raise InvalidKeyError("Key is not an RSA private key.")
        return key
    except Exception as e:
        raise InvalidKeyError(f"Failed to parse private key PEM: {e}")


def load_public_key_from_env(env_var: str = "SENTINEL_WORKER_PUBLIC_KEY") -> rsa.RSAPublicKey:
    """
    Retrieves and parses the worker public key from environment variables,
    Streamlit secrets, or local configuration.
    Used in Edge Function / provisioning context. Fails closed.
    """
    val = os.environ.get(env_var)
    if not val:
        try:
            import streamlit as st
            val = st.secrets.get(env_var)
        except Exception:
            pass
    if not val:
        try:
            from worker.imap_client import _lookup_local_env_var
            val = _lookup_local_env_var(env_var)
        except Exception:
            pass
    if not val:
        raise KeyNotFoundError(f"Worker public key environment variable '{env_var}' is not set or empty.")
    return load_public_key_from_pem(val)


def load_private_key_from_env(env_var: str = "SENTINEL_WORKER_PRIVATE_KEY") -> rsa.RSAPrivateKey:
    """
    Retrieves and parses the worker private key from environment variables.
    Used strictly in isolated Worker Daemon context. Fails closed.
    """
    val = os.environ.get(env_var)
    if not val:
        raise KeyNotFoundError(f"Worker private key environment variable '{env_var}' is not set or empty.")
    return load_private_key_from_pem(val)


def encrypt_credential_asymmetric(
    plaintext: str,
    public_key: rsa.RSAPublicKey,
    user_id: str,
    purpose: str = CONTEXT_MAILBOX,
    key_version: str = DEFAULT_KEY_VERSION
) -> str:
    """
    Encrypts a plaintext credential using Asymmetric Hybrid Envelope Encryption:
    1. Generates an ephemeral 256-bit Data Encryption Key (DEK).
    2. Encrypts plaintext with DEK via AES-256-GCM, cryptographically bound to
       Associated Authenticated Data (AAD) containing the tenant's user_id and purpose.
    3. Wraps the DEK using the Worker's RSA Public Key with RSA-OAEP (SHA-256).
    4. Returns a versioned envelope string:
       v2:<key_version>:<b64_wrapped_dek>:<b64_nonce>:<b64_ciphertext_and_tag>

    Security Invariant: The encryptor possesses ONLY the Public Key and cannot decrypt.
    Plaintext lifetime in memory is minimized.
    """
    if not isinstance(plaintext, str):
        raise TypeError("Plaintext must be a string.")
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise InvalidKeyError("public_key must be an instance of rsa.RSAPublicKey.")
    if not isinstance(user_id, str) or not user_id.strip():
        raise ValueError("user_id is required for cryptographic AAD tenant binding.")

    # 1. Ephemeral DEK generation
    dek = AESGCM.generate_key(bit_length=256)

    # 2. Asymmetric key wrapping of DEK via RSA-OAEP (SHA-256)
    try:
        wrapped_dek = public_key.encrypt(
            dek,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except Exception as e:
        raise SentinelCryptoError(f"DEK key wrapping failed: {e}")

    # 3. Payload encryption via AES-256-GCM
    nonce = os.urandom(NONCE_LENGTH_BYTES)
    clean_user = user_id.strip()
    clean_purpose = purpose.strip() if purpose else CONTEXT_MAILBOX
    clean_kv = key_version.strip() if key_version else DEFAULT_KEY_VERSION

    aad = f"EMAILSHIELD:{clean_purpose}:{clean_user}:{clean_kv}".encode("utf-8")
    aesgcm = AESGCM(dek)
    ct_and_tag = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), aad)

    # 4. Serialize envelope components
    b64_wrapped_dek = base64.urlsafe_b64encode(wrapped_dek).decode("ascii")
    b64_nonce = base64.urlsafe_b64encode(nonce).decode("ascii")
    b64_ct = base64.urlsafe_b64encode(ct_and_tag).decode("ascii")

    return f"{ENVELOPE_VERSION_V2}:{clean_kv}:{b64_wrapped_dek}:{b64_nonce}:{b64_ct}"


def decrypt_credential_asymmetric(
    envelope: str,
    private_key: rsa.RSAPrivateKey,
    user_id: str,
    purpose: str = CONTEXT_MAILBOX,
    expected_key_version: Optional[str] = None
) -> str:
    """
    Decrypts a version 2 asymmetric hybrid ciphertext envelope.
    1. Unwraps the ephemeral DEK using the Worker's RSA Private Key via RSA-OAEP.
    2. Verifies cryptographic AAD context matching tenant user_id, purpose, and key version.
    3. Authenticates and decrypts the credential via AES-256-GCM.
    Fails closed on wrong private key, tampered wrapped DEK, tampered nonce/ciphertext,
    or mismatched tenant user_id.
    """
    if not isinstance(envelope, str) or not envelope.strip():
        raise PayloadFormatError("Envelope must be a non-empty string.")
    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise InvalidKeyError("private_key must be an instance of rsa.RSAPrivateKey.")
    if not isinstance(user_id, str) or not user_id.strip():
        raise ValueError("user_id is required for cryptographic AAD tenant binding.")

    parts = envelope.strip().split(":")
    if len(parts) != 5:
        raise PayloadFormatError(
            f"Invalid asymmetric envelope structure: expected 5 colon-delimited segments, got {len(parts)}."
        )

    version, key_version, b64_wdek, b64_nonce, b64_ct = parts

    if version != ENVELOPE_VERSION_V2:
        raise UnsupportedVersionError(
            f"Unsupported ciphertext envelope version '{version}'. Expected '{ENVELOPE_VERSION_V2}'."
        )

    if expected_key_version is not None and key_version != expected_key_version:
        raise DecryptionError(
            f"Envelope key version mismatch: expected '{expected_key_version}', got '{key_version}'."
        )

    # Decode base64 components
    try:
        pad_wdek = b64_wdek + "=" * ((4 - len(b64_wdek) % 4) % 4)
        wrapped_dek = base64.urlsafe_b64decode(pad_wdek)

        pad_nonce = b64_nonce + "=" * ((4 - len(b64_nonce) % 4) % 4)
        nonce = base64.urlsafe_b64decode(pad_nonce)

        pad_ct = b64_ct + "=" * ((4 - len(b64_ct) % 4) % 4)
        ct_and_tag = base64.urlsafe_b64decode(pad_ct)
    except Exception as e:
        raise PayloadFormatError(f"Envelope base64 decoding failed: {e}")

    if len(nonce) != NONCE_LENGTH_BYTES:
        raise PayloadFormatError(f"Invalid nonce length ({len(nonce)} bytes). Expected {NONCE_LENGTH_BYTES} bytes.")
    if len(ct_and_tag) < TAG_LENGTH_BYTES:
        raise PayloadFormatError("Ciphertext payload is shorter than authentication tag.")

    # 1. Unwrap DEK using Worker Private Key
    try:
        dek = private_key.decrypt(
            wrapped_dek,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except Exception as e:
        raise DecryptionError(f"Asymmetric DEK unwrapping failed: {e}")

    # 2. Reconstruct exact AAD context
    clean_user = user_id.strip()
    clean_purpose = purpose.strip() if purpose else CONTEXT_MAILBOX
    aad = f"EMAILSHIELD:{clean_purpose}:{clean_user}:{key_version}".encode("utf-8")

    # 3. Authenticate and decrypt payload
    aesgcm = AESGCM(dek)
    try:
        decrypted_bytes = aesgcm.decrypt(nonce, ct_and_tag, aad)
    except InvalidTag:
        raise DecryptionError(
            "Decryption failed: cryptographic authentication tag verification failed. "
            "Invalid key, corrupted ciphertext, altered nonce, or mismatched tenant user context."
        )
    except Exception as e:
        raise DecryptionError(f"Decryption failed: {str(e)}")

    try:
        return decrypted_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raise DecryptionError("Decrypted payload is not valid UTF-8 text.")


# =====================================================================
# Keyring & Multi-Version Key Management (Phase 4C)
# =====================================================================

class WorkerKeyRing:
    """
    Manages versioned RSA private keys for the external Sentinel worker runtime.
    Enforces strict key version selection during envelope decryption:
    - Multiple key versions can be registered for controlled rotation.
    - Decryption selects the exact private key matching the envelope's key_version.
    - Unknown key versions fail closed with UnknownKeyVersionError.
    """
    def __init__(self, active_version: Optional[str] = None, keys: Optional[dict] = None):
        self._keys: dict = {}
        if keys:
            for k, v in keys.items():
                self.register_key(k, v)
        if active_version is None and keys:
            active_version = next(iter(keys.keys()))
        if keys and active_version not in self._keys:
            raise KeyRotationError(f"Active key version '{active_version}' not found in provided keys.")
        self._active_version = active_version or DEFAULT_KEY_VERSION

    @property
    def active_version(self) -> str:
        return self._active_version

    def register_key(self, version_id: str, private_key: rsa.RSAPrivateKey, set_active: bool = False) -> None:
        if not isinstance(version_id, str) or not version_id.strip():
            raise KeyRotationError("version_id must be a non-empty string.")
        if not isinstance(private_key, rsa.RSAPrivateKey):
            raise InvalidKeyError("Key must be an instance of rsa.RSAPrivateKey.")
        clean_v = version_id.strip()
        self._keys[clean_v] = private_key
        if set_active or not hasattr(self, "_active_version") or not self._active_version:
            self._active_version = clean_v

    def get_key(self, version_id: str) -> rsa.RSAPrivateKey:
        clean_v = version_id.strip() if isinstance(version_id, str) else ""
        if clean_v not in self._keys:
            raise UnknownKeyVersionError(
                f"Unknown key version '{version_id}'. Available key versions: {list(self._keys.keys())}"
            )
        return self._keys[clean_v]

    def has_version(self, version_id: str) -> bool:
        return version_id.strip() in self._keys if isinstance(version_id, str) else False

    def list_versions(self) -> list:
        return list(self._keys.keys())

    def decrypt(
        self,
        envelope: str,
        user_id: str,
        purpose: str = CONTEXT_MAILBOX
    ) -> str:
        """
        Extracts key_version from the envelope, resolves the matching private key,
        and decrypts. Fails closed if the key version is unknown or mismatched.
        """
        if not isinstance(envelope, str) or not envelope.strip():
            raise PayloadFormatError("Envelope must be a non-empty string.")
        parts = envelope.strip().split(":")
        if len(parts) != 5:
            raise PayloadFormatError(f"Invalid asymmetric envelope structure: expected 5 parts, got {len(parts)}.")
        key_ver = parts[1]
        private_key = self.get_key(key_ver)
        return decrypt_credential_asymmetric(
            envelope,
            private_key,
            user_id,
            purpose=purpose,
            expected_key_version=key_ver
        )


class ProvisioningKeyRing:
    """
    Manages versioned RSA public keys for the credential provisioning boundary.
    - Possesses ONLY public keys; possesses zero decryption capability.
    - Encrypts using designated active public key version.
    - Can inspect public keys by version.
    """
    def __init__(self, active_version: Optional[str] = None, keys: Optional[dict] = None):
        self._keys: dict = {}
        if keys:
            for k, v in keys.items():
                self.register_key(k, v)
        if active_version is None and keys:
            active_version = next(iter(keys.keys()))
        if keys and active_version not in self._keys:
            raise KeyRotationError(f"Active key version '{active_version}' not found in provided keys.")
        self._active_version = active_version or DEFAULT_KEY_VERSION

    @property
    def active_version(self) -> str:
        return self._active_version

    def register_key(self, version_id: str, public_key: rsa.RSAPublicKey, set_active: bool = False) -> None:
        if not isinstance(version_id, str) or not version_id.strip():
            raise KeyRotationError("version_id must be a non-empty string.")
        if not isinstance(public_key, rsa.RSAPublicKey):
            raise InvalidKeyError("Key must be an instance of rsa.RSAPublicKey.")
        clean_v = version_id.strip()
        self._keys[clean_v] = public_key
        if set_active or not hasattr(self, "_active_version") or not self._active_version:
            self._active_version = clean_v

    def get_key(self, version_id: str) -> rsa.RSAPublicKey:
        clean_v = version_id.strip() if isinstance(version_id, str) else ""
        if clean_v not in self._keys:
            raise UnknownKeyVersionError(
                f"Unknown public key version '{version_id}'. Available versions: {list(self._keys.keys())}"
            )
        return self._keys[clean_v]

    def has_version(self, version_id: str) -> bool:
        return version_id.strip() in self._keys if isinstance(version_id, str) else False

    def list_versions(self) -> list:
        return list(self._keys.keys())

    def get_public_key(self, version_id: Optional[str] = None) -> rsa.RSAPublicKey:
        target_version = version_id if version_id else self._active_version
        return self.get_key(target_version)

    def encrypt(
        self,
        plaintext: str,
        user_id: str,
        purpose: str = CONTEXT_MAILBOX,
        key_version: Optional[str] = None
    ) -> str:
        """
        Encrypts plaintext credential using the specified or active public key version.
        Cannot decrypt under any circumstance.
        """
        target_version = key_version if key_version else self._active_version
        pub_key = self.get_key(target_version)
        return encrypt_credential_asymmetric(
            plaintext,
            pub_key,
            user_id,
            purpose=purpose,
            key_version=target_version
        )


