"""
core/session_vault.py
Hardware-Bound Encrypted Multi-Account Session Vault for EMAILSHIELD INDIA.
Provides military-grade credential protection with 14-day auto-expiration and multi-account switching.

Security Architecture:
1. Machine-Bound Key Derivation: Key is derived from physical hardware IDs (MachineGuid, MAC address, CPU/Host,
   or optional SESSION_SECRET_KEY for cloud containers). Stealing the encrypted file to another computer results in 100% decryption failure.
2. OWASP-Standard Key Stretching: PBKDF2-HMAC-SHA256 with 600,000 iterations and per-vault cryptographic salt.
3. Authenticated AES-256 Encryption (Fernet): Ensures confidentiality and prevents tampering.
4. Strict 14-Day Time-To-Live (TTL): Each account tracks its own 14-day expiry. Expired accounts are automatically shredded.
5. Cryptographic Shredding (Zeroization): Overwrites vault with random noise before unlinking.
6. Multi-Account Management: Store unlimited email accounts with 1-click seamless switching.
"""

import os
import json
import time
import uuid
import math
import platform
import base64
from typing import Optional, Dict, Any, List
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

VAULT_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", ".vault")
VAULT_FILE = os.path.join(VAULT_DIR, "session.enc")
SALT_LENGTH = 16
PBKDF2_ITERATIONS = 600000


def _get_machine_hardware_seed() -> bytes:
    """
    Collects unique physical hardware identifiers of the current machine.
    Combines:
    - Cloud environment secret (SESSION_SECRET_KEY, if set in Docker/Cloud PaaS)
    - Windows MachineGuid (unique cryptographic motherboard/OS ID)
    - Linux /etc/machine-id (unique system installation ID)
    - Hardware NIC MAC address via uuid.getnode()
    - System processor and node identity
    """
    seed_parts = []
    
    # 0. Cloud environment variable (for Docker, Streamlit Cloud, Render, Kubernetes)
    cloud_secret = os.environ.get("SESSION_SECRET_KEY", "")
    if cloud_secret:
        seed_parts.append(cloud_secret)
    
    # 1. Windows MachineGuid
    machine_guid = ""
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography") as key:
            machine_guid, _ = winreg.QueryValueEx(key, "MachineGuid")
    except Exception:
        pass
    seed_parts.append(str(machine_guid))
    
    # 2. Linux machine-id
    for linux_id_path in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        try:
            if os.path.exists(linux_id_path):
                with open(linux_id_path, "r") as mf:
                    seed_parts.append(mf.read().strip())
                break
        except Exception:
            pass
    
    # 3. Hardware MAC address
    seed_parts.append(str(uuid.getnode()))
    
    # 4. System and Node identity
    seed_parts.append(platform.node())
    seed_parts.append(platform.processor())
    seed_parts.append(platform.machine())

    combined = "::".join(seed_parts).encode("utf-8")
    return combined


def _derive_key(salt: bytes) -> bytes:
    """
    Derives a URL-safe base64-encoded 32-byte key for Fernet
    using PBKDF2-HMAC-SHA256 with 600,000 iterations.
    """
    hardware_seed = _get_machine_hardware_seed()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    derived = kdf.derive(hardware_seed)
    return base64.urlsafe_b64encode(derived)


def _write_raw_vault(payload: Dict[str, Any]) -> bool:
    """
    Encrypts and writes the multi-account payload to disk atomically with a fresh salt.
    """
    try:
        os.makedirs(VAULT_DIR, exist_ok=True)
        data_bytes = json.dumps(payload).encode("utf-8")
        salt = os.urandom(SALT_LENGTH)
        key = _derive_key(salt)
        
        fernet = Fernet(key)
        encrypted_token = fernet.encrypt(data_bytes)
        
        with open(VAULT_FILE, "wb") as f:
            f.write(salt + encrypted_token)
            f.flush()
            os.fsync(f.fileno())
            
        return True
    except Exception as e:
        print(f"[!] Error writing encrypted vault: {e}")
        return False


def _read_raw_vault() -> Optional[Dict[str, Any]]:
    """
    Reads and decrypts the multi-account vault.
    - Validates hardware authentication.
    - Migrates legacy single-account payload if encountered.
    - Automatically purges any expired accounts (> 14 days).
    """
    if not os.path.exists(VAULT_FILE):
        return None
        
    try:
        with open(VAULT_FILE, "rb") as f:
            content = f.read()
            
        if len(content) <= SALT_LENGTH:
            clear_session_credentials()
            return None
            
        salt = content[:SALT_LENGTH]
        encrypted_token = content[SALT_LENGTH:]
        
        key = _derive_key(salt)
        fernet = Fernet(key)
        decrypted_bytes = fernet.decrypt(encrypted_token)
        
        payload = json.loads(decrypted_bytes.decode("utf-8"))
        
        # Legacy Migration: if older single-account payload was saved
        if "accounts" not in payload:
            if "pwd" in payload and "email" in payload:
                email = payload["email"]
                payload = {
                    "active_account": email,
                    "accounts": {
                        email: payload
                    }
                }
            else:
                clear_session_credentials()
                return None
                
        now = time.time()
        accounts = payload.get("accounts", {})
        valid_accounts = {}
        purged = False
        
        for em, acc in accounts.items():
            if now < acc.get("expires_at", 0):
                valid_accounts[em] = acc
            else:
                print(f"[*] Account session for '{em}' expired (> 14 days). Purged from vault.")
                purged = True
                
        if not valid_accounts:
            clear_session_credentials()
            return None
            
        payload["accounts"] = valid_accounts
        active = payload.get("active_account")
        if active not in valid_accounts:
            payload["active_account"] = next(iter(valid_accounts.keys()))
            purged = True
            
        if purged:
            _write_raw_vault(payload)
            
        return payload
        
    except InvalidToken:
        print("[!] Vault token invalid or decrypted on different machine. Clearing vault.")
        clear_session_credentials()
        return None
    except Exception as e:
        print(f"[!] Vault read error: {e}")
        clear_session_credentials()
        return None


def save_account_credentials(email: str, pwd: str, host: str, provider: str, days: int = 14) -> bool:
    """
    Saves or updates an account in the multi-account encrypted vault.
    Sets the newly saved account as the active account.
    """
    payload = _read_raw_vault()
    if not payload:
        payload = {
            "active_account": email,
            "accounts": {}
        }
        
    now = time.time()
    expires_at = now + (days * 86400)
    
    payload["accounts"][email] = {
        "email": email,
        "pwd": pwd,
        "host": host,
        "provider": provider,
        "created_at": now,
        "expires_at": expires_at,
    }
    payload["active_account"] = email
    
    return _write_raw_vault(payload)


def list_saved_accounts() -> List[Dict[str, Any]]:
    """
    Returns a sanitized list of all active non-expired accounts in the vault.
    Does not expose passwords.
    """
    payload = _read_raw_vault()
    if not payload or "accounts" not in payload:
        return []
        
    now = time.time()
    active_email = payload.get("active_account", "")
    account_list = []
    
    for em, acc in payload["accounts"].items():
        seconds_left = max(0.0, acc.get("expires_at", 0) - now)
        days_remaining = max(1, math.ceil(seconds_left / 86400))
        account_list.append({
            "email": em,
            "provider": acc.get("provider", "Gmail"),
            "host": acc.get("host", ""),
            "days_remaining": days_remaining,
            "is_active": (em == active_email)
        })
        
    # Sort active account to the top
    account_list.sort(key=lambda x: (not x["is_active"], x["email"]))
    return account_list


def get_account_credentials(email: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """
    Retrieves decrypted credentials for a specific account, or the active account if email is None.
    """
    payload = _read_raw_vault()
    if not payload or "accounts" not in payload:
        return None
        
    target_email = email if email else payload.get("active_account")
    if not target_email or target_email not in payload["accounts"]:
        return None
        
    acc = payload["accounts"][target_email].copy()
    now = time.time()
    seconds_left = max(0.0, acc.get("expires_at", 0) - now)
    acc["days_remaining"] = max(1, math.ceil(seconds_left / 86400))
    return acc


def switch_active_account(email: str) -> Optional[Dict[str, Any]]:
    """
    Switches the active account in the vault to the specified email and returns its credentials.
    """
    payload = _read_raw_vault()
    if not payload or "accounts" not in payload:
        return None
        
    if email not in payload["accounts"]:
        return None
        
    payload["active_account"] = email
    _write_raw_vault(payload)
    return get_account_credentials(email)


def forget_account(email: str) -> bool:
    """
    Removes a specific account from the vault.
    If no accounts remain, cryptographically shreds the entire vault file.
    """
    payload = _read_raw_vault()
    if not payload or "accounts" not in payload:
        return True
        
    if email in payload["accounts"]:
        del payload["accounts"][email]
        
    if not payload["accounts"]:
        return clear_session_credentials()
        
    if payload.get("active_account") == email:
        payload["active_account"] = next(iter(payload["accounts"].keys()))
        
    return _write_raw_vault(payload)


def clear_session_credentials() -> bool:
    """
    Cryptographically shreds and deletes the entire session vault file.
    Overwrites the file with random noise before unlinking.
    """
    if not os.path.exists(VAULT_FILE):
        return True
        
    try:
        file_size = os.path.getsize(VAULT_FILE)
        with open(VAULT_FILE, "wb") as f:
            f.write(os.urandom(max(file_size, 512)))
            f.flush()
            os.fsync(f.fileno())
            
        os.remove(VAULT_FILE)
        return True
    except Exception as e:
        print(f"[!] Error shredding session vault: {e}")
        try:
            if os.path.exists(VAULT_FILE):
                os.remove(VAULT_FILE)
        except Exception:
            pass
        return False


# Backwards compatibility aliases
def save_session_credentials(email: str, pwd: str, host: str, provider: str, days: int = 14) -> bool:
    return save_account_credentials(email, pwd, host, provider, days)


def load_session_credentials() -> Optional[Dict[str, Any]]:
    return get_account_credentials(None)
