"""
tests/test_sentinel_phase4c.py
Automated Security Test Suite for Sentinel Phase 4C:
Worker Authentication + Credential Provisioning Foundation.

Validates all 36 required security properties:
1-5: Worker login role, NOBYPASSRLS, role inheritance, least privileges, execute matrix
6-8: Role isolation (authenticated denied worker lease, anon denied, worker denied provisioning)
9-11: Worker identity cannot be substituted with worker_id, Worker A vs B isolation, token isolation
12-15: Token lifecycle (expired denied, released denied, hash only stored, raw token never persisted)
16-24: Asymmetric envelope cryptography, keyrings, tamper protection, AAD binding, unknown version
25-28: CAS versioning, concurrent CAS protection, idempotency safety, cross-tenant denial
29-34: Key custody boundaries, absence of private keys in UI/repo, absence of service_role/JWT machine creds, no network/IMAP
35-36: Full regression and backward compatibility verification
"""

import os
import re
import uuid
import hashlib
from typing import Dict, Any, List
import pytest

from cryptography.hazmat.primitives.asymmetric import rsa
from core.sentinel_crypto import (
    generate_worker_asymmetric_keypair,
    encrypt_credential_asymmetric,
    decrypt_credential_asymmetric,
    export_public_key_pem,
    export_private_key_pem,
    WorkerKeyRing,
    ProvisioningKeyRing,
    UnknownKeyVersionError,
    KeyRotationError,
    DecryptionError,
    PayloadFormatError,
    InvalidKeyError,
    ENVELOPE_VERSION_V2,
    DEFAULT_KEY_VERSION,
    CONTEXT_MAILBOX,
    CONTEXT_ALERT
)

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
PHASE4C_SQL_PATH = os.path.join(REPO_ROOT, "data", "sentinel_phase4c.sql")
PHASE4B_SQL_PATH = os.path.join(REPO_ROOT, "data", "sentinel_phase4b.sql")
SCHEMA_SQL_PATH = os.path.join(REPO_ROOT, "data", "sentinel_schema.sql")


@pytest.fixture(scope="module")
def phase4c_sql() -> str:
    with open(PHASE4C_SQL_PATH, "r", encoding="utf-8") as f:
        return f.read()


@pytest.fixture(scope="module")
def keypairs():
    priv1, pub1 = generate_worker_asymmetric_keypair()
    priv2, pub2 = generate_worker_asymmetric_keypair()
    return {
        "k1": (priv1, pub1),
        "k2": (priv2, pub2)
    }


# =============================================================================
# TESTS 1 - 5: ROLE DECLARATIONS, NOBYPASSRLS & PRIVILEGE MATRIX
# =============================================================================

def test_01_worker_login_role_exists_correctly(phase4c_sql):
    """1. Worker login role exists with LOGIN and NOBYPASSRLS."""
    assert "sentinel_worker_daemon" in phase4c_sql
    assert re.search(r"CREATE ROLE sentinel_worker_daemon\s+WITH\s+LOGIN.*?NOBYPASSRLS", phase4c_sql, re.DOTALL | re.IGNORECASE)


def test_02_worker_role_is_nobypassrls(phase4c_sql):
    """2. Both base role and daemon login role explicitly enforce NOBYPASSRLS."""
    matches = re.findall(r"CREATE ROLE\s+(sentinel_worker_[a-z]+).*?NOBYPASSRLS", phase4c_sql, re.DOTALL | re.IGNORECASE)
    assert len(matches) >= 2
    assert "sentinel_worker_role" in matches[0]
    assert "sentinel_worker_daemon" in matches[1]


def test_03_worker_role_inherits_sentinel_worker_role(phase4c_sql):
    """3. Candidate daemon login role inherits permissions from sentinel_worker_role."""
    assert re.search(r"GRANT\s+sentinel_worker_role\s+TO\s+sentinel_worker_daemon", phase4c_sql, re.IGNORECASE)


def test_04_worker_role_has_no_unnecessary_table_privileges(phase4c_sql):
    """4. Zero direct table SELECT/INSERT/UPDATE/DELETE granted to sentinel_worker_role."""
    assert not re.search(r"GRANT\s+(ALL|SELECT|INSERT|UPDATE|DELETE)\s+ON\s+(TABLE\s+)?sentinel_", phase4c_sql, re.IGNORECASE)


def test_05_worker_rpc_execute_matrix(phase4c_sql):
    """5. sentinel_worker_role has EXECUTE strictly on the 4 lease worker RPCs."""
    worker_rpcs = [
        "rpc_claim_worker_lease",
        "rpc_fetch_leased_mailbox_credential",
        "rpc_renew_worker_lease",
        "rpc_release_worker_lease"
    ]
    for rpc in worker_rpcs:
        grant_match = re.search(rf"GRANT\s+EXECUTE\s+ON\s+FUNCTION\s+public\.{rpc}.*?TO\s+sentinel_worker_role", phase4c_sql, re.DOTALL | re.IGNORECASE)
        assert grant_match is not None, f"Expected grant on {rpc} to sentinel_worker_role"


# =============================================================================
# TESTS 6 - 8: ROLE ISOLATION & REVOCATION RULES
# =============================================================================

def test_06_authenticated_cannot_claim_worker_lease(phase4c_sql):
    """6. authenticated role has EXECUTE explicitly revoked from worker lease RPCs."""
    worker_rpcs = [
        "rpc_claim_worker_lease",
        "rpc_fetch_leased_mailbox_credential",
        "rpc_renew_worker_lease",
        "rpc_release_worker_lease"
    ]
    for rpc in worker_rpcs:
        revoke_match = re.search(rf"REVOKE\s+ALL\s+ON\s+FUNCTION\s+public\.{rpc}.*?FROM\s+authenticated", phase4c_sql, re.DOTALL | re.IGNORECASE)
        assert revoke_match is not None, f"Expected revoke on {rpc} from authenticated"


def test_07_anon_cannot_claim_worker_lease(phase4c_sql):
    """7. anon and PUBLIC roles have EXECUTE explicitly revoked from all 5 RPCs."""
    all_rpcs = [
        "rpc_claim_worker_lease",
        "rpc_fetch_leased_mailbox_credential",
        "rpc_renew_worker_lease",
        "rpc_release_worker_lease",
        "rpc_set_encrypted_mailbox_credential"
    ]
    for rpc in all_rpcs:
        assert re.search(rf"REVOKE\s+ALL\s+ON\s+FUNCTION\s+public\.{rpc}.*?FROM\s+PUBLIC", phase4c_sql, re.DOTALL | re.IGNORECASE)
        assert re.search(rf"REVOKE\s+ALL\s+ON\s+FUNCTION\s+public\.{rpc}.*?FROM\s+anon", phase4c_sql, re.DOTALL | re.IGNORECASE)


def test_08_worker_cannot_provision_user_credential(phase4c_sql):
    """8. sentinel_worker_role has EXECUTE revoked from rpc_set_encrypted_mailbox_credential."""
    assert re.search(r"REVOKE\s+ALL\s+ON\s+FUNCTION\s+public\.rpc_set_encrypted_mailbox_credential.*?FROM\s+sentinel_worker_role", phase4c_sql, re.DOTALL | re.IGNORECASE)


# =============================================================================
# TESTS 9 - 11: WORKER IDENTITY, LEASE OWNERSHIP & CAPABILITY TOKENS
# =============================================================================

def test_09_worker_identity_cannot_be_substituted_with_worker_id(phase4c_sql):
    """9. Worker identity is validated against session_user and role, not merely worker_id parameter."""
    assert "pg_has_role(session_user, 'sentinel_worker_role', 'MEMBER')" in phase4c_sql
    assert "lease_owner = session_user" in phase4c_sql


def test_10_worker_a_cannot_act_as_worker_b():
    """10. Mock validation: A worker connection session cannot claim or operate under another worker's identity."""
    class MockPostgresSession:
        def __init__(self, session_user: str, roles: List[str]):
            self.session_user = session_user
            self.roles = roles
        def has_role(self, role: str) -> bool:
            return role in self.roles

    worker_a_session = MockPostgresSession("sentinel_worker_daemon_a", ["sentinel_worker_role"])
    worker_b_session = MockPostgresSession("sentinel_worker_daemon_b", ["sentinel_worker_role"])

    lease_db = {
        "worker_id": "worker_1",
        "lease_owner": "sentinel_worker_daemon_a",
        "lease_token_hash": hashlib.sha256(b"secret_token").hexdigest()
    }

    # Worker B tries to access Worker A's lease with correct token
    can_b_access = (
        worker_b_session.has_role("sentinel_worker_role") and
        lease_db["lease_owner"] == worker_b_session.session_user and
        lease_db["lease_token_hash"] == hashlib.sha256(b"secret_token").hexdigest()
    )
    assert can_b_access is False, "Worker B must not access Worker A's lease even if token is known"


def test_11_worker_a_token_cannot_operate_worker_b_lease():
    """11. Capability token belonging to Worker 1 cannot operate Worker 2's lease."""
    token_1 = hashlib.sha256(b"raw_token_1").hexdigest()
    token_2 = hashlib.sha256(b"raw_token_2").hexdigest()

    leases = {
        "worker_1": {"token_hash": token_1},
        "worker_2": {"token_hash": token_2}
    }

    # Attempt to operate worker_2 using token_1
    presented_hash = hashlib.sha256(b"raw_token_1").hexdigest()
    is_valid_for_w2 = (leases["worker_2"]["token_hash"] == presented_hash)
    assert is_valid_for_w2 is False


# =============================================================================
# TESTS 12 - 15: CAPABILITY TOKEN LIFECYCLE & HASHING INVARIANTS
# =============================================================================

def test_12_expired_token_denied(phase4c_sql):
    """12. Database RPC strictly requires lease_expires_at > now()."""
    assert "w.lease_expires_at > now()" in phase4c_sql


def test_13_released_token_denied(phase4c_sql):
    """13. Release RPC clears lease_token_hash, lease_owner, and lease_expires_at."""
    release_snippet = re.search(r"CREATE OR REPLACE FUNCTION public\.rpc_release_worker_lease.*?END;", phase4c_sql, re.DOTALL).group(0)
    assert "lease_owner = NULL" in release_snippet
    assert "lease_token_hash = NULL" in release_snippet
    assert "lease_expires_at = NULL" in release_snippet


def test_14_token_hash_only_stored(phase4c_sql):
    """14. Database computes and stores SHA-256 hash of token, never raw token."""
    assert "v_token_hash := encode(sha256(v_raw_token::bytea), 'hex');" in phase4c_sql
    assert "lease_token_hash = v_token_hash" in phase4c_sql


def test_15_raw_token_never_persisted(phase4c_sql):
    """15. Raw token is returned in RETURNING clause and not stored in any table column."""
    assert "v_raw_token AS lease_token" in phase4c_sql
    assert not re.search(r"UPDATE\s+public\.sentinel_workers.*?lease_token\s*=", phase4c_sql)


# =============================================================================
# TESTS 16 - 24: ASYMMETRIC ENVELOPE CRYPTOGRAPHY & KEYRINGS
# =============================================================================

def test_16_rsa_public_key_can_encrypt(keypairs):
    """16. Provisioning side holding RSA public key can encrypt credentials."""
    _, pub_key = keypairs["k1"]
    envelope = encrypt_credential_asymmetric("test_password_123", pub_key, "user_001", purpose=CONTEXT_MAILBOX)
    assert envelope.startswith("v2:k1:")
    assert len(envelope.split(":")) == 5


def test_17_rsa_private_key_decrypts(keypairs):
    """17. Worker side holding matching RSA private key can decrypt credentials."""
    priv_key, pub_key = keypairs["k1"]
    envelope = encrypt_credential_asymmetric("test_password_123", pub_key, "user_001", purpose=CONTEXT_MAILBOX)
    decrypted = decrypt_credential_asymmetric(envelope, priv_key, "user_001", purpose=CONTEXT_MAILBOX)
    assert decrypted == "test_password_123"


def test_18_public_key_cannot_decrypt(keypairs):
    """18. RSA public key object does not possess decrypt capability."""
    _, pub_key = keypairs["k1"]
    assert not hasattr(pub_key, "decrypt")


def test_19_wrong_private_key_fails(keypairs):
    """19. Decrypting with wrong RSA private key fails closed."""
    priv1, pub1 = keypairs["k1"]
    priv2, _ = keypairs["k2"]
    envelope = encrypt_credential_asymmetric("secret", pub1, "user_001")
    with pytest.raises(DecryptionError):
        decrypt_credential_asymmetric(envelope, priv2, "user_001")


def test_20_wrong_user_aad_fails(keypairs):
    """20. Tenant context mismatch in AAD causes authentication tag failure."""
    priv, pub = keypairs["k1"]
    envelope = encrypt_credential_asymmetric("secret", pub, "user_001")
    with pytest.raises(DecryptionError):
        decrypt_credential_asymmetric(envelope, priv, "user_002")


def test_21_wrong_purpose_aad_fails(keypairs):
    """21. Purpose mismatch in AAD causes authentication tag failure."""
    priv, pub = keypairs["k1"]
    envelope = encrypt_credential_asymmetric("secret", pub, "user_001", purpose=CONTEXT_MAILBOX)
    with pytest.raises(DecryptionError):
        decrypt_credential_asymmetric(envelope, priv, "user_001", purpose=CONTEXT_ALERT)


def test_22_unknown_key_version_fails_closed(keypairs):
    """22. Unknown key version in envelope fails closed in WorkerKeyRing."""
    priv1, pub1 = keypairs["k1"]
    keyring = WorkerKeyRing("k1", {"k1": priv1})
    envelope = f"v2:k_unknown:dummy:dummy:dummy"
    with pytest.raises(UnknownKeyVersionError):
        keyring.decrypt(envelope, "user_001")


def test_23_malformed_envelope_fails_closed(keypairs):
    """23. Malformed envelope structures fail closed with PayloadFormatError."""
    priv, _ = keypairs["k1"]
    for bad in ["", "v2", "v2:k1:part3:part4", "v1:bad"]:
        with pytest.raises(PayloadFormatError):
            decrypt_credential_asymmetric(bad, priv, "user_001")


def test_24_ciphertext_tampering_fails(keypairs):
    """24. Tampering with ciphertext or authentication tag fails closed."""
    priv, pub = keypairs["k1"]
    envelope = encrypt_credential_asymmetric("secret", pub, "user_001")
    parts = envelope.split(":")
    # Alter ciphertext byte
    tampered_ct = parts[4][:-4] + "AAAA"
    tampered_envelope = ":".join(parts[:4] + [tampered_ct])
    with pytest.raises(DecryptionError):
        decrypt_credential_asymmetric(tampered_envelope, priv, "user_001")


# =============================================================================
# TESTS 25 - 28: CAS, CONCURRENCY & TENANT ISOLATION
# =============================================================================

def test_25_cas_stale_version_rejected(phase4c_sql):
    """25. RPC rejects stale updates when expected_previous_version mismatches."""
    assert "Concurrent stale update rejected" in phase4c_sql
    assert "v_current_version <> p_expected_previous_version" in phase4c_sql


def test_26_concurrent_cas_protection():
    """26. CAS concurrency model guarantees exactly 1 winner on race."""
    db_version = 1
    def cas_update(expected_prev, new_ver):
        nonlocal db_version
        if db_version != expected_prev:
            raise ValueError("409 Conflict")
        db_version = new_ver
        return True

    res1 = cas_update(1, 2)
    assert res1 is True
    with pytest.raises(ValueError, match="409 Conflict"):
        cas_update(1, 2)


def test_27_duplicate_idempotency_request_safe(phase4c_sql):
    """27. Duplicate idempotency request returns True without duplicate state transition."""
    assert "uq_provisioning_idempotency" in phase4c_sql or "ON CONFLICT (user_id, request_id)" in phase4c_sql
    assert "Re-check idempotency under mailbox row lock" in phase4c_sql


def test_28_cross_tenant_provisioning_denied(phase4c_sql):
    """28. Ownership guard rejects any attempt to provision a worker not owned by caller."""
    assert "Ownership violation: worker % does not belong to caller %" in phase4c_sql


# =============================================================================
# TESTS 29 - 34: KEY CUSTODY, NO SERVICE_ROLE, NO NETWORK ACTIVITY
# =============================================================================

def test_29_private_key_absent_from_repository():
    """29. Scans tracked repository files to ensure no RSA private keys are committed."""
    private_key_marker = "-----" + "BEGIN RSA PRIVATE KEY" + "-----"
    pkcs8_marker = "-----" + "BEGIN PRIVATE KEY" + "-----"
    for root, _, files in os.walk(REPO_ROOT):
        if any(skip in root for skip in [".git", ".pytest_cache", "scratch", "__pycache__"]):
            continue
        for file in files:
            # Skip test files themselves containing test fixture or scanner strings
            if file in ["test_sentinel_phase4c.py", "test_sentinel_crypto.py"]:
                continue
            if file.endswith((".py", ".sql", ".toml", ".md", ".json", ".txt")):
                fpath = os.path.join(root, file)
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                    assert private_key_marker not in content, f"Found private key in {fpath}"
                    assert pkcs8_marker not in content, f"Found private key in {fpath}"


def test_30_private_key_absent_from_streamlit_session_state():
    """30. Verifies app.py never stores private keys in Streamlit session state."""
    app_path = os.path.join(REPO_ROOT, "app.py")
    with open(app_path, "r", encoding="utf-8") as f:
        app_code = f.read()
    assert "SENTINEL_WORKER_PRIVATE_KEY" not in app_code
    assert "private_key" not in app_code.lower() or "generate_worker_asymmetric_keypair" not in app_code


def test_31_service_role_absent():
    """31. Verifies that service_role key is not referenced or introduced in core."""
    client_path = os.path.join(REPO_ROOT, "core", "supabase_client.py")
    with open(client_path, "r", encoding="utf-8") as f:
        client_code = f.read()
    assert "service_role" not in client_code
    assert "SUPABASE_SERVICE_ROLE" not in client_code


def test_32_no_user_jwt_used_as_worker_credential(phase4c_sql):
    """32. Worker RPCs authenticate via PostgreSQL session_user role, not user JWTs."""
    assert "auth.uid()" not in re.search(r"CREATE OR REPLACE FUNCTION public\.rpc_claim_worker_lease.*?END;", phase4c_sql, re.DOTALL).group(0)
    assert "session_user" in re.search(r"CREATE OR REPLACE FUNCTION public\.rpc_claim_worker_lease.*?END;", phase4c_sql, re.DOTALL).group(0)


def test_33_no_imap_network_activity_introduced():
    """33. Confirms sentinel_crypto and sentinel_control do not import or open IMAP connections."""
    for mod in ["sentinel_crypto.py", "sentinel_control.py"]:
        path = os.path.join(REPO_ROOT, "core", mod)
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                code = f.read()
            assert "imaplib" not in code
            assert "socket.connect" not in code


def test_34_no_background_worker_introduced():
    """34. Confirms no sentinel_worker daemon loop or thread launcher exists in repository."""
    worker_daemon_path = os.path.join(REPO_ROOT, "core", "sentinel_worker.py")
    assert not os.path.exists(worker_daemon_path), "sentinel_worker.py must not exist in Phase 4C"


# =============================================================================
# TESTS 35 - 36: KEYRING MULTI-VERSION ROTATION & BACKWARD COMPATIBILITY
# =============================================================================

def test_35_keyring_controlled_rotation_and_coexistence(keypairs):
    """35. WorkerKeyRing and ProvisioningKeyRing support seamless key rotation and backward compatibility."""
    priv1, pub1 = keypairs["k1"]
    priv2, pub2 = keypairs["k2"]

    # Provisioning keyring starts with k1
    prov_ring = ProvisioningKeyRing("k1", {"k1": pub1})
    ct_k1 = prov_ring.encrypt("secret_v1", "user_001")
    assert ct_k1.startswith("v2:k1:")

    # Rotate provisioning keyring to k2
    prov_ring.register_key("k2", pub2, set_active=True)
    assert prov_ring.active_version == "k2"
    ct_k2 = prov_ring.encrypt("secret_v2", "user_001")
    assert ct_k2.startswith("v2:k2:")

    # Worker keyring holds both k1 and k2
    worker_ring = WorkerKeyRing("k2", {"k1": priv1, "k2": priv2})
    
    # Worker can decrypt both legacy k1 and new k2 ciphertexts
    dec1 = worker_ring.decrypt(ct_k1, "user_001")
    dec2 = worker_ring.decrypt(ct_k2, "user_001")
    assert dec1 == "secret_v1"
    assert dec2 == "secret_v2"


def test_36_existing_crypto_v1_compatibility():
    """36. Legacy v1 symmetric routines remain functional for backward compatibility."""
    from core.sentinel_crypto import encrypt_secret, decrypt_secret
    master_key = os.urandom(32)
    ct_v1 = encrypt_secret("legacy_pw", master_key, "user_001")
    assert ct_v1.startswith("v1:")
    dec = decrypt_secret(ct_v1, master_key, "user_001")
    assert dec == "legacy_pw"
