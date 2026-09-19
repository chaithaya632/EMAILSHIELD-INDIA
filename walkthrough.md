# EMAILSHIELD INDIA — Consolidated Authorization & Data-Isolation Audit Walkthrough

## Executive Summary

This security remediation and audit consolidated all authorization and multi-tenant data-isolation mechanisms across EMAILSHIELD INDIA into **ONE unified, reusable authorization model**.

The architecture enforces the single-pass authorization chain:
```text
REQUEST ➔ AUTHENTICATION ➔ USER ID ➔ TENANT ➔ RESOURCE OWNERSHIP ➔ RLS ➔ AUTHORIZED DATA
```

### Core Security Guarantees:
1. **Zero Unauthenticated Access**: Anonymous/logged-out visitors are denied all private cases, indicators, telemetry, reports, and alerts.
2. **Fail Closed**: Any missing, invalid, or mismatched authorization parameter fails closed immediately. Direct backend calls with `client=None` or `user_id=None` never fall through to shared local SQLite or disk files when Supabase is active or in multi-user mode.
3. **Strict Multi-Tenant Isolation**: Tenant A cannot observe, query, modify, or export Tenant B's investigations, indicators, attack graphs, mailboxes, worker controls, or telemetry.
4. **Session Purge on Logout**: Explicit token revocation (`sign_out_user`) followed by complete session memory wipe (`st.session_state.clear()`) leaves zero residual data in memory.
5. **Clean Regression**: **891 passed**, 0 failed, 2 skipped across 40 test suites.

---

## 1. Unified Authorization Pipeline & Implementation

All authorization checks are consolidated into `core/case_store.py::is_authorized_caller()`:

```python
def is_authorized_caller(
    user_id: Optional[str] = None,
    client: Any = None,
    resource_owner_id: Optional[str] = None
) -> bool:
    if not user_id and not client:
        return False

    try:
        supabase_active = is_supabase_configured()
    except Exception:
        supabase_active = False

    if is_public_multiuser_mode() or supabase_active:
        if not (client and user_id):
            return False
    else:
        if not (user_id or client):
            return False

    # Ownership / Tenant check (if resource owner specified)
    if resource_owner_id is not None:
        eff_user = user_id or getattr(client, "user_id", None)
        if eff_user != resource_owner_id:
            return False

    return True
```

`is_authenticated_soc_caller` is preserved as a direct backward-compatible alias to `is_authorized_caller`.

### Backend Export Authorization Helpers (`core/case_store.py`):
- `export_case_report_pdf(case_id, client=None, user_id=None) -> Optional[bytes]`
- `export_case_report_json(case_id, client=None, user_id=None) -> Optional[str]`
- `export_case_ncrp_pdf(case_id, client=None, user_id=None) -> Optional[bytes]`
- `export_case_bsa_pdf(case_id, client=None, user_id=None) -> Optional[bytes]`

Each helper checks `get_case_record(case_id, client=client)` and validates `is_authorized_caller`. If unauthenticated or mismatched tenant, it returns `None` (fails closed).

### Presentation Layer Guards (`app.py`):
All 9 Streamlit navigation views and sensitive controls enforce authorization:
- `🛡️ SOC Dashboard`: Guarded by `is_authorized_caller` (displays landing banner, zero private metrics if logged out).
- `📡 Live Mail Analysis`: Guarded by `is_authorized_caller` (worker control plane, mailbox, checkpoints hidden).
- `📧 Analyze Email`: Batch analytics and inspection isolated to active user session.
- `🔎 Investigations`: Guarded by `is_authorized_caller` (case search and case management hidden).
- `🌐 IOC / URL Intelligence`: Guarded by `is_authorized_caller` (Tenant IOC repository and GeoIP infrastructure map hidden).
- `🕸️ Attack Graph`: Guarded by `is_authorized_caller` (threat infrastructure graphs hidden).
- `📄 Evidence & Reports`: Guarded by `is_authorized_caller` (evidence certificates and report downloads hidden).
- `📱 Mobile Alerts`: Guarded by `is_authorized_caller` (Telegram and WhatsApp alert configurations hidden).
- `⚙️ System / Diagnostics`: Guarded by `is_authorized_caller` (local storage retention and worker telemetry hidden).

---

## 2. The 5-State Common Audit Matrix

Every protected resource was tested against 5 operational states:
- **State A (Logged Out)**: Anonymous visitor with no credentials. Expected: Denied / Empty / Fail-closed.
- **State B (Authenticated Owner)**: User A accessing User A's data. Expected: Allowed, strictly RLS-filtered.
- **State C (Wrong Tenant)**: User B accessing under User B's session. Expected: Cannot see User A's data.
- **State D (Direct Backend Call)**: Missing auth arguments (`client=None`, `user_id=None`). Expected: Fail closed immediately, zero fallback to SQLite.
- **State E (ID Substitution)**: User B requesting User A's known resource ID. Expected: Denied / Empty / 404.

---

## 3. Resource Inventory Table

| # | Protected Resource | Primary Functions / Endpoints | Enforcing Layer | State A (Logged Out) | State B (Owner) | State C (Wrong Tenant) | State D (Direct Backend) | State E (ID Sub.) |
|---|---|---|---|:---:|:---:|:---:|:---:|:---:|
| 1 | **SOC Dashboard** | `get_soc_kpi_metrics`, `get_soc_threat_distribution`, `get_soc_threat_activity`, `get_soc_investigation_queue` | `core/case_store.py`, `app.py` | Denied (zeros) | Allowed | Denied (0 cases) | Denied (zeros) | Denied |
| 2 | **Analyze Email** | `save_case`, `get_case_record` | `core/case_store.py`, PostgREST RLS | Denied (`None`) | Allowed | Denied (`None`) | Denied (`None`) | Denied (`None`) |
| 3 | **Investigations** | `get_all_cases`, `update_case_metadata` | `core/case_store.py`, PostgREST RLS | Denied (`[]`) | Allowed | Denied (`[]`) | Denied (`[]`) | Denied (`False`) |
| 4 | **IOC / URL Intelligence** | `get_all_indicators` | `core/case_store.py`, PostgREST RLS | Denied (`[]`) | Allowed | Denied (`[]`) | Denied (`[]`) | Denied (`[]`) |
| 5 | **GeoIP Private Data** | `derive_authoritative_location`, case geo data | `core/geolocation.py`, `app.py` | Denied (`None`) | Allowed | Denied (`None`) | Denied (`None`) | Denied (`None`) |
| 6 | **Attack Graph** | `build_case_infrastructure_graph` | `core/correlation.py`, `app.py` | Denied (`None`) | Allowed | Denied | Denied (`None`) | Denied (`None`) |
| 7 | **Evidence & Reports** | `get_case_record`, report viewer | `core/case_store.py`, PostgREST RLS | Denied (`None`) | Allowed | Denied (`None`) | Denied (`None`) | Denied (`None`) |
| 8 | **PDF Export** | `export_case_report_pdf` | `core/case_store.py` | Denied (`None`) | Allowed | Denied (`None`) | Denied (`None`) | Denied (`None`) |
| 9 | **JSON Export** | `export_case_report_json`, `export_case_iocs_json` | `core/case_store.py` | Denied (`None` / 0 IOCs) | Allowed | Denied (`None` / 0 IOCs) | Denied (`None` / 0 IOCs) | Denied (`None` / 0 IOCs) |
| 10 | **CSV Export** | `export_case_iocs_csv` | `core/case_store.py` | Header only (0 data rows) | Allowed | Header only (0 data rows) | Header only (0 data rows) | Header only (0 data rows) |
| 11 | **NCRP / BSA Export** | `export_case_ncrp_pdf`, `export_case_bsa_pdf` | `core/case_store.py` | Denied (`None`) | Allowed | Denied (`None`) | Denied (`None`) | Denied (`None`) |
| 12 | **Live Mail Analysis** | `get_user_worker`, `upsert_user_worker` | `core/sentinel_control.py` | Denied (`None`) | Allowed | Denied (`None`) | Denied (`None`) | Denied (`None`) |
| 13 | **Sentinel Telemetry** | `get_user_checkpoint` | `core/sentinel_control.py` | Denied (`None`) | Allowed | Denied (`None`) | Denied (`None`) | Denied (`None`) |
| 14 | **Mailbox Configuration** | `get_user_mailbox`, `save_user_mailbox_metadata` | `core/sentinel_control.py` | Denied (`None`) | Allowed | Denied (`None`) | Denied (`None`) | Denied (`None`) |
| 15 | **Mobile Alerts** | `get_user_alerts`, `save_user_alert_metadata` | `core/sentinel_control.py` | Denied (`[]`) | Allowed | Denied (`[]`) | Denied (`[]`) | Denied (`[]`) |
| 16 | **Batch Analysis** | `scan_mailbox_batch`, session state | `core/batch_scanner.py`, `app.py` | Denied (`None`) | Allowed | Isolated | Denied | Denied |

---

## 4. Batch Analysis & Live Mail Isolation

- Batch scan metrics and today's analytics are stored in `st.session_state["batch_results"]`, scoped entirely to the authenticated user's session.
- Live mail worker polling and checkpoints update tenant-isolated tables (`sentinel_workers`, `sentinel_checkpoints`) filtered by `auth.uid() = user_id`.
- Verified in `test_batch_and_live_isolation_across_tenants`: Tenant A's batch runs do not modify Tenant B's KPI metrics, queue, or threat activity.

---

## 5. Session Purge on Logout

Streamlit session termination in `app.py` (lines 348-351) executes:
```python
sign_out_user(st.session_state.get("supabase_auth_token"))
st.session_state.clear()
st.rerun()
```
Verified in `test_session_purge_on_logout`:
- Revokes JWT auth token with Supabase Auth service.
- Clears `user_id`, `user_email`, `supabase_auth_token`, `supabase_refresh_token`.
- Wipes `_cached_analysis_payload`, `batch_results`, `mailbox_connected`.
- Wipes all manual GeoIP coordinates and display IPs (`manual_geoip_display_ip`, `manual_geoip_lat`, `manual_geoip_lon`, `manual_geoip_city`).
- Zero residual investigator data remains in session memory for subsequent requests.

---

## 6. Verification & Test Suite Results

### Full Pytest Regression
```text
891 passed, 2 skipped, 191 warnings, 9 subtests passed in 373.96s (0:06:13)
```
- Total tests passed: **891**
- Regressions: **0**
- Failures: **0**
- Skipped: **2** (external integration markers)

### Dedicated Test Suites Verified
1. `tests/test_consolidated_authorization.py` (12 tests, 100% pass)
2. `tests/test_soc_dashboard_audit.py` (14 tests, 100% pass)
3. `tests/test_soc_tenant_isolation.py` (5 tests, 100% pass)
4. `tests/test_multiuser_security.py` (12 tests, 100% pass)
5. `tests/test_manual_geoip_search.py` (19 tests, 100% pass)

### Security & Secret Leakage Verification
- Prohibited token scan: Clean (zero `service_role` tokens, zero leaked keys).
- Git repository constraints: No commit, no push, no deployment.
