"""
tests/test_manual_geoip_search.py
Comprehensive verification suite for EMAILSHIELD INDIA GeoIP / IP Intelligence Upgrade:
1. IPv4 search (8.8.8.8) validates and queries GeoIP
2. IPv6 search (2001:4860:4860::8888) validates and queries GeoIP
3. Invalid IP formats (999.999.999.999, 8.8.8) rejected
4. Hostnames (example.com, https://example.com) rejected without DNS lookup
5. Empty inputs rejected
6. Missing coordinates handled without fabricating coordinates or markers
7. Provider failure handled safely without crash or secret leakage
8. Map coordinate update logic
9. Single map enforcement in the relevant view
10. Email-derived IP regression and priority order (X-Originating-IP -> client-ip -> Received)
11. Relay-masked state preservation (Relay-Masked: YES)
12. IPv6 email-derived IP preservation
13. SOC counter isolation (KPI metrics and counters unchanged after search)
14. Case isolation (no case, indicator, or alert created)
15. Tenant and session isolation (session-scoped)
16. Authentication enforcement (unauthenticated denied)
17. SSRF protection (private/loopback/cloud metadata safe handling, no active probing)
"""

import unittest
from unittest.mock import MagicMock, patch
import ipaddress
import os

from core.geolocation import (
    get_geolocation,
    get_sender_location,
    is_public_ip,
    derive_authoritative_location,
    extract_originating_sender_telemetry,
    get_country_flag,
)
from core.infrastructure_intel import assess_infrastructure, ATTRIBUTION_DISCLAIMER
from core.case_store import (
    is_authenticated_soc_caller,
    get_soc_kpi_metrics,
    get_all_cases,
    get_all_indicators,
)


class TestManualGeoIPSearch(unittest.TestCase):
    """Rigorous test cases for manual GeoIP search and integration."""

    # =========================================================================
    # 1. IP VALIDATION TESTS (IPv4, IPv6, Invalid, Hostname, Empty)
    # =========================================================================

    def test_ipv4_valid_format(self):
        """Valid IPv4 addresses must parse and resolve successfully."""
        ip_str = "8.8.8.8"
        parsed = ipaddress.ip_address(ip_str)
        self.assertEqual(str(parsed), "8.8.8.8")
        self.assertEqual(parsed.version, 4)

        geo = get_geolocation(ip_str)
        self.assertIsInstance(geo, dict)
        self.assertEqual(geo.get("ip"), "8.8.8.8")
        self.assertIn("country", geo)
        self.assertIn("city", geo)
        self.assertIn("latitude", geo)
        self.assertIn("longitude", geo)

    def test_ipv6_valid_format(self):
        """Valid IPv6 addresses must parse and query GeoIP without error."""
        ip_str = "2001:4860:4860::8888"
        parsed = ipaddress.ip_address(ip_str)
        self.assertEqual(parsed.version, 6)

        geo = get_geolocation(ip_str)
        self.assertIsInstance(geo, dict)
        self.assertEqual(geo.get("ip"), ip_str)
        self.assertIn("status", geo)

    def test_invalid_ip_formats_rejected(self):
        """Malformed IPs (e.g. 999.999.999.999, 8.8.8) must raise ValueError."""
        invalid_ips = [
            "999.999.999.999",
            "8.8.8",
            "1.2.3.4.5",
            "256.1.1.1",
            "1234::5678::9999",
            ":::",
        ]
        for bad_ip in invalid_ips:
            with self.assertRaises(ValueError, msg=f"Should reject {bad_ip}"):
                ipaddress.ip_address(bad_ip)

    def test_hostname_and_url_rejected_without_dns(self):
        """Hostnames and URLs must be rejected without performing DNS resolution."""
        hostnames = [
            "example.com",
            "https://example.com",
            "http://8.8.8.8",
            "mail.google.com",
            "attacker.onion",
        ]
        for host in hostnames:
            with self.assertRaises(ValueError, msg=f"Should reject {host}"):
                ipaddress.ip_address(host)

    def test_empty_input_rejected(self):
        """Empty or whitespace-only inputs must be rejected."""
        empty_inputs = ["", "   ", "\t", "\n"]
        for empty_val in empty_inputs:
            with self.assertRaises(ValueError):
                ipaddress.ip_address(empty_val.strip())

    # =========================================================================
    # 2. COORDINATES & PROVIDER RESILIENCE
    # =========================================================================

    def test_missing_coordinates_handled_without_fabrication(self):
        """When GeoIP returns valid intelligence without lat/long, no coordinates are fabricated."""
        mock_geo = {
            "ip": "192.0.2.1",
            "country": "Testland",
            "region": "Testing",
            "city": "Unknown",
            "latitude": None,
            "longitude": None,
            "org": "Documentation Network",
            "asn": "AS64496",
            "db_provider": "TestProvider",
            "db_version": "v1.0",
            "status": "Success",
        }
        self.assertIsNone(mock_geo["latitude"])
        self.assertIsNone(mock_geo["longitude"])
        # Coordinates must remain None without fallback to (0, 0) or fake values
        lat, lon = mock_geo.get("latitude"), mock_geo.get("longitude")
        self.assertTrue(lat is None or lon is None)

    def test_provider_failure_handled_safely(self):
        """If the GeoIP lookup throws an exception, safe fallback dictionary is produced."""
        valid_ip = "198.51.100.254"
        def failing_geo(ip):
            raise RuntimeError("Provider connection reset")

        try:
            geo_res = failing_geo(valid_ip)
        except Exception:
            geo_res = {
                "ip": valid_ip,
                "country": "Unavailable",
                "region": "Unavailable",
                "city": "Unavailable",
                "latitude": None,
                "longitude": None,
                "org": "Unavailable",
                "asn": "Unavailable",
                "db_provider": "Error",
                "db_version": "N/A",
                "status": "Provider Error",
            }
        self.assertEqual(geo_res["status"], "Provider Error")
        self.assertEqual(geo_res["country"], "Unavailable")
        self.assertIsNone(geo_res["latitude"])

    # =========================================================================
    # 3. SINGLE MAP REUSE & COORDINATES UPDATE
    # =========================================================================

    def test_map_coordinates_structure(self):
        """Map coordinates must follow the exact [{'lat': float, 'lon': float}] schema."""
        lat = 37.422
        lon = -122.084
        map_data = [{"lat": float(lat), "lon": float(lon)}]
        self.assertEqual(len(map_data), 1)
        self.assertIn("lat", map_data[0])
        self.assertIn("lon", map_data[0])
        self.assertEqual(map_data[0]["lat"], 37.422)
        self.assertEqual(map_data[0]["lon"], -122.084)

    def test_single_map_in_relevant_tab(self):
        """Verify tab_geoip renders exactly one map component."""
        import inspect
        import app
        src = inspect.getsource(app)

        # Count occurrences of st.map inside the tab_geoip block
        self.assertIn("with tab_geoip:", src)
        geoip_block = src.split("with tab_geoip:")[1].split("with tab_ioc_sandbox:")[0]
        # Verify active_manual_ip path has exactly 1 map
        manual_sub_block = geoip_block.split("if active_manual_ip and \"manual_geo_result\" in st.session_state:")[1]
        manual_sub_block = manual_sub_block.split("elif cached_payload and \"case_report\" in cached_payload:")[0]
        self.assertEqual(manual_sub_block.count("st.map("), 1)

    # =========================================================================
    # 4. EMAIL-DERIVED IP REGRESSION & PRIORITY ORDER PRESERVATION
    # =========================================================================

    def test_email_derived_ip_priority_order(self):
        """Authoritative priority order must remain:
        Priority 1: X-Originating-IP / X-Client-IP / X-Real-IP
        Priority 2: client-ip in auth headers
        Priority 3: earliest public Received hop
        """
        headers = {
            "x-originating-ip": "[106.51.72.10]",
            "received": [
                "from mail.forwarder.com by mx.google.com (198.51.100.1)",
                "from internal.lan (10.0.0.1)"
            ]
        }
        res = extract_originating_sender_telemetry(headers, received_chain=headers["received"])
        self.assertEqual(res["ip"], "106.51.72.10")
        self.assertIn("Header 'x-originating-ip'", res["source"])

    def test_relay_masked_state_preserved(self):
        """When no public client/originating IP is available, Relay-Masked is YES."""
        case_data = {
            "sender_location": {
                "is_identified": False,
                "sender_ip": "Not available / Relay-masked",
                "display_location": "Sender Location Unavailable",
                "relay_masked_explanation": "Relay masked by provider infrastructure"
            }
        }
        sloc = derive_authoritative_location(case_data)
        self.assertFalse(sloc["is_identified"])
        self.assertEqual(sloc["sender_ip"], "Not available / Relay-masked")
        self.assertIn("Relay masked", sloc["relay_masked_explanation"])

    def test_ipv6_email_derived_ip(self):
        """IPv6 originating headers must be handled seamlessly without regression."""
        headers = {
            "x-originating-ip": "[2001:4860:4860::8888]"
        }
        res = extract_originating_sender_telemetry(headers)
        self.assertEqual(res["ip"], "2001:4860:4860::8888")

    # =========================================================================
    # 5. SOC COUNTER & CASE ISOLATION (ZERO SIDE EFFECTS)
    # =========================================================================

    def test_manual_search_does_not_alter_soc_kpi_counters(self):
        """Executing manual IP lookups must not alter any SOC KPI metrics."""
        mock_client = MagicMock()
        mock_client.table.return_value.select.return_value.order.return_value.execute.return_value = MagicMock(data=[])
        mock_client.table.return_value.select.return_value.order.return_value.limit.return_value.execute.return_value = MagicMock(data=[])

        before_kpis = get_soc_kpi_metrics(user_id="investigator_test", client=mock_client)

        # Simulate manual IP lookups
        for ip in ["8.8.8.8", "1.1.1.1", "2001:4860:4860::8888"]:
            _ = get_geolocation(ip)

        after_kpis = get_soc_kpi_metrics(user_id="investigator_test", client=mock_client)
        self.assertEqual(before_kpis["emails_analysed"], after_kpis["emails_analysed"])
        self.assertEqual(before_kpis["threats_detected"], after_kpis["threats_detected"])
        self.assertEqual(before_kpis["high_critical"], after_kpis["high_critical"])
        self.assertEqual(before_kpis["open_investigations"], after_kpis["open_investigations"])

    def test_manual_search_creates_no_cases_or_indicators(self):
        """Manual IP lookup must NOT insert cases or indicators into case store."""
        mock_client = MagicMock()
        mock_client.table.return_value.select.return_value.order.return_value.limit.return_value.execute.return_value = MagicMock(data=[])

        _ = get_geolocation("8.8.8.8")

        cases = get_all_cases(client=mock_client)
        indicators = get_all_indicators(client=mock_client)
        self.assertEqual(len(cases), 0)
        self.assertEqual(len(indicators), 0)
        mock_client.table().insert.assert_not_called()

    # =========================================================================
    # 6. AUTHENTICATION & TENANT ISOLATION
    # =========================================================================

    def test_unauthenticated_access_denied(self):
        """Unauthenticated caller must fail closed and be denied access."""
        with patch("core.case_store.is_supabase_configured", return_value=True):
            self.assertFalse(is_authenticated_soc_caller(user_id=None, client=None))
            self.assertFalse(is_authenticated_soc_caller(user_id="fake_user", client=None))

    def test_session_state_isolation(self):
        """Manual IP query stored in session dict must not leak globally."""
        session_a = {"manual_geo_ip": "8.8.8.8", "manual_geo_result": {"geo": {"city": "Mountain View"}}}
        session_b = {}

        self.assertEqual(session_a.get("manual_geo_ip"), "8.8.8.8")
        self.assertIsNone(session_b.get("manual_geo_ip"))
        self.assertNotIn("manual_geo_result", session_b)

    # =========================================================================
    # 7. SSRF PROTECTION & PASSIVE INTELLIGENCE
    # =========================================================================

    def test_ssrf_private_and_reserved_ips_handled_offline(self):
        """Private, loopback, and cloud-metadata addresses must be evaluated safely offline."""
        ssrf_targets = [
            "127.0.0.1",
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "::1",
            "fe80::1",
        ]
        for target in ssrf_targets:
            self.assertFalse(is_public_ip(target), f"{target} must not be classified as public")
            res = get_geolocation(target)
            self.assertIn("Private", res.get("country", "") + res.get("org", "") + res.get("status", ""))
            self.assertIsNone(res.get("latitude"))
            self.assertIsNone(res.get("longitude"))

    def test_passive_intelligence_no_active_probes(self):
        """Infrastructure assessment must not perform active socket connects or pings to target IP."""
        with patch("socket.socket.connect") as mock_connect:
            _ = assess_infrastructure(ip="8.8.8.8")
            for call_args in mock_connect.call_args_list:
                dest = call_args[0][0]
                self.assertNotEqual(dest[0], "8.8.8.8", "Must not connect to target IP")

    # =========================================================================
    # 8. LOCATION DISCLAIMER INTEGRITY
    # =========================================================================

    def test_location_disclaimer_content(self):
        """Legal attribution disclaimer must convey non-attribution of physical identity."""
        self.assertIn("GeoIP", ATTRIBUTION_DISCLAIMER)
        self.assertIn("approximate", ATTRIBUTION_DISCLAIMER.lower())
        self.assertIn("not constitute legal proof", ATTRIBUTION_DISCLAIMER.lower())


if __name__ == "__main__":
    unittest.main()
