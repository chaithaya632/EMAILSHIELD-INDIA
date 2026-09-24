"""
tests/test_geoip_intelligence_upgrade.py
Comprehensive regression tests for GeoIP Intelligence Upgrade in EMAILSHIELD INDIA:
1. Originating IP extraction priority: X-Originating-IP > client-ip > Received hops.
2. Public IP validation: private/loopback IPs return Not geolocatable, no fabricated coordinates.
3. Accuracy radius extraction from offline MMDB.
4. Multiple IP roles (Originating vs Relay) preserved.
5. Plotly figure generation with custom tooltips and roles.
6. Read-only behavior: no counter or state side effects.
"""

import unittest
import uuid
from unittest.mock import patch, MagicMock
import plotly.graph_objects as go

from core.geolocation import (
    get_geolocation,
    get_sender_location,
    is_public_ip,
    extract_originating_sender_telemetry,
    extract_originating_sender_ip,
    build_geoip_map,
)
from core.relay_tracer import build_relay_flight_map, analyze_relay_transit
from core.sentinel_stats import (
    get_user_sentinel_stats,
    record_user_sentinel_poll,
    reset_user_sentinel_stats,
)


class TestGeoIPIntelligenceUpgrade(unittest.TestCase):
    """Test suite validating GeoIP intelligence hierarchy, public validation, MMDB accuracy, and visualization."""

    def setUp(self):
        self.user_id = str(uuid.uuid4())
        self.mailbox_id = str(uuid.uuid4())

    def tearDown(self):
        reset_user_sentinel_stats(self.user_id, self.mailbox_id)

    # -------------------------------------------------------------------------
    # 1. Originating IP extraction priority: X-Originating-IP > client-ip > Received hops
    # -------------------------------------------------------------------------
    def test_01_originating_ip_extraction_priority_hierarchy(self):
        """
        Verifies exact extraction priority:
        Priority 1: X-Originating-IP
        Priority 2: client-ip in Authentication-Results / Received-SPF
        Priority 3: Chronological Received chain (earliest public hop)
        """
        ip_originating = "106.51.72.10"       # Public IP (should win if present)
        ip_auth = "54.240.0.1"                 # Public IP (should win if X-Originating-IP absent)
        ip_received = "93.184.216.34"          # Public IP (should win if both above absent)

        # Case A: All 3 present -> X-Originating-IP wins (Priority 1)
        headers_all = {
            "x-originating-ip": f"[{ip_originating}]",
            "authentication-results": f"mx.google.com; spf=pass client-ip={ip_auth};",
            "received": [
                f"from mail.gateway.com by mx.google.com with ESMTPS; Sun, 20 Sep 2026 10:05:00 +0000",
                f"from [10.0.0.1] (helo=outbound.server.com) by mail.gateway.com ({ip_received}) with ESMTP; Sun, 20 Sep 2026 10:00:00 +0000"
            ]
        }
        telem_a = extract_originating_sender_telemetry(headers_all)
        self.assertEqual(telem_a["ip"], ip_originating)
        self.assertTrue(telem_a["is_client_ip"])
        self.assertIn("x-originating-ip", telem_a["source"].lower())

        # Case B: X-Originating-IP absent, Authentication client-ip + Received present -> client-ip wins (Priority 2)
        headers_auth_rec = {
            "authentication-results": f"mx.google.com; spf=pass client-ip={ip_auth};",
            "received": [
                f"from mail.gateway.com by mx.google.com with ESMTPS; Sun, 20 Sep 2026 10:05:00 +0000",
                f"from outbound.server.com ({ip_received}) by mail.gateway.com with ESMTP; Sun, 20 Sep 2026 10:00:00 +0000"
            ]
        }
        telem_b = extract_originating_sender_telemetry(headers_auth_rec)
        self.assertEqual(telem_b["ip"], ip_auth)
        self.assertTrue(telem_b["is_client_ip"])
        self.assertIn("authentication", telem_b["source"].lower())

        # Case C: Only Received chain present -> earliest public hop wins (Priority 3)
        headers_rec_only = {
            "received": [
                "from mx2.dest.com (198.51.100.99) by gateway.dest.com; Sun, 20 Sep 2026 10:10:00 +0000",
                f"from relay1.source.com ({ip_received}) by mx2.dest.com; Sun, 20 Sep 2026 10:00:00 +0000",
                "from internal.lan (10.0.0.5) by relay1.source.com; Sun, 20 Sep 2026 09:55:00 +0000"
            ]
        }
        telem_c = extract_originating_sender_telemetry(headers_rec_only)
        self.assertEqual(telem_c["ip"], ip_received)
        self.assertFalse(telem_c["is_client_ip"])
        self.assertIn("earliest public relay", telem_c["source"].lower())


    # -------------------------------------------------------------------------
    # 2. Public IP validation: private/loopback IPs return Not geolocatable, no fabricated coordinates
    # -------------------------------------------------------------------------
    def test_02_private_and_loopback_ips_return_no_fabricated_coordinates(self):
        """
        Verifies that private, loopback, and link-local IPs return 'Not geolocatable',
        and lat/lon are strictly None (zero fabricated coordinates).
        """
        private_ips = [
            "127.0.0.1",       # Loopback
            "10.0.0.1",        # RFC 1918 Class A
            "172.16.50.1",     # RFC 1918 Class B
            "192.168.1.254",   # RFC 1918 Class C
            "169.254.10.20",   # Link-local
            "::1",             # IPv6 Loopback
            "fe80::1",         # IPv6 Link-local
        ]

        for pip in private_ips:
            # 1. is_public_ip must be False
            self.assertFalse(is_public_ip(pip), f"{pip} was incorrectly identified as public")

            # 2. get_geolocation must return None for lat/lon (no fabricated coordinates)
            geo = get_geolocation(pip)
            self.assertIsNone(geo["latitude"], f"Fabricated latitude for private IP: {pip}")
            self.assertIsNone(geo["longitude"], f"Fabricated longitude for private IP: {pip}")
            self.assertIsNone(geo.get("accuracy_radius"), f"Fabricated accuracy radius for private IP: {pip}")
            self.assertIn("private", geo.get("status", "").lower())

        # 3. Email headers with only private IPs return Unavailable/Relay-masked
        private_headers = {
            "from": "alice@local.lan",
            "received": [
                "from internal.host (127.0.0.1) by mail.lan (192.168.1.1); Sun, 20 Sep 2026 10:00:00 +0000"
            ]
        }
        sender_loc = get_sender_location(private_headers)
        self.assertFalse(sender_loc["is_identified"])
        self.assertIsNone(sender_loc["latitude"])
        self.assertIsNone(sender_loc["longitude"])
        self.assertIn("Unavailable", sender_loc["display_location"])

    # -------------------------------------------------------------------------
    # 3. Accuracy radius extraction from offline MMDB
    # -------------------------------------------------------------------------
    def test_03_accuracy_radius_extraction_from_offline_mmdb(self):
        """
        Verifies that accuracy radius (in km) is extracted from the MMDB location record
        and returned under 'accuracy_radius' and 'accuracy_radius_km'.
        """
        # Mock MMDB reader returning a known city record with accuracy_radius
        mock_city_record = MagicMock()
        mock_city_record.country.name = "India"
        mock_city_record.registered_country.name = "India"
        mock_city_record.subdivisions.most_specific.name = "Karnataka"
        mock_city_record.city.name = "Bengaluru"
        mock_city_record.location.latitude = 12.9716
        mock_city_record.location.longitude = 77.5946
        mock_city_record.location.accuracy_radius = 50  # 50 km accuracy radius

        mock_reader = MagicMock()
        mock_reader.city.return_value = mock_city_record

        with patch("core.geolocation._get_reader", return_value=mock_reader), \
             patch.dict("core.geolocation._GEO_CACHE", {}, clear=True):

            geo = get_geolocation("106.51.72.10")

            self.assertEqual(geo["country"], "India")
            self.assertEqual(geo["city"], "Bengaluru")
            self.assertEqual(geo["latitude"], 12.9716)
            self.assertEqual(geo["longitude"], 77.5946)
            self.assertEqual(geo.get("accuracy_radius"), 50)
            self.assertEqual(geo.get("accuracy_radius_km"), 50)

    # -------------------------------------------------------------------------
    # 4. Multiple IP roles (Originating vs Relay) preserved
    # -------------------------------------------------------------------------
    def test_04_multiple_ip_roles_originating_vs_relay_preserved(self):
        """
        Verifies that in a multi-hop email transmission:
        - Originating hop role is preserved as 'Originating Client / Outbound MTA'.
        - Intermediate hop role is preserved as 'Intermediate Relay'.
        - Destination hop role is preserved as 'Inbound Enterprise MX Gateway'.
        """
        received_chain = [
            "from mx.destination.com by internal.dest.local; Sun, 20 Sep 2026 12:05:00 +0530",
            "from relay.intermediate.net by mx.destination.com; Sun, 20 Sep 2026 12:02:00 +0530",
            "from outbound.origin.org by relay.intermediate.net; Sun, 20 Sep 2026 12:00:00 +0530"
        ]

        analysis = analyze_relay_transit(received_chain)
        hops = analysis["hops"]

        self.assertEqual(len(hops), 3)

        # Chronological order: Hop 1 is Origin, Hop 2 is Intermediate Relay, Hop 3 is Destination
        self.assertEqual(hops[0]["role"], "Originating Client / Outbound MTA")
        self.assertEqual(hops[0]["trust_level"], "Untrusted (Sender Controlled)")

        self.assertEqual(hops[1]["role"], "Intermediate Relay #1")
        self.assertEqual(hops[1]["trust_level"], "Intermediate Infrastructure")

        self.assertEqual(hops[2]["role"], "Inbound Enterprise MX Gateway")
        self.assertEqual(hops[2]["trust_level"], "Trusted (Receiving Infrastructure)")

    # -------------------------------------------------------------------------
    # 5. Plotly figure generation with custom tooltips and roles
    # -------------------------------------------------------------------------
    def test_05_plotly_figure_generation_with_custom_tooltips_and_roles(self):
        """
        Verifies Plotly figure generation for GeoIP intelligence:
        - Returns a valid plotly.graph_objects.Figure.
        - Traces contain scattergeo markers.
        - Tooltips contain role, IP, location, and ISP details.
        - Marker colors distinguish Originating (Red) from Relay (Orange) and Destination (Green).
        """
        locations = [
            {
                "ip": "203.0.113.195",
                "role": "Originating Client / Outbound MTA",
                "city": "Bengaluru",
                "country": "India",
                "org": "ACT Fibernet",
                "latitude": 12.9716,
                "longitude": 77.5946,
                "accuracy_radius": 20
            },
            {
                "ip": "198.51.100.42",
                "role": "Intermediate Relay",
                "city": "Frankfurt",
                "country": "Germany",
                "org": "Deutsche Telekom",
                "latitude": 50.1109,
                "longitude": 8.6821,
                "accuracy_radius": 50
            },
            {
                "ip": "192.0.2.1",
                "role": "Inbound Enterprise MX Gateway",
                "city": "New York",
                "country": "United States",
                "org": "Verizon",
                "latitude": 40.7128,
                "longitude": -74.0060,
                "accuracy_radius": 10
            }
        ]

        fig = build_geoip_map(locations)
        self.assertIsInstance(fig, go.Figure)

        # Verify Scattergeo trace exists
        scatter_traces = [t for t in fig.data if isinstance(t, go.Scattergeo)]
        self.assertGreater(len(scatter_traces), 0)

        marker_trace = scatter_traces[0]
        self.assertEqual(len(marker_trace.lat), 3)
        self.assertEqual(len(marker_trace.lon), 3)

        # Verify custom tooltips contain Role, IP, Location, Org
        tooltips = list(marker_trace.text)
        self.assertEqual(len(tooltips), 3)

        self.assertIn("Originating Client / Outbound MTA", tooltips[0])
        self.assertIn("203.0.113.195", tooltips[0])
        self.assertIn("Bengaluru, India", tooltips[0])
        self.assertIn("Accuracy: ~20 km", tooltips[0])

        self.assertIn("Intermediate Relay", tooltips[1])
        self.assertIn("198.51.100.42", tooltips[1])
        self.assertIn("Frankfurt, Germany", tooltips[1])

        self.assertIn("Inbound Enterprise MX Gateway", tooltips[2])
        self.assertIn("192.0.2.1", tooltips[2])

        # Verify role-based color coding
        colors = marker_trace.marker.color
        self.assertEqual(colors[0], "#EF553B")  # Red for Origin
        self.assertEqual(colors[1], "#FFA15A")  # Orange for Relay
        self.assertEqual(colors[2], "#00CC96")  # Green for Destination

    # -------------------------------------------------------------------------
    # 6. Read-only behavior: no counter or state side effects
    # -------------------------------------------------------------------------
    def test_06_geoip_intelligence_read_only_no_counter_side_effects(self):
        """
        Verifies that GeoIP extraction, location resolution, and map generation
        are strictly read-only and have zero side effects on Sentinel stats or telemetry.
        """
        record_user_sentinel_poll(
            user_id=self.user_id,
            mailbox_id=self.mailbox_id,
            arrived=100,
            analysed=95,
            clean=80,
            suspicious=15,
            last_uid=1234
        )

        stats_before = get_user_sentinel_stats(self.user_id, self.mailbox_id)

        # Run GeoIP intelligence operations
        _ = get_geolocation("8.8.8.8")
        _ = get_geolocation("127.0.0.1")
        _ = get_sender_location({
            "from": "user@domain.com",
            "x-originating-ip": "[203.0.113.1]"
        })
        _ = build_geoip_map([
            {"latitude": 12.97, "longitude": 77.59, "role": "Origin", "ip": "203.0.113.1"}
        ])

        # Stats must remain completely unchanged
        stats_after = get_user_sentinel_stats(self.user_id, self.mailbox_id)
        self.assertEqual(stats_after, stats_before)
        self.assertEqual(stats_after["emails_arrived"], 100)
        self.assertEqual(stats_after["emails_analysed"], 95)
        self.assertEqual(stats_after["last_processed_uid"], 1234)


if __name__ == "__main__":
    unittest.main()
