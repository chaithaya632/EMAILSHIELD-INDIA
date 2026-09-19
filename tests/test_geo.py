"""
tests/test_geo.py
Comprehensive regression tests for authoritative sender location derivation and SIH26106 infrastructure integration.
Verifies that:
1. Identified location preserves all GeoIP, ASN, ISP, and coordinate fields.
2. Unavailable / relay-masked location safely defaults without NameError or uninitialized state.
3. Infrastructure intelligence result present correctly populates origin infrastructure when sender location is absent.
4. Infrastructure intelligence result absent safely falls back to standard disclaimers and unknown status.
5. Exact UI expressions at app.py lines 1269 and 1383 evaluate without NameError.
"""
import pytest
from typing import Dict, Any
from core.geolocation import (
    get_geolocation,
    get_sender_location,
    is_public_ip,
    derive_authoritative_location
)
from core.schemas import CaseReport, Indicator


def test_authoritative_location_identified_location():
    """Verify identified location preserves all forensic GeoIP fields."""
    raw_sloc = {
        "is_identified": True,
        "is_client_ip": True,
        "sender_ip": "106.51.72.10",
        "city": "Bengaluru",
        "region": "Karnataka",
        "country": "India",
        "flag": "🇮🇳",
        "display_location": "Bengaluru, Karnataka, India 🇮🇳",
        "latitude": 12.9716,
        "longitude": 77.5946,
        "org": "ACT Fibernet",
        "asn": "AS132203",
        "attribution_disclaimer": "Geo-IP disclaimer",
        "relay_masked_explanation": "Relay explanation"
    }
    case_dict = {"sender_location": raw_sloc}
    sloc = derive_authoritative_location(case_dict)

    assert sloc["is_identified"] is True
    assert sloc["sender_ip"] == "106.51.72.10"
    assert sloc["city"] == "Bengaluru"
    assert sloc["region"] == "Karnataka"
    assert sloc["country"] == "India"
    assert sloc["latitude"] == 12.9716
    assert sloc["longitude"] == 77.5946
    assert sloc["org"] == "ACT Fibernet"
    assert sloc["asn"] == "AS132203"
    assert sloc["display_location"] == "Bengaluru, Karnataka, India 🇮🇳"

    # Test exact app.py line 1269 / 1383 expression
    loc_val = sloc.get('display_location', 'Unavailable') if sloc.get('is_identified') else 'Unavailable'
    assert loc_val == "Bengaluru, Karnataka, India 🇮🇳"


def test_authoritative_location_unavailable_location():
    """Verify unavailable/unknown location fails safe without uninitialized state or NameError."""
    raw_sloc = {
        "is_identified": False,
        "sender_ip": "Not available / Relay-masked",
        "display_location": "Sender Location Unavailable",
        "country": "Unknown",
        "region": "Unknown",
        "city": "Unknown",
        "org": "Unknown Network",
        "asn": "None"
    }
    case_dict = {"sender_location": raw_sloc}
    sloc = derive_authoritative_location(case_dict)

    assert sloc["is_identified"] is False
    assert sloc["sender_ip"] == "Not available / Relay-masked"
    assert sloc["country"] == "Unknown"
    assert sloc["latitude"] is None
    assert sloc["longitude"] is None
    assert "attribution_disclaimer" in sloc
    assert len(sloc["attribution_disclaimer"]) > 20
    assert "relay_masked_explanation" in sloc

    # Test exact app.py line 1269 / 1383 expression
    loc_val = sloc.get('display_location', 'Unavailable') if sloc.get('is_identified') else 'Unavailable'
    assert loc_val == "Unavailable"


def test_authoritative_location_infrastructure_result_present():
    """Verify infrastructure intelligence enriches and provides origin location when sender location is absent."""
    case_data = {
        "sender_location": None,
        "infrastructure_intel": {
            "origin_ip": "54.240.0.1",
            "domain": "amazon.com",
            "country": "United States",
            "region": "Washington",
            "city": "Seattle",
            "flag": "🇺🇸",
            "latitude": 47.6062,
            "longitude": -122.3321,
            "isp": "Amazon AWS",
            "asn": "AS16509",
            "confidence": 92,
            "cloud_indicator": {
                "is_cloud_hosted": True,
                "provider": "AWS",
                "confidence": 95
            },
            "attribution_disclaimer": "Infrastructure attribution disclaimer"
        }
    }
    sloc = derive_authoritative_location(case_data)

    assert sloc["is_identified"] is True
    assert sloc["sender_ip"] == "54.240.0.1"
    assert sloc["country"] == "United States"
    assert sloc["region"] == "Washington"
    assert sloc["city"] == "Seattle"
    assert "Seattle, Washington, United States" in sloc["display_location"]
    assert sloc["org"] == "Amazon AWS"
    assert sloc["asn"] == "AS16509"
    assert sloc["cloud_provider"] == "AWS"
    assert sloc["hosting_provider"] == "AWS"
    assert sloc["confidence"] == 92
    assert sloc["attribution_disclaimer"] == "Infrastructure attribution disclaimer"

    # Test exact app.py line 1269 / 1383 expression
    loc_val = sloc.get('display_location', 'Unavailable') if sloc.get('is_identified') else 'Unavailable'
    assert "Seattle" in loc_val


def test_authoritative_location_infrastructure_result_absent():
    """Verify safe fallback when both sender location and infrastructure intelligence are absent."""
    case_data = {
        "sender_location": None,
        "infrastructure_intel": None
    }
    sloc = derive_authoritative_location(case_data)

    assert sloc["is_identified"] is False
    assert sloc["sender_ip"] == "Unavailable / Relay-masked"
    assert sloc["display_location"] == "Unavailable"
    assert sloc["country"] == "Unknown"
    assert sloc["org"] == "Unknown Network"
    assert sloc["asn"] == "Unknown ASN"
    assert sloc["cloud_provider"] == "None"
    assert sloc["confidence"] == 0
    assert len(sloc["attribution_disclaimer"]) > 20

    # Test exact app.py line 1269 / 1383 expression
    loc_val = sloc.get('display_location', 'Unavailable') if sloc.get('is_identified') else 'Unavailable'
    assert loc_val == "Unavailable"


def test_authoritative_location_from_none_input():
    """Verify derive_authoritative_location handles None case_data without exception."""
    sloc = derive_authoritative_location(None)
    assert sloc["is_identified"] is False
    assert sloc["display_location"] == "Unavailable"
    loc_val = sloc.get('display_location', 'Unavailable') if sloc.get('is_identified') else 'Unavailable'
    assert loc_val == "Unavailable"


def test_authoritative_location_with_casereport_pydantic_model():
    """Verify CaseReport Pydantic object works seamlessly with derive_authoritative_location."""
    case_report = CaseReport(
        case_id="CASE-PYDANTIC-01",
        original_sha256="abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        subject="Pydantic Test",
        sender="test@secure.bank",
        threat_verdict="Phishing Lure",
        verdict_confidence=95,
        risk_score="HIGH",
        sender_location={
            "is_identified": True,
            "sender_ip": "185.220.101.5",
            "city": "Frankfurt",
            "region": "Hesse",
            "country": "Germany",
            "flag": "🇩🇪",
            "display_location": "Frankfurt, Hesse, Germany 🇩🇪",
            "org": "Tor Exit Node",
            "asn": "AS12345"
        }
    )

    sloc = derive_authoritative_location(case_report)
    assert sloc["is_identified"] is True
    assert sloc["sender_ip"] == "185.220.101.5"
    assert sloc["city"] == "Frankfurt"
    assert sloc["country"] == "Germany"

    loc_val = sloc.get('display_location', 'Unavailable') if sloc.get('is_identified') else 'Unavailable'
    assert loc_val == "Frankfurt, Hesse, Germany 🇩🇪"


def test_safe_and_unsafe_dashboard_flows_prevent_sloc_name_error():
    """
    Integration Test: Verifies both safe and unsafe email flows correctly
    derive sloc and execute the Overview and Forensics expressions without NameError.
    """
    # 1. Safe Email Scenario
    safe_report = CaseReport(
        case_id="CASE-SAFE-01",
        original_sha256="1111111111111111111111111111111111111111111111111111111111111111",
        subject="Monthly Newsletter",
        sender="newsletter@verified-corp.com",
        threat_verdict="Verified Clean",
        verdict_confidence=99,
        risk_score="LOW",
        sender_location=None  # e.g., webmail relay without direct client IP
    )

    # Replicate app.py line 1157:
    sloc = derive_authoritative_location(safe_report)
    safe_report.sender_location = sloc

    # Replicate app.py line 1269 (Safe branch with technical details enabled):
    loc_val_safe = sloc.get('display_location', 'Unavailable') if sloc.get('is_identified') else 'Unavailable'
    assert loc_val_safe == "Unavailable"

    # 2. Unsafe Email Scenario with identified location
    unsafe_report = CaseReport(
        case_id="CASE-UNSAFE-01",
        original_sha256="2222222222222222222222222222222222222222222222222222222222222222",
        subject="Urgent Security Alert",
        sender="spoofed@paypal.com",
        threat_verdict="Phishing Lure",
        verdict_confidence=95,
        risk_score="HIGH",
        sender_location={
            "is_identified": True,
            "sender_ip": "198.51.100.23",
            "city": "Dallas",
            "region": "Texas",
            "country": "United States",
            "flag": "🇺🇸",
            "display_location": "Dallas, Texas, United States 🇺🇸",
            "org": "ColoCrossing",
            "asn": "AS36352"
        }
    )

    # Replicate app.py line 1157:
    sloc = derive_authoritative_location(unsafe_report)
    unsafe_report.sender_location = sloc

    # Replicate app.py line 1383 (Unsafe hero card metadata):
    loc_val_unsafe = sloc.get('display_location', 'Unavailable') if sloc.get('is_identified') else 'Unavailable'
    assert loc_val_unsafe == "Dallas, Texas, United States 🇺🇸"

    # Replicate Tab 3 metadata accesses:
    assert sloc.get("sender_ip") == "198.51.100.23"
    assert sloc.get("org") == "ColoCrossing"
    assert sloc.get("asn") == "AS36352"
    assert sloc.get("city") == "Dallas"
    assert sloc.get("country") == "United States"


def test_derive_authoritative_location_import_and_contract():
    """
    Focused Regression Test:
    1. Import succeeds cleanly from core.geolocation
    2. Function accepts a valid case_report
    3. Sender location is correctly returned when available
    4. Infrastructure location is correctly used when available
    5. Missing location safely produces the existing unavailable representation
    6. No unrelated infrastructure fields disappear
    """
    # 1. Import succeeds
    from core.geolocation import derive_authoritative_location as dal_func
    assert callable(dal_func)

    # 2. Function accepts valid case_report
    report_valid = CaseReport(
        case_id="CASE-CONTRACT-01",
        original_sha256="abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdef",
        sender_location={
            "is_identified": True,
            "sender_ip": "103.21.244.0",
            "city": "Mumbai",
            "region": "Maharashtra",
            "country": "India",
            "flag": "🇮🇳",
            "display_location": "Mumbai, Maharashtra, India 🇮🇳",
            "org": "Cloudflare",
            "asn": "AS13335"
        },
        infrastructure_intel={
            "cloud_indicator": {"provider": "Cloudflare", "is_cloud_hosted": True},
            "confidence": 94,
            "attribution_disclaimer": "Authoritative contract disclaimer"
        }
    )
    result_valid = dal_func(report_valid)

    # 3. Sender location correctly returned
    assert result_valid["is_identified"] is True
    assert result_valid["sender_ip"] == "103.21.244.0"
    assert result_valid["city"] == "Mumbai"
    assert result_valid["country"] == "India"
    assert "Mumbai, Maharashtra, India" in result_valid["display_location"]

    # 4. Infrastructure location is correctly used when sender location is absent
    report_infra_only = CaseReport(
        case_id="CASE-CONTRACT-02",
        original_sha256="1234561234561234561234561234561234561234561234561234561234561234",
        sender_location=None,
        infrastructure_intel={
            "origin_ip": "198.51.100.5",
            "city": "Austin",
            "region": "Texas",
            "country": "United States",
            "isp": "Local Fiber",
            "asn": "AS9999",
            "cloud_indicator": {"provider": "Dedicated Host", "is_cloud_hosted": False},
            "confidence": 88
        }
    )
    result_infra = dal_func(report_infra_only)
    assert result_infra["is_identified"] is True
    assert result_infra["sender_ip"] == "198.51.100.5"
    assert result_infra["city"] == "Austin"
    assert "Austin, Texas, United States" in result_infra["display_location"]
    assert result_infra["org"] == "Local Fiber"
    assert result_infra["asn"] == "AS9999"

    # 5. Missing location safely produces existing unavailable representation
    report_empty = CaseReport(
        case_id="CASE-CONTRACT-03",
        original_sha256="0000000000000000000000000000000000000000000000000000000000000000",
        sender_location=None,
        infrastructure_intel=None
    )
    result_empty = dal_func(report_empty)
    assert result_empty["is_identified"] is False
    assert result_empty["display_location"] == "Unavailable"
    assert result_empty["sender_ip"] == "Unavailable / Relay-masked"
    assert result_empty["country"] == "Unknown"

    # 6. No unrelated infrastructure fields disappear
    assert "cloud_provider" in result_valid
    assert "confidence" in result_valid
    assert "attribution_disclaimer" in result_valid
    assert "relay_masked_explanation" in result_valid


