"""
tests/test_infrastructure_intelligence.py
Comprehensive Verification Test Suite for SIH26106 Infrastructure Intelligence Gap Closure.

Validates 19 distinct functional invariants:
1. VPN detection positive (Mullvad, NordVPN, etc.) -> DETECTED
2. VPN detection negative (clean public IP) -> NOT_DETECTED
3. VPN detection unknown on private/reserved IP -> UNKNOWN
4. Tor detection positive (verified exit relay) -> DETECTED
5. Tor detection negative (clean public IP) -> NOT_DETECTED
6. Tor detection fail-closed on invalid and RFC1918 IPs -> UNKNOWN
7. Passive open-relay detection indicated (anomalies / abusive transit) -> INDICATED (100% passive)
8. Passive open-relay detection not indicated (standard delivery) -> NOT_INDICATED
9. Botnet detection indicated (C2 / spambot pool) -> INDICATED
10. Botnet detection not indicated (standard mail infrastructure) -> NOT_INDICATED
11. Cloud infrastructure classification (AWS, Azure, GCP, Cloudflare, DigitalOcean) -> is_cloud_hosted=True
12. Domain registrar intelligence extraction (RDAP + WHOIS fallback) -> RegistrarIntel
13. DNS & MX intelligence resolution with strict SSRF protection -> is_ssrf_safe
14. Threat intelligence blacklist correlation -> MATCH, NO_MATCH, UNKNOWN
15. Unified InfrastructureAssessment serialization & schema compliance
16. AutonomousForensicAgent ReAct step 10 integration
17. Forensic rule matrix evaluation for RULE-022, RULE-023, RULE-024, RULE-024-RELAY, RULE-025
18. Attack Graph build_case_infrastructure_graph generation
19. Forensic PDF and JSON reports inclusion of infrastructure intelligence & disclaimers
"""

import io
import pytest
from unittest.mock import patch, MagicMock

from core.infrastructure_intel import (
    classify_cloud_infrastructure,
    detect_vpn_indicator,
    detect_tor_indicator,
    detect_open_relay_indicator,
    detect_botnet_indicator,
    correlate_threat_intelligence,
    resolve_dns_mx_intelligence,
    extract_registrar_intel,
    assess_infrastructure,
    InfrastructureAssessment,
    ATTRIBUTION_DISCLAIMER
)
from core.schemas import CaseReport, Indicator
from core.agent import AutonomousForensicAgent
from core.risk import evaluate_rules, calculate_hybrid_risk
from core.correlation import build_case_infrastructure_graph
from core.report import generate_pdf_report, generate_json_report
from core.case_store import filter_raw_json_allowlist


# =====================================================================
# 1. VPN DETECTION TESTS
# =====================================================================

def test_vpn_detection_positive():
    """Verify commercial VPN detection on known ASN and organization keywords."""
    # Test ASN match (Mullvad ASN 210644)
    res_asn = detect_vpn_indicator(ip="185.213.154.2", asn="210644", org="Amagicom AB")
    assert res_asn.status == "DETECTED"
    assert "Mullvad" in res_asn.provider
    assert res_asn.confidence >= 90

    # Test Org keyword match (NordVPN)
    res_org = detect_vpn_indicator(ip="185.156.172.5", asn="60060", org="NordVPN Network")
    assert res_org.status == "DETECTED"
    assert "NordVPN" in res_org.provider


def test_vpn_detection_negative():
    """Verify clean public infrastructure reports NOT_DETECTED."""
    res = detect_vpn_indicator(ip="142.250.190.46", asn="15169", org="Google LLC")
    assert res.status == "NOT_DETECTED"
    assert res.provider is None
    assert res.confidence >= 80


def test_vpn_detection_unknown_on_private_ip():
    """Verify private and unroutable IPs return UNKNOWN."""
    res_priv = detect_vpn_indicator(ip="192.168.1.1", asn="None", org="Private")
    assert res_priv.status == "UNKNOWN"

    res_loop = detect_vpn_indicator(ip="127.0.0.1", asn="", org="")
    assert res_loop.status == "UNKNOWN"


# =====================================================================
# 2. TOR DETECTION TESTS
# =====================================================================

def test_tor_detection_positive():
    """Verify known verified Tor exit node from curated dataset returns DETECTED."""
    res = detect_tor_indicator(ip="185.220.101.5")
    assert res.status == "DETECTED"
    assert res.exit_node_ip == "185.220.101.5"
    assert res.confidence >= 95
    assert "Tor exit" in res.evidence


def test_tor_detection_negative():
    """Verify standard legitimate IP does not trigger Tor alert."""
    res = detect_tor_indicator(ip="8.8.8.8")
    assert res.status == "NOT_DETECTED"
    assert res.exit_node_ip is None
    assert res.confidence >= 90


def test_tor_detection_fail_closed_invalid_and_private_ip():
    """Verify fail-closed behavior on invalid string, loopback, and RFC1918."""
    # Loopback
    res_loop = detect_tor_indicator(ip="127.0.0.1")
    assert res_loop.status == "UNKNOWN"

    # RFC 1918
    res_priv = detect_tor_indicator(ip="10.0.0.1")
    assert res_priv.status == "UNKNOWN"

    # Garbage syntax
    res_inv = detect_tor_indicator(ip="not-an-ip-address")
    assert res_inv.status == "UNKNOWN"

    # Empty string
    res_empty = detect_tor_indicator(ip="")
    assert res_empty.status == "UNKNOWN"


# =====================================================================
# 3. PASSIVE OPEN-RELAY DETECTION TESTS (ZERO PROBING)
# =====================================================================

def test_open_relay_passive_detection_indicated():
    """Verify passive detection triggers when unauthenticated relay marker or abusive ASN is observed."""
    # Test abusive transit ASN
    res_asn = detect_open_relay_indicator(
        received_chain=["from unknown by relay.evil.com with ESMTP"],
        headers={"from": "spoofed@bank.com"},
        asn="45102"
    )
    assert res_asn.status == "INDICATED"
    assert res_asn.confidence >= 80

    # Test explicit unauthenticated relay keyword in Received header
    res_kw = detect_open_relay_indicator(
        received_chain=["from bad.host by open-relay.net with SMTP; id 1234"],
        headers={},
        asn="1234"
    )
    assert res_kw.status == "INDICATED"
    assert "open-relay" in res_kw.evidence.lower()


def test_open_relay_passive_detection_not_indicated():
    """Verify standard legitimate authenticated hops return NOT_INDICATED."""
    chain = [
        "from mail-wm1-f44.google.com (mail-wm1-f44.google.com [209.85.128.44]) by mx.google.com with ESMTPS id 123; TLS1_3",
        "by 2002:a05:600c:4c87 with SMTP id abc"
    ]
    res = detect_open_relay_indicator(received_chain=chain, headers={}, asn="15169")
    assert res.status == "NOT_INDICATED"
    assert res.confidence >= 80


# =====================================================================
# 4. BOTNET DETECTION TESTS
# =====================================================================

def test_botnet_detection_indicated():
    """Verify botnet C2 IP or spambot pool ASN triggers INDICATED."""
    # Matched in threat feed as botnet C2
    res_c2 = detect_botnet_indicator(ip="194.165.16.11", domain="evil.com", asn="1234", org="Bad Hosting")
    assert res_c2.status == "INDICATED"
    assert "Botnet" in str(res_c2.botnet_family)

    # Matched spambot ASN
    res_asn = detect_botnet_indicator(ip="114.240.1.1", domain="test.com", asn="4837", org="China Unicom Dynamic Pool")
    assert res_asn.status == "INDICATED"
    assert "Residential Spambot Pool" in str(res_asn.botnet_family)


def test_botnet_detection_not_indicated():
    """Verify clean business infrastructure returns NOT_INDICATED."""
    res = detect_botnet_indicator(ip="142.250.190.46", domain="google.com", asn="15169", org="Google LLC")
    assert res.status == "NOT_INDICATED"
    assert res.botnet_family is None


# =====================================================================
# 5. CLOUD INFRASTRUCTURE CLASSIFICATION TESTS
# =====================================================================

def test_cloud_infrastructure_classification():
    """Verify accurate classification across hyperscalers and VPS providers."""
    # AWS
    res_aws = classify_cloud_infrastructure(asn="16509", org="Amazon.com, Inc.", ip="54.240.0.1")
    assert res_aws.is_cloud_hosted is True
    assert res_aws.provider == "AWS"
    assert res_aws.confidence >= 90

    # Azure
    res_az = classify_cloud_infrastructure(asn="8075", org="Microsoft Corporation", ip="40.76.4.15")
    assert res_az.is_cloud_hosted is True
    assert res_az.provider == "Azure"

    # GCP
    res_gcp = classify_cloud_infrastructure(asn="15169", org="Google LLC", ip="34.120.5.10")
    assert res_gcp.is_cloud_hosted is True
    assert res_gcp.provider == "GCP"

    # DigitalOcean
    res_do = classify_cloud_infrastructure(asn="14061", org="DigitalOcean, LLC", ip="159.65.1.1")
    assert res_do.is_cloud_hosted is True
    assert res_do.provider == "DigitalOcean"

    # Non-cloud dedicated or local
    res_std = classify_cloud_infrastructure(asn="701", org="Verizon Business", ip="198.6.1.1")
    assert res_std.is_cloud_hosted is False
    assert "Dedicated" in res_std.provider or "None" in res_std.provider


# =====================================================================
# 6. DOMAIN REGISTRAR INTELLIGENCE TESTS
# =====================================================================

def test_registrar_intelligence_extraction():
    """Verify registrar name, creation date, domain age, and RDAP source parsing."""
    intel = extract_registrar_intel("paypal.com")
    assert intel.registrar != "Unknown"
    assert intel.creation_date != "Unknown"
    assert intel.domain_age_days is not None and intel.domain_age_days > 1000
    assert intel.confidence >= 80


# =====================================================================
# 7. DNS & MX INTELLIGENCE RESOLUTION WITH SSRF GUARDS
# =====================================================================

def test_dns_mx_intelligence_with_ssrf_guard():
    """Verify DNS resolution extracts MX records and filters non-public SSRF addresses."""
    # Normal domain
    res = resolve_dns_mx_intelligence("google.com")
    assert res.domain == "google.com"
    assert res.is_ssrf_safe is True
    assert len(res.a_records) > 0 or len(res.mx_records) > 0

    # SSRF verification: Mock a private IP resolution for an internal domain
    with patch("dns.resolver.Resolver.resolve") as mock_resolve:
        mock_rr = MagicMock()
        mock_rr.__iter__.return_value = ["10.0.0.1"]  # RFC 1918 Private IP
        mock_resolve.return_value = mock_rr

        ssrf_intel = resolve_dns_mx_intelligence("internal-target-corp.local")
        assert ssrf_intel.is_ssrf_safe is False
        assert "10.0.0.1" not in ssrf_intel.a_records  # Strictly filtered


# =====================================================================
# 8. THREAT INTELLIGENCE FEED CORRELATION TESTS
# =====================================================================

def test_threat_feed_correlation():
    """Verify threat intelligence blacklist correlation matches known IOCs."""
    # IP Match
    res_ip = correlate_threat_intelligence(ip="194.165.16.11", domain="clean.com")
    assert res_ip.status == "MATCH"
    assert "Feodo" in str(res_ip.feed_name)
    assert res_ip.confidence >= 90

    # Domain Match
    res_dom = correlate_threat_intelligence(ip="1.1.1.1", domain="secure-sbi-update.xyz")
    assert res_dom.status == "MATCH"
    assert "Phishing" in str(res_dom.category)

    # Clean IP & Domain
    res_clean = correlate_threat_intelligence(ip="8.8.8.8", domain="google.com")
    assert res_clean.status == "NO_MATCH"
    assert res_clean.confidence >= 80


# =====================================================================
# 9. UNIFIED ASSESSMENT MODEL SERIALIZATION TESTS
# =====================================================================

def test_unified_infrastructure_assessment_model():
    """Verify master assess_infrastructure produces valid, complete InfrastructureAssessment."""
    assessment = assess_infrastructure(
        ip="185.220.101.5",
        domain="paypal.com",
        headers={"from": "service@paypal.com"},
        received_chain=["from 185.220.101.5 by mx.google.com with ESMTP"]
    )

    assert isinstance(assessment, InfrastructureAssessment)
    assert assessment.tor_indicator.status == "DETECTED"
    assert assessment.domain == "paypal.com"
    assert assessment.attribution_disclaimer == ATTRIBUTION_DISCLAIMER

    # JSON serialization
    dump = assessment.model_dump()
    assert dump["tor_indicator"]["status"] == "DETECTED"
    assert "attribution_disclaimer" in dump


# =====================================================================
# 10. RE-ACT AGENT STEP 10 INTEGRATION TESTS
# =====================================================================

def test_agentic_react_step_10_integration():
    """Verify AutonomousForensicAgent runs Infrastructure_Threat_Intel_Tool."""
    mock_ml = MagicMock()
    mock_ml.predict.return_value = {"assessment": "Phishing", "probability": 0.95, "features_used": ["urgent"]}

    agent = AutonomousForensicAgent(mock_ml)
    sample_email = {
        "headers": {
            "subject": "Urgent Security Verification",
            "from": "security@paypal-account-verification-alert.top",
            "received": ["from 185.220.101.5 by mail.test.com"]
        },
        "body": "Click here to verify your PayPal account.",
        "received_chain": ["from 185.220.101.5 by mail.test.com"]
    }

    out = agent.run_investigation(
        parsed_email=sample_email,
        raw_iocs={"ipv4": ["185.220.101.5"], "urls": []}
    )

    assert "infrastructure_intel" in out
    infra = out["infrastructure_intel"]
    assert infra.tor_indicator.status == "DETECTED"
    assert infra.threat_intel_match.status == "MATCH"

    # Verify AgentStep trace includes Infrastructure_Threat_Intel_Tool
    tools_used = [step.tool_used for step in out["agent_steps"]]
    assert "Infrastructure_Threat_Intel_Tool" in tools_used


# =====================================================================
# 11. FORENSIC RULE MATRIX RULES 22 TO 25 TESTS
# =====================================================================

def test_forensic_rule_matrix_rules_22_to_25():
    """Verify evaluation of RULE-022, RULE-023, RULE-024, RULE-024-RELAY, and RULE-025."""
    # 1. Threat Feed Match -> RULE-022 (HIGH)
    infra_threat = assess_infrastructure(ip="194.165.16.11", domain="test.com")
    rules_threat = evaluate_rules(parsed_email={"headers": {}}, infrastructure_intel=infra_threat)
    assert any(r["rule_id"] == "RULE-022" and r["severity"] == "HIGH" for r in rules_threat)

    # 2. Tor Exit Node -> RULE-023 (HIGH)
    infra_tor = assess_infrastructure(ip="185.220.101.5", domain="test.com")
    rules_tor = evaluate_rules(parsed_email={"headers": {}}, infrastructure_intel=infra_tor)
    assert any(r["rule_id"] == "RULE-023" and r["severity"] == "HIGH" for r in rules_tor)

    # 3. Commercial VPN -> RULE-024 (MEDIUM or LOW)
    infra_vpn = assess_infrastructure(ip="185.213.154.2", domain="test.com", geo_data={"asn": "210644", "org": "Mullvad"})
    rules_vpn = evaluate_rules(parsed_email={"headers": {}}, infrastructure_intel=infra_vpn)
    assert any(r["rule_id"] == "RULE-024" for r in rules_vpn)

    # 4. Open Relay Indicator -> RULE-024-RELAY (MEDIUM)
    infra_relay = assess_infrastructure(
        ip="1.2.3.4",
        domain="test.com",
        headers={"from": "attacker@victim.com"},
        received_chain=["from bad.host by open-relay.net with SMTP"]
    )
    rules_relay = evaluate_rules(parsed_email={"headers": {}}, infrastructure_intel=infra_relay)
    assert any(r["rule_id"] == "RULE-024-RELAY" for r in rules_relay)

    # 5. Cloud VPS with Identity Anomaly -> RULE-025 (HIGH / MEDIUM)
    infra_cloud = assess_infrastructure(ip="54.240.0.1", domain="lookalike-brand.xyz", geo_data={"asn": "16509", "org": "Amazon.com"})
    mock_lookalike = MagicMock()
    mock_lookalike.is_lookalike = True
    rules_cloud = evaluate_rules(
        parsed_email={"headers": {}},
        lookalike_analysis=mock_lookalike,
        infrastructure_intel=infra_cloud
    )
    assert any(r["rule_id"] == "RULE-025" for r in rules_cloud)


# =====================================================================
# 12. ATTACK GRAPH GENERATION TESTS
# =====================================================================

def test_correlation_attack_graph_generation():
    """Verify build_case_infrastructure_graph builds interactive Plotly figure with ASN & Provider nodes."""
    case_data = {
        "case_id": "CASE-TEST-001",
        "sender": "support@paypal-alert.top",
        "sender_location": {"sender_ip": "54.240.0.1", "asn": "16509", "org": "Amazon AWS"},
        "infrastructure_intel": {
            "origin_ip": "54.240.0.1",
            "domain": "paypal-alert.top",
            "asn": "16509",
            "cloud_indicator": {"is_cloud_hosted": True, "provider": "AWS"},
            "vpn_indicator": {"status": "NOT_DETECTED"},
            "tor_indicator": {"status": "NOT_DETECTED"},
            "threat_intel_match": {"status": "MATCH", "feed_name": "PhishFeed"},
            "registrar_intel": {"registrar": "GoDaddy.com, LLC"}
        }
    }

    fig = build_case_infrastructure_graph("CASE-TEST-001", case_data)
    assert fig is not None
    # Check that scatter traces exist
    assert len(fig.data) == 2
    # Verify title text contains case id
    assert "CASE-TEST-001" in fig.layout.title.text


# =====================================================================
# 13. FORENSIC REPORTS INTEGRATION TESTS
# =====================================================================

def test_forensic_reports_infrastructure_integration():
    """Verify PDF and JSON reports serialize and include infrastructure intelligence."""
    case_dict = {
        "case_id": "CASE-INFRA-REPORT",
        "timestamp": "2026-09-18T10:00:00Z",
        "original_sha256": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        "subject": "Phishing Test",
        "sender": "fake@paypal-account-verification-alert.top",
        "threat_verdict": "Phishing Lure",
        "verdict_confidence": 95,
        "risk_score": "HIGH",
        "sender_location": {"is_identified": True, "sender_ip": "185.220.101.5", "org": "Tor Exit"},
        "infrastructure_intel": {
            "origin_ip": "185.220.101.5",
            "domain": "paypal-account-verification-alert.top",
            "cloud_indicator": {"provider": "Dedicated / Non-Cloud", "confidence": 80, "evidence": "Non-cloud"},
            "vpn_indicator": {"status": "NOT_DETECTED", "confidence": 85, "evidence": "None"},
            "tor_indicator": {"status": "DETECTED", "confidence": 98, "evidence": "Verified Tor exit relay"},
            "open_relay_indicator": {"status": "NOT_INDICATED", "confidence": 85, "evidence": "Clean transit"},
            "botnet_indicator": {"status": "NOT_INDICATED", "confidence": 85, "evidence": "No botnet"},
            "threat_intel_match": {"status": "MATCH", "confidence": 99, "evidence": "Blacklist match"},
            "registrar_intel": {"registrar": "NameCheap", "creation_date": "2026-09-01", "domain_age_days": 17, "confidence": 90}
        }
    }

    # 1. JSON Report
    json_str = generate_json_report(case_dict)
    assert "infrastructure_intel" in json_str
    assert "DETECTED" in json_str
    assert "Tor Exit" in json_str

    # 2. PDF Report
    pdf_buffer = io.BytesIO()
    generate_pdf_report(case_dict, output_path=pdf_buffer)
    pdf_bytes = pdf_buffer.getvalue()
    assert len(pdf_bytes) > 1000
    assert b"%PDF" in pdf_bytes[:10]


# =====================================================================
# 14. CASE STORE RAW_JSON ALLOWLIST PERSISTENCE TESTS
# =====================================================================

def test_case_store_raw_json_allowlist_preserves_infrastructure_intel():
    """Verify filter_raw_json_allowlist retains infrastructure_intel while stripping forbidden keys."""
    raw_case = {
        "case_id": "CASE-PERSIST-01",
        "password": "secret_app_password",
        "body": "Full unmasked email body",
        "infrastructure_intel": {
            "origin_ip": "54.240.0.1",
            "asn": "16509",
            "cloud_indicator": {"provider": "AWS"}
        }
    }

    clean = filter_raw_json_allowlist(raw_case)
    assert "password" not in clean
    assert "body" not in clean
    assert "infrastructure_intel" in clean
    assert clean["infrastructure_intel"]["asn"] == "16509"


# =====================================================================
# 15. REGRESSION TEST FOR updated_case_dict IN STREAMLIT EXPORT FLOW
# =====================================================================

def test_updated_case_dict_construction_and_report_generation():
    """
    Regression Test: Ensures updated_case_dict is correctly constructed
    from case_report.model_dump() and passed into PDF, JSON, and NCRP exporters
    without NameError or data loss.
    """
    from core.parser import SecureEmailParser
    from core.classifier import MLClassifier
    from core.ncrp_packager import generate_ncrp_complaint_text, generate_ncrp_pdf_annexure

    with open("samples/phishing.eml", "rb") as f:
        eml_bytes = f.read()

    parser = SecureEmailParser(eml_bytes)
    parsed = parser.parse()
    headers = parsed.get("headers", {})
    body = parsed.get("body", "")

    agent = AutonomousForensicAgent(MLClassifier())
    agent_out = agent.run_investigation(
        parsed_email=parsed,
        raw_iocs={"ipv4": ["54.240.0.1"], "urls": []}
    )

    infra_intel = agent_out.get("infrastructure_intel")
    assert infra_intel is not None

    case_report = CaseReport(
        case_id="CASE-REGRESSION-01",
        original_sha256=parsed["sha256"],
        subject=headers.get("subject", "Test Subject"),
        sender=headers.get("from", "test@test.com"),
        content_type="Direct Mail",
        status="Open",
        assigned_investigator="Investigator 1",
        analyst_notes="Test Notes",
        threat_verdict="Phishing Lure",
        verdict_confidence=90,
        indicators=[Indicator(type="IP", value="54.240.0.1", source="Headers")],
        rule_findings=agent_out["rule_findings"],
        infrastructure_intel=infra_intel,
        risk_score=agent_out["risk_score"],
        risk_reasons=agent_out["reasons"]
    )

    # Replicate exact app.py lines:
    new_status = "In Progress"
    new_investigator = "Senior Analyst"
    new_notes = "Updated investigation findings"
    geolocations = []

    updated_case_dict = case_report.model_dump()
    updated_case_dict["status"] = new_status
    updated_case_dict["assigned_investigator"] = new_investigator
    updated_case_dict["investigator"] = new_investigator
    updated_case_dict["analyst_notes"] = new_notes
    updated_case_dict["body_text"] = body
    updated_case_dict["sha256"] = case_report.original_sha256
    if geolocations:
        updated_case_dict["originating_ip"] = geolocations[0].ip

    # Verify updated_case_dict contains infrastructure_intel
    assert "infrastructure_intel" in updated_case_dict
    assert updated_case_dict["status"] == "In Progress"
    assert updated_case_dict["assigned_investigator"] == "Senior Analyst"

    # Test PDF generation
    pdf_bytes = io.BytesIO()
    generate_pdf_report(updated_case_dict, pdf_bytes)
    assert len(pdf_bytes.getvalue()) > 500
    assert b"%PDF" in pdf_bytes.getvalue()[:10]

    # Test JSON generation
    json_str = generate_json_report(updated_case_dict)
    assert "CASE-REGRESSION-01" in json_str
    assert "infrastructure_intel" in json_str

    # Test NCRP exports
    ncrp_text = generate_ncrp_complaint_text(updated_case_dict)
    assert len(ncrp_text) > 20

    ncrp_pdf_bytes = io.BytesIO()
    generate_ncrp_pdf_annexure(updated_case_dict, ncrp_pdf_bytes)
    assert len(ncrp_pdf_bytes.getvalue()) > 500

