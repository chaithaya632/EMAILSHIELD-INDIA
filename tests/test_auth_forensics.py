"""
tests/test_auth_forensics.py
Comprehensive tests for Forensic Authentication Alignment, Header Diff & Baseline Comparator.
Verifies that legitimate domains (such as NPTEL, Stanford, etc.) are accurately evaluated
without contradictory evidence, without false positive FORGERY classifications,
and without any hardcoded domain whitelists.
"""

import pytest
from core.header_diff import compare_headers_against_baseline, find_matching_brand_baseline
from core.auth_claims import evaluate_auth_and_alignment, extract_domain, get_org_domain


def test_no_hardcoded_nptel_whitelist():
    """Verify that no hardcoded NPTEL whitelist exists in brand baselines."""
    from core.header_diff import BRAND_BASELINES
    assert "nptel.iitm.ac.in" not in BRAND_BASELINES
    assert "iitm.ac.in" not in BRAND_BASELINES
    assert find_matching_brand_baseline("onlinecourses@nptel.iitm.ac.in") is None


def test_nptel_legitimate_email_forensics_diff():
    """
    Test legitimate NPTEL email with generic baseline:
    - Envelope From: <onlinecourses@nptel.iitm.ac.in>
    - Header From: "NPTEL" <onlinecourses@nptel.iitm.ac.in>
    - No DKIM signature
    - SPF: Pass
    - DMARC: None / Unconfigured
    - First Hop: 2002:a05:6918:fe6:b0:4a0:98ab:973b (Google internal 6to4 relay)
    """
    payload = {
        "from": '"NPTEL" <onlinecourses@nptel.iitm.ac.in>',
        "sender_name": "NPTEL",
        "return_path": "<onlinecourses@nptel.iitm.ac.in>",
        "dkim_domain": "",
        "spf": "Pass",
        "dkim": "None",
        "dmarc": "None",
        "first_hop": "2002:a05:6918:fe6:b0:4a0:98ab:973b"
    }
    
    diff = compare_headers_against_baseline(payload)
    
    assert diff["forgery_count"] == 0
    assert diff["anomaly_count"] == 0
    assert diff["verdict"] == "LEGITIMATE / ALIGNED"
    
    checkpoints = {cp["checkpoint"]: cp for cp in diff["checkpoints"]}
    
    # 1. Return-Path
    rp_cp = checkpoints["Return-Path Alignment"]
    assert rp_cp["status"] == "MATCH"
    assert "Mismatched Return-Path" not in rp_cp["finding"]
    assert "Envelope matches legitimate sender domain" in rp_cp["finding"]
    
    # 2. DKIM
    dkim_cp = checkpoints["DKIM Signing Key (d=)"]
    assert dkim_cp["status"] == "NONE"
    assert dkim_cp["severity"] == "LOW"
    assert "Signed by third-party" not in dkim_cp["finding"]
    assert "No DKIM cryptographic signature" in dkim_cp["finding"]
    
    # 3. SPF
    spf_cp = checkpoints["SPF Authentication"]
    assert spf_cp["status"] == "MATCH"
    
    # 4. DMARC
    dmarc_cp = checkpoints["DMARC Alignment"]
    assert dmarc_cp["status"] == "UNCONFIGURED"
    assert dmarc_cp["severity"] == "LOW"
    assert "DMARC failed" not in dmarc_cp["finding"]
    
    # 5. Outbound MTA / IPv6
    mta_cp = checkpoints["Outbound MTA Gateway"]
    assert mta_cp["status"] == "MATCH"
    assert "2002:a05:6918:fe6:b0:4a0:98ab:973b" in mta_cp["suspect_actual"]


def test_nptel_legitimate_email_with_dkim_signed():
    """
    Test NPTEL email when DKIM is signed by nptel.iitm.ac.in or parent iitm.ac.in.
    """
    payload = {
        "from": "onlinecourses@nptel.iitm.ac.in",
        "return_path": "<onlinecourses@nptel.iitm.ac.in>",
        "dkim_domain": "nptel.iitm.ac.in",
        "spf": "Pass",
        "dkim": "Pass",
        "dmarc": "Pass",
        "first_hop": "mail.iitm.ac.in"
    }
    
    diff = compare_headers_against_baseline(payload)
    assert diff["forgery_count"] == 0
    assert diff["verdict"] == "LEGITIMATE / ALIGNED"
    
    checkpoints = {cp["checkpoint"]: cp for cp in diff["checkpoints"]}
    assert checkpoints["DKIM Signing Key (d=)"]["status"] == "MATCH"
    assert checkpoints["DMARC Alignment"]["status"] == "MATCH"


def test_relaxed_organizational_domain_alignment():
    """
    Subdomains sharing the organizational base domain must align (e.g. cs.stanford.edu and stanford.edu).
    """
    payload = {
        "from": "alice@cs.stanford.edu",
        "return_path": "<bounces@stanford.edu>",
        "dkim_domain": "stanford.edu",
        "spf": "Pass",
        "dkim": "Pass",
        "dmarc": "Pass",
        "first_hop": "smtp.stanford.edu"
    }
    diff = compare_headers_against_baseline(payload)
    assert diff["forgery_count"] == 0
    checkpoints = {cp["checkpoint"]: cp for cp in diff["checkpoints"]}
    assert checkpoints["Return-Path Alignment"]["status"] == "MATCH"
    assert checkpoints["DKIM Signing Key (d=)"]["status"] == "MATCH"


def test_actual_brand_spoofing_triggers_forgery():
    """
    An email spoofing SBI with third-party return-path, third-party DKIM, and SPF fail
    must be flagged as CRITICAL SPOOFING with multiple forgeries detected.
    """
    payload = {
        "from": "service@sbi.co.in",
        "return_path": "bounces@untrusted-relay.com",
        "dkim_domain": "sendgrid.net",
        "spf": "Fail",
        "dkim": "Pass",
        "dmarc": "Fail",
        "first_hop": "smtp.sendgrid.net"
    }
    diff = compare_headers_against_baseline(payload, "sbi.co.in")
    assert diff["forgery_count"] >= 2
    assert "CRITICAL SPOOFING" in diff["verdict"]
    
    checkpoints = {cp["checkpoint"]: cp for cp in diff["checkpoints"]}
    assert checkpoints["Return-Path Alignment"]["status"] == "FORGERY_DETECTED"
    assert checkpoints["DKIM Signing Key (d=)"]["status"] == "FORGERY_DETECTED"
    assert checkpoints["SPF Authentication"]["status"] == "FORGERY_DETECTED"
    assert checkpoints["DMARC Alignment"]["status"] == "FORGERY_DETECTED"


def test_ipv6_transit_preservation_no_truncation():
    """
    IPv6 addresses in first_hop must not be truncated at 35 characters.
    """
    ipv6_addr = "2002:a05:6918:fe6:b0:4a0:98ab:973b"
    payload = {
        "from": "user@generic-domain.org",
        "return_path": "user@generic-domain.org",
        "dkim_domain": "",
        "spf": "Pass",
        "dkim": "None",
        "dmarc": "None",
        "first_hop": ipv6_addr
    }
    diff = compare_headers_against_baseline(payload)
    checkpoints = {cp["checkpoint"]: cp for cp in diff["checkpoints"]}
    mta_cp = checkpoints["Outbound MTA Gateway"]
    assert mta_cp["suspect_actual"] == ipv6_addr
    assert len(mta_cp["suspect_actual"]) == len(ipv6_addr)


def test_google_workspace_dkim_convention_alignment():
    """
    Test Google Workspace hyphenated customer domain DKIM signing convention.
    nptel-iitm-ac-in.20251104.gappssmtp.com must align with nptel.iitm.ac.in.
    """
    headers = {
        "from": "onlinecourses@nptel.iitm.ac.in",
        "return-path": "<noc26-cs161-announce+bnc@nptel.iitm.ac.in>",
        "dkim-signature": "v=1; a=rsa-sha256; d=nptel-iitm-ac-in.20251104.gappssmtp.com; s=20251104;",
        "authentication-results": "mx.google.com; dkim=pass header.d=nptel-iitm-ac-in.20251104.gappssmtp.com; spf=pass; dmarc=pass header.from=nptel.iitm.ac.in",
        "list-unsubscribe": "<https://groups.google.com/a/nptel.iitm.ac.in/group/noc26-cs161-announce/subscribe>"
    }
    auth_res = evaluate_auth_and_alignment(headers)
    assert auth_res["dkim_aligned"] is True
    assert auth_res["threat_detected"] is False
    assert auth_res["effective_dmarc"] == "PASS"

    # Header diff test
    payload = {
        "from": "onlinecourses@nptel.iitm.ac.in",
        "return_path": "<noc26-cs161-announce+bnc@nptel.iitm.ac.in>",
        "dkim_domain": "nptel-iitm-ac-in.20251104.gappssmtp.com",
        "spf": "Pass",
        "dkim": "Pass",
        "dmarc": "Pass",
        "first_hop": "mail-sor-f69.google.com"
    }
    diff = compare_headers_against_baseline(payload)
    assert diff["forgery_count"] == 0
    assert diff["verdict"] == "LEGITIMATE / ALIGNED"
    checkpoints = {cp["checkpoint"]: cp for cp in diff["checkpoints"]}
    assert checkpoints["DKIM Signing Key (d=)"]["status"] == "MATCH"
    assert "Google Workspace" in checkpoints["DKIM Signing Key (d=)"]["finding"]


def test_real_nptel_email_assignment_solutions_clean():
    """
    Verify real NPTEL email with Google Drive links wrapped in SendGrid ESP click tracker
    evaluates to LOW risk without triggering RULE-019 HIGH.
    """
    from core.risk import evaluate_rules, calculate_hybrid_risk
    from core.batch_scanner import categorize_content

    headers = {
        "from": "onlinecourses@nptel.iitm.ac.in",
        "subject": "Introduction to Internet of Things - Assignment- 6,7&8 Solution Released",
        "return-path": "<noc26-cs161-announce+bncBCZ5RXNBUUOBBV5PV3KQMGQEPRTAFAA@nptel.iitm.ac.in>",
        "dkim-signature": "v=1; a=rsa-sha256; d=nptel-iitm-ac-in.20251104.gappssmtp.com; s=20251104;",
        "authentication-results": "mx.google.com; dkim=pass header.d=nptel-iitm-ac-in.20251104.gappssmtp.com; spf=pass; dmarc=pass header.from=nptel.iitm.ac.in",
        "list-unsubscribe": "<https://groups.google.com/a/nptel.iitm.ac.in/group/noc26-cs161-announce/subscribe>"
    }
    body = (
        "Dear Students,\n"
        "The solutions for Assignment 6, 7 and 8 have been released.\n"
        'Assignment 6 Solution: <a href="https://u3447072.ct.sendgrid.net/ls/click?upn=123">https://drive.google.com/file/d/1YuhZ2NAKAudVxPuhLVtf0yD2LVABe7Ux/view?usp=drive_link</a>\n'
        'Assignment 7 Solution: <a href="https://u3447072.ct.sendgrid.net/ls/click?upn=456">https://drive.google.com/file/d/1E7OSfsJp2oYPUjUydYIsqQ6p8Ik6OTGE/view?usp=drive_link</a>\n'
        "Thanks and Regards, --NPTEL Team"
    )
    auth_res = evaluate_auth_and_alignment(headers)
    content_type = categorize_content(headers["subject"], body, headers["from"], headers=headers)
    parsed_data = {"headers": headers, "body": body}

    findings = evaluate_rules(parsed_data, auth_alignment=auth_res, content_type=content_type)
    r19_high = [f for f in findings if f.get("rule_id") == "RULE-019" and f.get("severity") == "HIGH"]
    assert len(r19_high) == 0, f"Unexpected RULE-019 HIGH findings: {r19_high}"

    risk_score, _ = calculate_hybrid_risk(findings, ml_prob=0.47, auth_alignment=auth_res, content_type=content_type)
    assert risk_score == "LOW"


def test_spoofed_financial_anchor_always_triggers_high():
    """
    Controlled Spoof Control: An email disguising a banking URL (e.g. sbi.co.in)
    behind an unrelated destination must trigger RULE-019 HIGH regardless of newsletter state.
    """
    from core.risk import evaluate_rules

    headers = {
        "from": "updates@promotional-blast.com",
        "subject": "Important Account Update",
        "list-unsubscribe": "<https://promotional-blast.com/unsub>"
    }
    auth_res = evaluate_auth_and_alignment(headers)
    body = 'Update your KYC: <a href="https://u3447072.ct.sendgrid.net/ls/click?upn=789">https://retail.sbi.co.in/banking/login</a>'
    parsed_data = {"headers": headers, "body": body}
    findings = evaluate_rules(parsed_data, auth_alignment=auth_res, content_type="Education / Academic")

    r19_high = [f for f in findings if f.get("rule_id") == "RULE-019" and f.get("severity") == "HIGH"]
    assert len(r19_high) > 0, "Disguised financial anchor MUST trigger RULE-019 HIGH"
