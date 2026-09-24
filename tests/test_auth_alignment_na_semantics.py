"""
tests/test_auth_alignment_na_semantics.py

Comprehensive regression tests to verify the N/A Authentication -> False Alignment HIGH fix.

CRITICAL REQUIREMENTS:
The test suite covers all 7 scenarios specified:
1. Test 1: Missing Return-Path (Envelope-From is N/A) -> SPF alignment status is NOT_DETERMINABLE,
   effective_dmarc is NOT FAIL (Alignment Bypass), RULE-014 does NOT fire (0 High findings).
2. Test 2: Missing DKIM (DKIM-d is N/A) -> DKIM alignment status is NOT_DETERMINABLE,
   effective_dmarc is NOT FAIL (Alignment Bypass), RULE-014 does NOT fire (0 High findings).
3. Test 3: Actual SPF failure (spf=fail in Authentication-Results) -> effective_dmarc is FAIL,
   threat_detected is True, RULE-014 fires with HIGH severity.
4. Test 4: Actual DKIM failure (dkim=fail in Authentication-Results) -> effective_dmarc is FAIL,
   threat_detected is True, RULE-014 fires with HIGH severity.
5. Test 5: Actual Alignment failure / Bypass (e.g. sender passes SPF on evil.com with visible
   From support@sbi.co.in) -> effective_dmarc is FAIL (Alignment Bypass),
   threat_detected is True, RULE-014 fires with HIGH severity.
6. Test 6: Legitimate NPTEL email with missing Return-Path / DKIM-d (only spf=pass; dkim=pass
   in Authentication-Results, no return-path header, no dkim-signature header) ->
   Evaluated to LOW / SAFE, RULE-014 does NOT fire, 0 High findings.
7. Test 7: NPTEL Lookalike / Phishing email (e.g. From onlinecourses@nptel-iitm-courses.com
   or From onlinecourses@nptel.iitm.ac.in with SPF fail / bypass from attacker.com) ->
   Detected as threat, RULE-014 or lookalike rule fires with HIGH severity.
"""

import unittest
from core.auth_claims import evaluate_auth_and_alignment
from core.risk import evaluate_rules, calculate_hybrid_risk
from core.lookalike import detect_lookalike_domain


class TestAuthAlignmentNASemantics(unittest.TestCase):
    """Regression test suite for N/A Authentication -> False Alignment HIGH fix."""

    def test_01_missing_return_path_envelope_from_na(self):
        """
        Test 1: Missing Return-Path (Envelope-From is N/A)
        - SPF alignment status is NOT_DETERMINABLE
        - effective_dmarc is NOT 'FAIL (Alignment Bypass)'
        - RULE-014 does NOT fire
        - 0 High findings
        """
        headers = {
            "from": "alice@university.edu",
            "subject": "Research paper discussion",
            # No Return-Path header
            "authentication-results": "mx.google.com; spf=pass; dkim=pass header.d=university.edu"
        }
        auth_res = evaluate_auth_and_alignment(headers)

        # 1. Verify SPF alignment status is NOT_DETERMINABLE
        self.assertEqual(auth_res["spf_alignment_status"], "NOT_DETERMINABLE")
        self.assertEqual(auth_res["envelope_from_domain"], "")

        # 2. Verify effective_dmarc is NOT FAIL (Alignment Bypass)
        self.assertNotIn("Alignment Bypass", auth_res["effective_dmarc"])
        self.assertFalse(auth_res["threat_detected"])

        # 3. Verify RULE-014 does NOT fire in rule evaluation
        parsed_data = {
            "headers": headers,
            "body": "Hi team, please find the latest draft of our paper attached."
        }
        findings = evaluate_rules(parsed_data, auth_alignment=auth_res)
        rule_014 = [f for f in findings if f.get("rule_id") == "RULE-014"]
        self.assertEqual(len(rule_014), 0, "RULE-014 must not fire when Return-Path is missing")

        # 4. Verify 0 High findings
        high_findings = [f for f in findings if f.get("severity") == "HIGH"]
        self.assertEqual(len(high_findings), 0, f"Expected 0 High findings, found: {high_findings}")

    def test_02_missing_dkim_signing_domain_na(self):
        """
        Test 2: Missing DKIM (DKIM-d is N/A)
        - DKIM alignment status is NOT_DETERMINABLE
        - effective_dmarc is NOT 'FAIL (Alignment Bypass)'
        - RULE-014 does NOT fire
        - 0 High findings
        """
        headers = {
            "from": "bob@corporate.org",
            "return-path": "<bob@corporate.org>",
            "subject": "Quarterly Planning Update",
            # No dkim-signature header, no header.d in Authentication-Results
            "authentication-results": "mx.google.com; spf=pass smtp.mailfrom=corporate.org; dkim=none"
        }
        auth_res = evaluate_auth_and_alignment(headers)

        # 1. Verify DKIM alignment status is NOT_DETERMINABLE
        self.assertEqual(auth_res["dkim_alignment_status"], "NOT_DETERMINABLE")
        self.assertEqual(auth_res["dkim_signing_domain"], "")

        # 2. Verify effective_dmarc is NOT FAIL (Alignment Bypass)
        self.assertNotIn("Alignment Bypass", auth_res["effective_dmarc"])
        self.assertFalse(auth_res["threat_detected"])

        # 3. Verify RULE-014 does NOT fire
        parsed_data = {
            "headers": headers,
            "body": "Team, please review the slides before our quarterly planning sync."
        }
        findings = evaluate_rules(parsed_data, auth_alignment=auth_res)
        rule_014 = [f for f in findings if f.get("rule_id") == "RULE-014"]
        self.assertEqual(len(rule_014), 0, "RULE-014 must not fire when DKIM signature is missing")

        # 4. Verify 0 High findings
        high_findings = [f for f in findings if f.get("severity") == "HIGH"]
        self.assertEqual(len(high_findings), 0, f"Expected 0 High findings, found: {high_findings}")

    def test_03_actual_spf_failure_triggers_high(self):
        """
        Test 3: Actual SPF failure (spf=fail in Authentication-Results)
        - effective_dmarc is FAIL
        - threat_detected is True
        - RULE-014 fires with HIGH severity
        """
        headers = {
            "from": "alerts@mybank.in",
            "return-path": "<alerts@mybank.in>",
            "subject": "Security Notification",
            "authentication-results": "mx.google.com; spf=fail (google.com: domain of alerts@mybank.in does not designate 198.51.100.1 as permitted sender) smtp.mailfrom=alerts@mybank.in; dkim=none"
        }
        auth_res = evaluate_auth_and_alignment(headers)

        # 1. Verify effective_dmarc is FAIL
        self.assertEqual(auth_res["effective_dmarc"], "FAIL")

        # 2. Verify threat_detected is True
        self.assertTrue(auth_res["threat_detected"])

        # 3. Verify RULE-014 fires with HIGH severity
        parsed_data = {
            "headers": headers,
            "body": "Your bank account has been locked. Contact customer support."
        }
        findings = evaluate_rules(parsed_data, auth_alignment=auth_res)
        rule_014 = [f for f in findings if f.get("rule_id") == "RULE-014"]
        self.assertTrue(len(rule_014) >= 1, "RULE-014 must fire on actual SPF failure")
        self.assertEqual(rule_014[0]["severity"], "HIGH")

    def test_04_actual_dkim_failure_triggers_high(self):
        """
        Test 4: Actual DKIM failure (dkim=fail in Authentication-Results)
        - effective_dmarc is FAIL
        - threat_detected is True
        - RULE-014 fires with HIGH severity
        """
        headers = {
            "from": "security@trusted-service.com",
            "return-path": "<security@trusted-service.com>",
            "dkim-signature": "v=1; a=rsa-sha256; d=trusted-service.com; s=k1; b=corrupted_sig;",
            "subject": "Account Verification",
            "authentication-results": "mx.google.com; dkim=fail (signature did not verify) header.d=trusted-service.com; spf=none"
        }
        auth_res = evaluate_auth_and_alignment(headers)

        # 1. Verify effective_dmarc is FAIL
        self.assertEqual(auth_res["effective_dmarc"], "FAIL")

        # 2. Verify threat_detected is True
        self.assertTrue(auth_res["threat_detected"])

        # 3. Verify RULE-014 fires with HIGH severity
        parsed_data = {
            "headers": headers,
            "body": "Please confirm your login attempt."
        }
        findings = evaluate_rules(parsed_data, auth_alignment=auth_res)
        rule_014 = [f for f in findings if f.get("rule_id") == "RULE-014"]
        self.assertTrue(len(rule_014) >= 1, "RULE-014 must fire on actual DKIM failure")
        self.assertEqual(rule_014[0]["severity"], "HIGH")

    def test_05_actual_alignment_bypass_triggers_high(self):
        """
        Test 5: Actual Alignment failure / Bypass
        - Sender passes SPF on evil.com with visible From support@sbi.co.in
        - effective_dmarc is FAIL (Alignment Bypass)
        - threat_detected is True
        - RULE-014 fires with HIGH severity
        """
        headers = {
            "from": "support@sbi.co.in",
            "return-path": "<attacker@evil.com>",
            "subject": "Mandatory KYC update required immediately",
            "authentication-results": "mx.google.com; spf=pass smtp.mailfrom=evil.com; dkim=none"
        }
        auth_res = evaluate_auth_and_alignment(headers)

        # 1. Verify effective_dmarc is FAIL (Alignment Bypass)
        self.assertEqual(auth_res["effective_dmarc"], "FAIL (Alignment Bypass)")

        # 2. Verify threat_detected is True and SPF alignment is UNALIGNED
        self.assertTrue(auth_res["threat_detected"])
        self.assertEqual(auth_res["spf_alignment_status"], "UNALIGNED")

        # 3. Verify RULE-014 fires with HIGH severity
        parsed_data = {
            "headers": headers,
            "body": "Dear customer, your SBI NetBanking profile is suspended. Update KYC now."
        }
        findings = evaluate_rules(parsed_data, auth_alignment=auth_res)
        rule_014 = [f for f in findings if f.get("rule_id") == "RULE-014"]
        self.assertTrue(len(rule_014) >= 1, "RULE-014 must fire on actual Alignment Bypass")
        self.assertEqual(rule_014[0]["severity"], "HIGH")

    def test_06_legitimate_nptel_missing_headers_low_safe(self):
        """
        Test 6: Legitimate NPTEL email with missing Return-Path / DKIM-d
        - Only spf=pass; dkim=pass in Authentication-Results
        - No return-path header, no dkim-signature header
        - Evaluated to LOW / SAFE
        - RULE-014 does NOT fire
        - 0 High findings
        """
        headers = {
            "from": "onlinecourses@nptel.iitm.ac.in",
            "subject": "Introduction to Internet of Things - Week 9 content is live now!!",
            "authentication-results": "mx.google.com; spf=pass; dkim=pass"
            # No Return-Path header, no DKIM-Signature header
        }
        auth_res = evaluate_auth_and_alignment(headers)

        # 1. Verify alignment statuses are NOT_DETERMINABLE
        self.assertEqual(auth_res["spf_alignment_status"], "NOT_DETERMINABLE")
        self.assertEqual(auth_res["dkim_alignment_status"], "NOT_DETERMINABLE")

        # 2. Verify effective_dmarc is NOT FAIL (Alignment Bypass) and threat_detected is False
        self.assertNotIn("Alignment Bypass", auth_res["effective_dmarc"])
        self.assertFalse(auth_res["threat_detected"])

        # 3. Verify RULE-014 does NOT fire
        body = (
            "Dear Candidate,\n\n"
            "Week 9 content for Introduction to Internet of Things is now live.\n"
            "Please access your course portal at: https://onlinecourses.nptel.ac.in/noc26_cs01/unit?unit=9\n"
            "Assignment 9 is available for submission.\n\n"
            "Happy Learning,\nNPTEL Team"
        )
        parsed_data = {
            "headers": headers,
            "body": body
        }
        findings = evaluate_rules(parsed_data, auth_alignment=auth_res, content_type="Education / Academic")
        rule_014 = [f for f in findings if f.get("rule_id") == "RULE-014"]
        self.assertEqual(len(rule_014), 0, "RULE-014 must not fire on legitimate NPTEL with missing Return-Path/DKIM-d")

        # 4. Verify 0 High findings
        high_findings = [f for f in findings if f.get("severity") == "HIGH"]
        self.assertEqual(len(high_findings), 0, f"Expected 0 High findings for legitimate NPTEL, found: {high_findings}")

        # 5. Verify overall risk score evaluates to LOW / SAFE
        risk_score, _ = calculate_hybrid_risk(findings, ml_prob=0.05, auth_alignment=auth_res, content_type="Education / Academic")
        self.assertIn(risk_score, ["LOW", "SAFE"], f"Expected LOW or SAFE risk score, got: {risk_score}")

    def test_07_nptel_lookalike_phishing_detected_high(self):
        """
        Test 7: NPTEL Lookalike / Phishing email
        - Variant A: From onlinecourses@nptel.iitm.ac.in with SPF bypass / fail from attacker.com
        - Variant B: From onlinecourses@nptel-iitm-courses.com (lookalike domain / third-party auth)
        - Both detected as threat, RULE-014 or lookalike rule fires with HIGH severity
        """
        # Variant A: Alignment bypass targeting NPTEL visible From
        headers_a = {
            "from": "onlinecourses@nptel.iitm.ac.in",
            "return-path": "<phish@attacker.com>",
            "subject": "Urgent: NPTEL Examination Fee Due",
            "authentication-results": "mx.google.com; spf=pass smtp.mailfrom=attacker.com; dkim=none"
        }
        auth_res_a = evaluate_auth_and_alignment(headers_a)
        self.assertEqual(auth_res_a["effective_dmarc"], "FAIL (Alignment Bypass)")
        self.assertTrue(auth_res_a["threat_detected"])

        parsed_data_a = {
            "headers": headers_a,
            "body": "Click here to pay your exam fees: http://attacker.com/pay"
        }
        findings_a = evaluate_rules(parsed_data_a, auth_alignment=auth_res_a)
        rule_014_a = [f for f in findings_a if f.get("rule_id") == "RULE-014"]
        self.assertTrue(len(rule_014_a) >= 1, "RULE-014 must fire on NPTEL alignment bypass from attacker.com")
        self.assertEqual(rule_014_a[0]["severity"], "HIGH")

        risk_score_a, _ = calculate_hybrid_risk(findings_a, ml_prob=0.85, auth_alignment=auth_res_a)
        self.assertIn(risk_score_a, ["HIGH", "CRITICAL"])

        # Variant B: Phishing email from lookalike domain with SPF fail / lookalike findings
        headers_b = {
            "from": "onlinecourses@nptel-iitm-courses.com",
            "return-path": "<support@nptel-iitm-courses.com>",
            "subject": "Exam Registration Final Warning",
            "authentication-results": "mx.google.com; spf=fail smtp.mailfrom=nptel-iitm-courses.com; dkim=none"
        }
        auth_res_b = evaluate_auth_and_alignment(headers_b)
        self.assertEqual(auth_res_b["effective_dmarc"], "FAIL")
        self.assertTrue(auth_res_b["threat_detected"])

        lookalike_info = {
            "domain": "nptel-iitm-courses.com",
            "is_lookalike": True,
            "impersonated_brand": "NPTEL",
            "technique": "Combo-squatting / Brand Affix Impersonation",
            "reasons": ["Domain mimics NPTEL portal with deceptive affixes"]
        }
        parsed_data_b = {
            "headers": headers_b,
            "body": "Immediate action required: please update your profile to prevent exam cancellation."
        }
        findings_b = evaluate_rules(parsed_data_b, auth_alignment=auth_res_b, lookalike_analysis=lookalike_info)

        # Either RULE-014 (auth failure) or RULE-016 (lookalike) must fire with HIGH severity
        high_threat_rules = [f for f in findings_b if f.get("rule_id") in ["RULE-014", "RULE-016"] and f.get("severity") == "HIGH"]
        self.assertTrue(len(high_threat_rules) >= 1, f"Expected RULE-014 or RULE-016 with HIGH severity, got: {findings_b}")

        risk_score_b, _ = calculate_hybrid_risk(findings_b, ml_prob=0.90, auth_alignment=auth_res_b)
        self.assertIn(risk_score_b, ["HIGH", "CRITICAL"])


if __name__ == "__main__":
    unittest.main()
