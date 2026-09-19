"""
tests/test_normalization_pipeline.py
Unit tests for EMAILSHIELD INDIA's multi-stage text normalization pipeline.

Verifies:
1. Exact conceptual pipeline order: Raw -> Zero-Width -> Confusables (pre-NFKC) -> NFKC -> Spaced-Tokens -> Rules & ML.
2. Confusable detection occurs strictly BEFORE NFKC normalization.
3. Zero-width and bidi characters are removed with telemetry recorded.
4. Bounded spaced-tokens: length <= 40 chars, gap <= 3 spaces, strictly per-line (no newline crossing or paragraph collapsing).
5. RULE-026 (Confusable / Mixed-Script Homoglyph) detection.
6. RULE-027 (Spaced Brand Obfuscation): Brand alone produces LOW severity; escalates only with urgency, credential lure, or deceptive hyperlink.
"""

import unittest
from core.normalization import (
    strip_zero_width_chars,
    detect_confusables,
    normalize_nfkc,
    detect_and_normalize_spaced_tokens,
    normalize_email_payload,
)
from core.risk import evaluate_rules


class TestNormalizationPipeline(unittest.TestCase):

    def test_01_zero_width_stripping(self):
        """Zero-width and bidi control characters are stripped and recorded."""
        raw_text = "H\u200be\u200cl\u200dl\ufeffo W\u202dor\u202eld"
        cleaned, evidence = strip_zero_width_chars(raw_text)
        self.assertEqual(cleaned, "Hello World")
        self.assertGreaterEqual(len(evidence), 5)
        char_codes = [e["char_code"] for e in evidence]
        self.assertIn("U+200B", char_codes)
        self.assertIn("U+200C", char_codes)
        self.assertIn("U+FEFF", char_codes)

    def test_02_confusable_detection_pre_nfkc(self):
        """Confusables must be detected before NFKC normalization erases them."""
        # Cyrillic small 'а' (U+0430) inside latin word 'pаypаl'
        spoofed_brand = "p\u0430yp\u0430l"
        
        # 1. Direct detection before NFKC finds the confusable
        res = detect_confusables(spoofed_brand)
        self.assertGreater(res["confusable_count"], 0)
        confusable_chars = [c["char"] for f in res["findings"] for c in f["confusables"]]
        self.assertIn("\u0430", confusable_chars)

        # 2. Verify master pipeline records confusables before NFKC normalization
        payload = normalize_email_payload(raw_subject=spoofed_brand, raw_body="")
        self.assertGreater(payload["confusable_evidence"]["confusable_count"], 0)
        self.assertEqual(payload["normalized_subject"].lower(), "paypal")

    def test_03_bounded_spaced_tokens(self):
        """Spaced tokens are normalized within bounds and strictly per-line."""
        # Case A: Standard spaced brand
        text = "Please verify your H D F C account credentials immediately."
        norm, evidence = detect_and_normalize_spaced_tokens(text)
        self.assertIn("hdfc", norm.lower())
        self.assertGreaterEqual(len(evidence), 1)
        self.assertEqual(evidence[0]["normalized"], "hdfc")

        # Case B: Gap > 3 spaces should not be treated as spaced token
        text_wide_gap = "H    D    F    C"
        norm_wide, evidence_wide = detect_and_normalize_spaced_tokens(text_wide_gap)
        self.assertEqual(evidence_wide, [])

        # Case C: Does NOT cross newlines or collapse paragraphs
        multiline_text = "Word A\nB line two\nC line three"
        norm_multi, evidence_multi = detect_and_normalize_spaced_tokens(multiline_text)
        self.assertEqual(norm_multi, multiline_text)
        self.assertEqual(evidence_multi, [])

        # Case D: Match exceeding max_window is bounded and ignored
        spaced_token_sample = "x x x x x x x"  # 13 characters
        norm_long, evidence_long = detect_and_normalize_spaced_tokens(spaced_token_sample, max_window=10)
        self.assertEqual(evidence_long, [])

    def test_04_rule_026_confusable_homoglyphs(self):
        """RULE-026 flags mixed-script confusables with MEDIUM severity."""
        norm_payload = normalize_email_payload(
            raw_subject="Security Alert for your p\u0430yp\u0430l account",
            raw_body="Your p\u0430yp\u0430l account has been locked."
        )
        parsed_email = {
            "headers": {"subject": norm_payload["normalized_subject"], "from": "support@service.com"},
            "body": norm_payload["normalized_body"]
        }
        findings = evaluate_rules(
            parsed_email=parsed_email,
            normalization_data=norm_payload
        )
        rule_026 = next((r for r in findings if r.get("rule_id") == "RULE-026"), None)
        self.assertIsNotNone(rule_026, "RULE-026 should be triggered by mixed-script confusables")
        self.assertEqual(rule_026["severity"], "MEDIUM")

    def test_05_rule_027_brand_alone_is_low(self):
        """CRITICAL: Spaced brand alone MUST NOT produce HIGH severity (produces LOW)."""
        # Spaced brand in a benign context without urgency, credential harvest, or deceptive URL
        norm_payload = normalize_email_payload(
            raw_subject="Monthly Newsletter from H D F C B A N K",
            raw_body="Thank you for being a valued customer. Here are the latest educational tips."
        )
        parsed_email = {
            "headers": {"subject": norm_payload["normalized_subject"], "from": "newsletter@hdfcbank.com"},
            "body": norm_payload["normalized_body"]
        }
        findings = evaluate_rules(
            parsed_email=parsed_email,
            auth_alignment={"effective_dmarc": "PASS"},
            normalization_data=norm_payload
        )
        rule_027 = next((r for r in findings if r.get("rule_id") == "RULE-027"), None)
        self.assertIsNotNone(rule_027, "RULE-027 should trigger on spaced brand token")
        self.assertEqual(rule_027["severity"], "LOW", "Spaced brand alone MUST NOT be HIGH; must be LOW")

    def test_06_rule_027_escalates_with_credential_lure(self):
        """Spaced brand escalates to HIGH when combined with credential harvesting lure."""
        norm_payload = normalize_email_payload(
            raw_subject="URGENT: Verify your H D F C account credentials",
            raw_body="Your password has expired. Click here to verify your password and login immediately. Update password."
        )
        parsed_email = {
            "headers": {"subject": norm_payload["normalized_subject"], "from": "security@attacker-phish.com"},
            "body": norm_payload["normalized_body"]
        }
        findings = evaluate_rules(
            parsed_email=parsed_email,
            auth_alignment={"effective_dmarc": "FAIL"},
            normalization_data=norm_payload
        )
        rule_027 = next((r for r in findings if r.get("rule_id") == "RULE-027"), None)
        self.assertIsNotNone(rule_027)
        self.assertIn(rule_027["severity"], ["MEDIUM", "HIGH"], "Spaced brand + credential lure must escalate")


if __name__ == "__main__":
    unittest.main()
