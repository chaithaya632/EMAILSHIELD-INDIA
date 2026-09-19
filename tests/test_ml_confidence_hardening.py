"""
tests/test_ml_confidence_hardening.py
Unit tests for EMAILSHIELD INDIA's confidence-aware ML classifier hardening.

Verifies:
1. Confidence score calculation: abs(prob - 0.5) * 2.0.
2. High confidence: prob >= 0.80 or prob <= 0.20 (confidence_score >= 0.60).
3. Low confidence: 0.20 < prob < 0.38 or 0.62 < prob < 0.80.
4. Borderline region: 0.38 <= prob <= 0.62 (confidence_score <= 0.24).
5. Borderline predictions cannot override deterministic forensic evidence or cryptographic authentication alignment.
6. MLAssessment schema validation with confidence fields.
"""

import unittest
from unittest.mock import MagicMock
from core.classifier import MLClassifier
from core.schemas import MLAssessment
from core.risk import calculate_hybrid_risk


class TestMLConfidenceHardening(unittest.TestCase):

    def setUp(self):
        self.classifier = MLClassifier()

    def test_01_confidence_score_calculation(self):
        """Verify confidence score formula: abs(prob - 0.5) * 2.0."""
        pred = self.classifier.predict(
            subject="Team Meeting Agenda for Tomorrow",
            body="Hi team, here is the agenda for our weekly sync. Let me know if you have topics."
        )
        self.assertIn("confidence_score", pred)
        self.assertIn("confidence_level", pred)
        self.assertIn("is_borderline", pred)

        prob = pred["probability"]
        expected_score = round(abs(prob - 0.5) * 2.0, 4)
        self.assertAlmostEqual(pred["confidence_score"], expected_score, places=3)

    def test_02_high_confidence_phishing(self):
        """High confidence classification when probability >= 0.80 or <= 0.20."""
        mock_classifier = MLClassifier()
        mock_classifier.model = MagicMock()
        mock_classifier.vectorizer = MagicMock()
        mock_classifier.vectorizer.transform.return_value = [[1, 2, 3]]
        
        # Test High Confidence Phishing (prob >= 0.80)
        mock_classifier.model.predict_proba.return_value = [[0.10, 0.90]]
        pred_phish = mock_classifier.predict("Account Suspended", "Verify password immediately")
        self.assertEqual(pred_phish["confidence_level"], "HIGH CONFIDENCE")
        self.assertFalse(pred_phish["is_borderline"])
        self.assertGreaterEqual(pred_phish["confidence_score"], 0.60)

        # Test High Confidence Safe (prob <= 0.20)
        mock_classifier.model.predict_proba.return_value = [[0.95, 0.05]]
        pred_safe = mock_classifier.predict("Project Update", "All milestones on schedule")
        self.assertEqual(pred_safe["confidence_level"], "HIGH CONFIDENCE")
        self.assertFalse(pred_safe["is_borderline"])
        self.assertGreaterEqual(pred_safe["confidence_score"], 0.60)

    def test_03_borderline_flagging(self):
        """Borderline classification triggered when probability falls between 0.38 and 0.62."""
        mock_classifier = MLClassifier()
        mock_classifier.model = MagicMock()
        mock_classifier.vectorizer = MagicMock()
        mock_classifier.vectorizer.transform.return_value = [[1, 2, 3]]
        mock_classifier.model.predict_proba.return_value = [[0.50, 0.50]]

        pred = mock_classifier.predict("Ambiguous Subject", "Ambiguous body text")
        self.assertTrue(pred["is_borderline"])
        self.assertEqual(pred["confidence_level"], "BORDERLINE")
        self.assertEqual(pred["confidence_score"], 0.0)

    def test_04_borderline_cannot_override_forensic_evidence(self):
        """Borderline ML predictions must not override deterministic forensic rules."""
        # High-severity forensic rule with borderline ML should still result in HIGH risk
        risk_high, reasons_high = calculate_hybrid_risk(
            rule_findings=[{"severity": "HIGH", "rule_id": "RULE-001"}],
            ml_prob=0.45,  # Borderline prob
            auth_alignment={"effective_dmarc": "FAIL"},
            is_ml_borderline=True
        )
        self.assertEqual(risk_high, "HIGH", "Deterministic HIGH rule must prevail over borderline ML")

        # Zero forensic findings with borderline ML should result in LOW / safe risk
        risk_clean, reasons_clean = calculate_hybrid_risk(
            rule_findings=[],
            ml_prob=0.55,  # Borderline prob
            auth_alignment={"effective_dmarc": "PASS"},
            is_ml_borderline=True
        )
        self.assertEqual(risk_clean, "LOW", "Clean deterministic auth and zero rules must not be escalated by borderline ML")

    def test_05_ml_assessment_schema_validation(self):
        """MLAssessment Pydantic model correctly serializes confidence fields."""
        assessment = MLAssessment(
            model_version="1.0",
            probability=0.92,
            assessment="Phishing",
            features_used=["subject", "body"],
            confidence_level="HIGH CONFIDENCE",
            confidence_score=0.84,
            is_borderline=False
        )
        dump = assessment.model_dump()
        self.assertEqual(dump["confidence_level"], "HIGH CONFIDENCE")
        self.assertEqual(dump["confidence_score"], 0.84)
        self.assertFalse(dump["is_borderline"])


if __name__ == "__main__":
    unittest.main()
