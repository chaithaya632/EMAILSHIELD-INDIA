import joblib
import os

MODEL_PATH = os.path.join("models", "model.joblib")
VECTORIZER_PATH = os.path.join("models", "vectorizer.joblib")

class MLClassifier:
    def __init__(self):
        self.model = None
        self.vectorizer = None
        self.load_models()

    def load_models(self):
        if os.path.exists(MODEL_PATH) and os.path.exists(VECTORIZER_PATH):
            self.model = joblib.load(MODEL_PATH)
            self.vectorizer = joblib.load(VECTORIZER_PATH)
    
    def predict(self, subject: str, body: str) -> dict:
        if not self.model or not self.vectorizer:
            return {
                "probability": 0.0,
                "confidence_score": 0.0,
                "confidence_level": "LOW CONFIDENCE",
                "is_borderline": False,
                "assessment": "Model not loaded",
                "features_used": ["subject", "body"]
            }

        text = (subject + " " + body).replace("\n", " ").strip()
        if not text:
            return {
                "probability": 0.0,
                "confidence_score": 0.0,
                "confidence_level": "LOW CONFIDENCE",
                "is_borderline": False,
                "assessment": "Empty content",
                "features_used": ["subject", "body"]
            }

        X = self.vectorizer.transform([text])
        prob = float(self.model.predict_proba(X)[0][1])  # Probability of class 1 (phishing)
        confidence_score = float(abs(prob - 0.5) * 2.0)

        if prob >= 0.80 or prob <= 0.20:
            confidence_level = "HIGH CONFIDENCE"
            is_borderline = False
        elif 0.38 <= prob <= 0.62:
            confidence_level = "BORDERLINE"
            is_borderline = True
        else:
            confidence_level = "LOW CONFIDENCE"
            is_borderline = False

        return {
            "probability": prob,
            "confidence_score": confidence_score,
            "confidence_level": confidence_level,
            "is_borderline": is_borderline,
            "assessment": "Phishing" if prob > 0.5 else "Safe",
            "features_used": ["subject", "body"]
        }
