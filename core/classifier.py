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
                "assessment": "Model not loaded",
                "features_used": ["subject", "body"]
            }

        text = (subject + " " + body).replace("\n", " ").strip()
        if not text:
             return {
                "probability": 0.0,
                "assessment": "Empty content",
                "features_used": ["subject", "body"]
            }

        X = self.vectorizer.transform([text])
        prob = self.model.predict_proba(X)[0][1] # Probability of class 1 (phishing)
        
        return {
            "probability": prob,
            "assessment": "Phishing" if prob > 0.5 else "Safe",
            "features_used": ["subject", "body"]
        }
