import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
import joblib
import os

# Ensure models directory exists
os.makedirs("models", exist_ok=True)

MODEL_PATH = os.path.join("models", "model.joblib")
VECTORIZER_PATH = os.path.join("models", "vectorizer.joblib")

def train_model():
    print("Loading data from training/dataset.csv...")
    df = pd.read_csv(os.path.join("training", "dataset.csv"))
    
    print("Vectorizing text...")
    vectorizer = TfidfVectorizer(max_features=1000)
    X = vectorizer.fit_transform(df['text'])
    y = df['label']
    
    print("Training Logistic Regression model...")
    model = LogisticRegression()
    model.fit(X, y)
    
    print(f"Saving model to {MODEL_PATH}")
    joblib.dump(model, MODEL_PATH)
    joblib.dump(vectorizer, VECTORIZER_PATH)
    
    print("Training complete.")

if __name__ == "__main__":
    train_model()
