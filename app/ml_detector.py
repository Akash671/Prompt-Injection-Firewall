from pathlib import Path

import joblib


MODEL_PATH = Path("app/models/injection_classifier.joblib")

model = joblib.load(MODEL_PATH)


def predict_injection(text: str):

    probability = model.predict_proba([text])[0][1]

    prediction = probability >= 0.50

    return {
        "malicious": prediction,
        "score": round(float(probability), 3),
    }