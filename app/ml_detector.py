from pathlib import Path
import joblib

BASE_DIR = Path(__file__).resolve().parent.parent
MODEL_PATH = BASE_DIR / "app" / "models" / "injection_classifier.joblib"


def ensure_model():
    if MODEL_PATH.exists():
        return

    print("ML model not found. Training model...")
    
    from app.train_ml import train
    train()

    if not MODEL_PATH.exists():
        raise FileNotFoundError(
            f"Model training completed but model was not created: {MODEL_PATH}"
        )


ensure_model()

model = joblib.load(MODEL_PATH)


def predict_injection(text: str):
    probability = model.predict_proba([text])[0][1]
    prediction = probability >= 0.5

    return {
        "malicious": prediction,
        "score": round(float(probability), 3),
    }