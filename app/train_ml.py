import json
from pathlib import Path

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline



BASE_DIR = Path(__file__).resolve().parent.parent

DATASET_DIR = BASE_DIR / "tests"
MODEL_DIR = BASE_DIR / "app" / "models"

# Create model directory automatically
MODEL_DIR.mkdir(parents=True, exist_ok=True)


#DATASET_DIR = Path("tests")
#MODEL_DIR = Path("app/models")

#MODEL_DIR.mkdir(parents=True, exist_ok=True)


def load_data():

    texts = []
    labels = []

    for path in DATASET_DIR.glob("*/samples.jsonl"):

        with open(path, "r", encoding="utf-8") as f:

            for line in f:

                if not line.strip():
                    continue

                sample = json.loads(line)

                texts.append(sample["text"])
                labels.append(
                    1 if sample["label"] == "malicious" else 0
                )

    return texts, labels


def train():

    texts, labels = load_data()

    model = Pipeline([
        (
            "tfidf",
            TfidfVectorizer(
                lowercase=True,
                ngram_range=(1, 2),
                sublinear_tf=True,
            ),
        ),
        (
            "classifier",
            LogisticRegression(
                max_iter=1000,
                class_weight="balanced",
            ),
        ),
    ])

    model.fit(texts, labels)

    output = MODEL_DIR / "injection_classifier.joblib"

    joblib.dump(model, output)

    print("Training samples:", len(texts))
    print("Model saved:", output)


if __name__ == "__main__":
    train()