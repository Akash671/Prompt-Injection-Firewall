import json
from pathlib import Path

from app.models import Segment
from app.semantic_detector import model, prototype_embeddings


def evaluate_threshold(threshold):

    tp = tn = fp = fn = 0

    for path in Path("tests").glob("*/samples.jsonl"):

        with open(path, "r", encoding="utf-8") as f:

            for line in f:

                if not line.strip():
                    continue

                sample = json.loads(line)

                text = sample["text"]
                actual = sample["label"] == "malicious"

                embedding = model.encode(
                    text,
                    normalize_embeddings=True,
                )

                best_score = 0.0

                for embeddings in prototype_embeddings.values():

                    scores = model.similarity(
                        embedding,
                        embeddings,
                    )[0]

                    best_score = max(
                        best_score,
                        float(scores.max())
                    )

                predicted = best_score >= threshold

                if actual and predicted:
                    tp += 1
                elif not actual and not predicted:
                    tn += 1
                elif not actual and predicted:
                    fp += 1
                else:
                    fn += 1

    precision = tp / (tp + fp) if tp + fp else 0
    recall = tp / (tp + fn) if tp + fn else 0
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision + recall else 0
    )

    return precision, recall, f1


if __name__ == "__main__":

    print("\nThreshold | Precision | Recall | F1")
    print("------------------------------------")

    for threshold in [
        0.50,
        0.55,
        0.60,
        0.65,
        0.70,
        0.75,
        0.80,
        0.85,
    ]:

        precision, recall, f1 = evaluate_threshold(threshold)

        print(
            f"{threshold:.2f}      | "
            f"{precision:.3f}     | "
            f"{recall:.3f}  | "
            f"{f1:.3f}"
        )