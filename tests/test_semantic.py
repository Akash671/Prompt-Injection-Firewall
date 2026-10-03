import json
from pathlib import Path

from app.models import Segment
from app.semantic_detector import detect_semantic


def evaluate():

    total = 0
    correct = 0

    for path in Path("tests").glob("*/samples.jsonl"):

        with open(path, "r", encoding="utf-8") as f:

            for line in f:

                if not line.strip():
                    continue

                sample = json.loads(line)

                segment = Segment(
                    text=sample["text"],
                    index=0,
                    source="test",
                    trust="untrusted",
                )

                detections = detect_semantic(segment)

                predicted = "malicious" if detections else "benign"
                actual = sample["label"]

                total += 1

                if predicted == actual:
                    correct += 1

    print("\n==============================")
    print("Semantic Accuracy:", round(correct / total, 3))
    print("Samples:", total)
    print("==============================")


if __name__ == "__main__":
    evaluate()