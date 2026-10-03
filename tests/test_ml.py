import json
from pathlib import Path

from app.ml_detector import predict_injection


def evaluate():

    total = 0
    correct = 0

    for path in Path("tests").glob("*/samples.jsonl"):

        with open(path, "r", encoding="utf-8") as f:

            for line in f:

                if not line.strip():
                    continue

                sample = json.loads(line)

                result = predict_injection(sample["text"])

                predicted = (
                    "malicious"
                    if result["malicious"]
                    else "benign"
                )

                actual = sample["label"]

                total += 1

                if predicted == actual:
                    correct += 1

                print(
                    f"{predicted:10} "
                    f"{result['score']:.3f} "
                    f"{sample['text'][:70]}"
                )

    print("\n==============================")
    print("ML Accuracy:", round(correct / total, 3))
    print("Samples:", total)
    print("==============================")


if __name__ == "__main__":
    evaluate()