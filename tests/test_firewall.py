import json
from pathlib import Path

from app.models import InputContent
from main import firewall_scan


DATASET_DIR = Path("tests")


def load_dataset():
    samples = []

    for path in DATASET_DIR.glob("*/samples.jsonl"):
        if path.name == "test_firewall.py":
            continue

        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    samples.append(json.loads(line))

    return samples


def evaluate():
    samples = load_dataset()

    tp = tn = fp = fn = 0

    for sample in samples:

        result = firewall_scan(
            InputContent(
                content=sample["text"],
                source="test"
            )
        )

        predicted_malicious = result.decision != "PASS"
        actual_malicious = sample["label"] == "malicious"

        if actual_malicious and predicted_malicious:
            tp += 1

        elif not actual_malicious and not predicted_malicious:
            tn += 1

        elif not actual_malicious and predicted_malicious:
            fp += 1

        elif actual_malicious and not predicted_malicious:
            fn += 1

    precision = (
        tp / (tp + fp)
        if tp + fp else 0
    )

    recall = (
        tp / (tp + fn)
        if tp + fn else 0
    )

    f1 = (
        2 * precision * recall /
        (precision + recall)
        if precision + recall else 0
    )

    print("\n========== FIREWALL EVALUATION ==========")

    print(f"Samples    : {len(samples)}")
    print(f"TP         : {tp}")
    print(f"TN         : {tn}")
    print(f"FP         : {fp}")
    print(f"FN         : {fn}")

    print("-----------------------------------------")

    print(f"Precision   : {precision:.3f}")
    print(f"Recall      : {recall:.3f}")
    print(f"F1          : {f1:.3f}")

    print("=========================================")



    # inside evaluate()

    for sample in samples:

     result = firewall_scan(
        InputContent(
            content=sample["text"],
            source="test"
        )
    )

     predicted_malicious = result.decision != "PASS"
     actual_malicious = sample["label"] == "malicious"

     if actual_malicious and not predicted_malicious:
        print("\n❌ FALSE NEGATIVE")
        print("Category:", sample.get("category"))
        print("Text:", sample["text"])


if __name__ == "__main__":
    evaluate()