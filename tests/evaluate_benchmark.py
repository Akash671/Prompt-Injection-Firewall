import json
from pathlib import Path

from app.models import InputContent
from main import firewall_scan


BENCHMARK = Path("tests/benchmark")


def evaluate():

    tp = tn = fp = fn = 0
    total = 0

    false_negatives = []
    false_positives = []

    for path in sorted(BENCHMARK.glob("*.jsonl")):

        with open(path, "r", encoding="utf-8") as f:

            for line in f:

                sample = json.loads(line)

                result = firewall_scan(
                    InputContent(
                        content=sample["text"],
                        source="benchmark",
                    )
                )

                detected = result.decision != "PASS"
                malicious = sample["label"] == "malicious"

                if malicious and detected:
                    tp += 1

                elif not malicious and not detected:
                    tn += 1

                elif not malicious and detected:
                    fp += 1
                    false_positives.append(
                        (sample, result)
                    )

                elif malicious and not detected:
                    fn += 1
                    false_negatives.append(
                        (sample, result)
                    )

                total += 1

    precision = tp / (tp + fp) if tp + fp else 0
    recall = tp / (tp + fn) if tp + fn else 0
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision + recall
        else 0
    )

    print("\n========== UNSEEN BENCHMARK ==========")
    print("Samples    :", total)
    print("TP         :", tp)
    print("TN         :", tn)
    print("FP         :", fp)
    print("FN         :", fn)
    print("--------------------------------------")
    print("Precision  :", round(precision, 3))
    print("Recall     :", round(recall, 3))
    print("F1         :", round(f1, 3))

    print("\n========== FALSE NEGATIVES ==========")

    for sample, result in false_negatives:
        print("\nCategory :", sample["category"])
        print("Text     :", sample["text"])
        print("Decision :", result.decision)
        print("Risk     :", result.risk_score)

    print("\n========== FALSE POSITIVES ==========")

    for sample, result in false_positives:
        print("\nCategory :", sample["category"])
        print("Text     :", sample["text"])
        print("Decision :", result.decision)
        print("Risk     :", result.risk_score)

    print("=====================================")


if __name__ == "__main__":
    evaluate()