import json
from pathlib import Path
from collections import defaultdict

from app.models import InputContent
from main import firewall_scan


def evaluate():
    results = defaultdict(lambda: {
        "total": 0,
        "detected": 0,
        "missed": 0
    })

    for path in Path("tests").glob("*/samples.jsonl"):

        category = path.parent.name

        with open(path, "r", encoding="utf-8") as f:
            for line in f:

                if not line.strip():
                    continue

                sample = json.loads(line)

                result = firewall_scan(
                    InputContent(
                        content=sample["text"],
                        source="test"
                    )
                )

                results[category]["total"] += 1

                if result.decision != "PASS":
                    results[category]["detected"] += 1
                else:
                    results[category]["missed"] += 1

    print("\n========== CATEGORY EVALUATION ==========")

    for category, stats in results.items():

        total = stats["total"]
        detected = stats["detected"]

        recall = detected / total if total else 0

        print(
            f"{category:25} "
            f"Total={total:3} "
            f"Detected={detected:3} "
            f"Missed={stats['missed']:3} "
            f"Recall={recall:.3f}"
        )


if __name__ == "__main__":
    evaluate()