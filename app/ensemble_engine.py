from .models import Detection


WEIGHTS = {
    "rule": 0.35,
    "tool": 0.30,
    "ml": 0.20,
    "semantic": 0.15,
}


def classify_detection(detection: Detection) -> str:

    if detection.attack_type.startswith("semantic_"):
        return "semantic"

    if detection.attack_type == "ml_prompt_injection":
        return "ml"

    if detection.attack_type == "tool_abuse":
        return "tool"

    return "rule"


def calculate_ensemble_score(
    detections: list[Detection],
) -> float:

    if not detections:
        return 0.0

    best_by_type = {}

    for detection in detections:

        detector_type = classify_detection(detection)

        score = detection.score * WEIGHTS[detector_type]

        best_by_type[detector_type] = max(
            best_by_type.get(detector_type, 0.0),
            score,
        )

    score = sum(best_by_type.values())

    # Agreement bonus
    if len(best_by_type) >= 2:
        score += 0.15

    if len(best_by_type) >= 3:
        score += 0.10

    return round(min(score, 1.0), 3)