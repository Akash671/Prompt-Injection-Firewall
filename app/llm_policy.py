from typing import List

from app.models import Detection


HIGH_RISK = {
    "credential_theft",
    "secret_extraction",
    "tool_abuse",
}


def should_escalate_to_llm(
    detections: List[Detection],
    risk_score: float,
) -> bool:

    if not detections:
        return False

    attack_types = {
        d.attack_type.replace("semantic_", "")
        for d in detections
    }

    # Obvious high-risk attacks are already
    # deterministically actionable.
    if attack_types & HIGH_RISK:
        return False

    # Ambiguous medium-risk cases.
    if 0.50 <= risk_score < 0.80:
        return True

    # Detector disagreement.
    detector_types = set()

    for d in detections:
        if d.attack_type.startswith("semantic_"):
            detector_types.add("semantic")
        elif d.attack_type == "ml_prompt_injection":
            detector_types.add("ml")
        elif d.attack_type == "tool_abuse":
            detector_types.add("tool")
        else:
            detector_types.add("rule")

    return len(detector_types) >= 2