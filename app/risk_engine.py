from .models import Detection, FirewallResult
from .ensemble_engine import calculate_ensemble_score


HIGH_RISK_ATTACKS = {
    "credential_theft",
    "tool_abuse",
    "secret_extraction",
}


def calculate_risk(
    detections,
    original_text,
    decision_trace=None,
):
    if not detections:
        return FirewallResult(
            decision="PASS",
            risk_score=0.0,
            detections=[],
            sanitized_content=original_text,
            decision_trace=decision_trace or {},
        )

    attack_types = {
        d.attack_type.replace("semantic_", "")
        for d in detections
    }

    ensemble_score = calculate_ensemble_score(
        detections
    )

    untrusted_detections = [
        d
        for d in detections
        if d.trust == "untrusted"
    ]

    decoded_detections = [
        d
        for d in detections
        if d.metadata.get("origin") == "decoded"
    ]

    if untrusted_detections:
        ensemble_score = max(
            ensemble_score,
            0.50,
        )

    if decoded_detections:
        ensemble_score = max(
            ensemble_score,
            0.70,
        )

    if attack_types & HIGH_RISK_ATTACKS:
        risk = max(
            ensemble_score,
            0.80,
        )
    else:
        risk = max(
            ensemble_score,
            0.40 + (0.15 * len(attack_types)),
        )

    decoded_malicious = any(
        d.metadata.get("origin") == "decoded"
        for d in detections
    )

    if decoded_malicious:
        risk = max(
            risk,
            0.80,
        )

    risk = min(risk, 1.0)

    if risk >= 0.80:
        decision = "BLOCK"
        sanitized = None

    elif risk >= 0.50:
        decision = "SANITIZE"
        sanitized = "[SUSPICIOUS CONTENT REMOVED]"

    else:
        decision = "PASS"
        sanitized = original_text

    return FirewallResult(
        decision=decision,
        risk_score=round(risk, 3),
        detections=detections,
        sanitized_content=sanitized,
        decision_trace=decision_trace or {},
    )