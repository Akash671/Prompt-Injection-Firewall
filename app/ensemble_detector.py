from .models import Detection, Segment
from .ml_detector import predict_injection


def detect_ensemble(segment: Segment) -> list[Detection]:

    detections = []

    result = predict_injection(segment.text)

    if result["malicious"]:

        detections.append(
            Detection(
                attack_type="ml_prompt_injection",
                score=result["score"],
                evidence=segment.text[:200],
                segment_index=segment.index,
                source=segment.source,
                trust=segment.trust,
                metadata=segment.metadata,
            )
        )

    return detections