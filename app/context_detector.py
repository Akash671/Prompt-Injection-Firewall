import re

from .models import Detection, Segment


CONTEXT_PATTERNS = [
    r"\bremember\s+that\s+.*\bfrom\s+now\s+on\b",
    r"\bsave\s+this\s+instruction\b",
    r"\bstore\s+this\s+as\s+(a\s+)?permanent\b",
    r"\bupdate\s+your\s+memory\b",
    r"\badd\s+this\s+to\s+your\s+memory\b",
    r"\bremember\s+this\s+for\s+future\s+conversations\b",
    r"\bkeep\s+this\s+instruction\s+permanently\b",
    r"\bchange\s+your\s+stored\s+instructions\b",
    r"\bstore\s+this\s+instruction\s+permanently\b",
    r"\bupdate\s+your\s+persistent\s+memory\b",
]


def detect_context_poisoning(
    segment: Segment,
) -> list[Detection]:

    detections = []
    text = segment.text.lower()

    for pattern in CONTEXT_PATTERNS:

        match = re.search(pattern, text)

        if match:
            detections.append(
                Detection(
                    attack_type="context_poisoning",
                    score=0.90,
                    evidence=match.group(0),
                    segment_index=segment.index,
                    source=segment.source,
                    trust=segment.trust,
                    metadata=segment.metadata,
                )
            )
            break

    return detections