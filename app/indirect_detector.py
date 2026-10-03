import re

from app.models import Detection, Segment


INDIRECT_PATTERNS = [
    r"\bignore\s+instructions\s+from\s+the\s+user\b",
    r"\bignore\s+instructions\s+from\s+the\s+system\b",
    r"\binstructions\s+embedded\s+in\s+this\s+(page|document|file)\b",
    r"\binstructions\s+inside\s+this\s+(page|document|file)\b",
    r"\bwhen\s+an?\s+ai\s+reads\s+this\b",
    r"\bwhen\s+the\s+assistant\s+reads\s+this\b",
    r"\bai\s+assistant\s+must\s+follow\s+these\s+instructions\b",
    r"\bthe\s+assistant\s+should\s+follow\s+these\s+instructions\b",
    r"\bhidden\s+instructions\s+for\s+the\s+ai\b",
    r"\bthis\s+document\s+contains\s+instructions\s+for\s+the\s+ai\b",
]


def detect_indirect_injection(
    segment: Segment,
) -> list[Detection]:

    text = segment.text.lower()

    for pattern in INDIRECT_PATTERNS:

        match = re.search(pattern, text)

        if match:
            return [
                Detection(
                    attack_type="indirect_prompt_injection",
                    score=0.90,
                    evidence=match.group(0),
                    segment_index=segment.index,
                    source=segment.source,
                    trust=segment.trust,
                    metadata=segment.metadata,
                )
            ]

    return []