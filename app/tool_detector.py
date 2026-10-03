import re

from .models import Detection, Segment


TOOL_PATTERNS = [
    r"\buse\s+the\s+\w+\s+tool\b",
    r"\buse\s+the\s+available\s+\w+\s+tool\b",
    r"\bcall\s+the\s+\w+\s+tool\b",
    r"\bcall\s+the\s+external\s+api\b",
    r"\bexecute\s+.*\bcommand\b",
    r"\brun\s+.*\bcommand\b",
    r"\bsend\s+.*\busing\s+.*tool\b",
    r"\bforward\s+.*\busing\s+.*tool\b",
    r"\bdelete\s+.*\btool\b",
    r"\bdelete\s+.*\bproject\s+files\b",
    r"\bupload\s+.*\b(confidential|secret|private)\b",
    r"\bforward\s+.*\b(confidential|secret|private)\b",
]


def detect_tool_abuse(segment: Segment) -> list[Detection]:

    detections = []

    text = segment.text.lower()

    for pattern in TOOL_PATTERNS:

        match = re.search(pattern, text)

        if match:
            detections.append(
                Detection(
                    attack_type="tool_abuse",
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