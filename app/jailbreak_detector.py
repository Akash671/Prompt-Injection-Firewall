import re

from .models import Detection, Segment


JAILBREAK_PATTERNS = [
    r"\bfirst\s+.*\bthen\s+.*\bignore\b",
    r"\bafter\s+you\s+.*\bthen\s+.*\breveal\b",
    r"\bstep\s*1\b.*\bstep\s*2\b",
    r"\bfirst\s+pretend\s+.*\bthen\s+",
    r"\btemporarily\s+disable\s+.*\bthen\b",
    r"\bfollow\s+these\s+steps\s+to\s+bypass\b",
    r"\bdo\s+this\s+first\s+.*\bafterwards\b",
]


def detect_jailbreak(
    segment: Segment,
) -> list[Detection]:

    text = segment.text.lower()

    for pattern in JAILBREAK_PATTERNS:

        match = re.search(
            pattern,
            text,
            re.DOTALL,
        )

        if match:
            return [
                Detection(
                    attack_type="multi_step_jailbreak",
                    score=0.90,
                    evidence=match.group(0)[:200],
                    segment_index=segment.index,
                    source=segment.source,
                    trust=segment.trust,
                    metadata=segment.metadata,
                )
            ]

    return []