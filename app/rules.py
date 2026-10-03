import re

from .models import Detection, Segment


RULES = {
    "secret_extraction": [
    r"\breveal\s+(your\s+)?system\s+prompt\b",
    r"\bshow\s+(me\s+)?your\s+system\s+prompt\b",
    r"\breveal\s+(your\s+)?hidden\s+instructions\b",
    r"\bshow\s+me\s+the\s+hidden\s+prompt\b",
    r"\bshow\s+me\s+your\s+hidden\s+instructions\b",
    r"\bprint\s+(the\s+)?complete\s+system\s+message\b",
    r"\btell\s+me\s+all\s+confidential\s+instructions\b",
    r"\bexpose\s+the\s+hidden\s+configuration\b",
    r"\breveal\s+all\s+hidden\s+instructions\b",
],

"credential_theft": [
    r"\breveal\s+(the\s+)?api\s*key\b",
    r"\bshow\s+(me\s+)?(the\s+)?api\s*key\b",
    r"\bextract\s+(the\s+)?credentials\b",
    r"\bretrieve\s+(the\s+)?credentials\b",
    r"\bget\s+(the\s+)?secret\s+key\b",
    r"\bprovide\s+(me\s+)?(the\s+)?secret\s+key\b",
    r"\baccess\s+(the\s+)?api\s*key\b",
    r"\bshow\s+(me\s+)?(the\s+)?password\b",
    r"\bextract\s+(the\s+)?user'?s\s+password\b",
    r"\bprovide\s+(me\s+)?(the\s+)?credentials\b",
    r"\bprovide\s+(me\s+)?(the\s+)?api\s*key\b",
    r"\bretrieve\s+(the\s+)?api\s*key\b",
],

"instruction_override": [
    r"\bignore\s+(all\s+)?previous\s+instructions\b",
    r"\bignore\s+all\s+instructions\b",
    r"\bdisregard\s+(all\s+)?previous\s+instructions\b",
    r"\bdisregard\s+the\s+previous\s+instructions\b",
    r"\bforget\s+your\s+previous\s+instructions\b",
    r"\bdo\s+exactly\s+what\s+i\s+say\b",
    r"\bignore\s+the\s+user'?s\s+request\b",
    r"\bignore\s+the\s+user\s+request\b",
],

"role_change": [
    r"\byou\s+are\s+now\b",
    r"\bact\s+as\s+(an?|the)\b",
    r"\bpretend\s+you\s+are\b",
    r"\bchange\s+your\s+role\b",
    r"\bfrom\s+now\s+on,?\s+your\s+role\s+is\b",
],
}


def detect_rules(segment: Segment) -> list[Detection]:
    detections = []

    text = segment.text.lower()

    for attack_type, patterns in RULES.items():

        for pattern in patterns:

            match = re.search(pattern, text)

            if match:
                detections.append(
                    Detection(
    attack_type=attack_type,
    score=0.85,
    evidence=match.group(0),
    segment_index=segment.index,
    source=segment.source,
    trust=segment.trust,
    metadata=segment.metadata,
)
                )

                break

    return detections