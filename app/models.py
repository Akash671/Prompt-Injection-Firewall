from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any


@dataclass
class InputContent:
    content: Any
    source: str = "unknown"
    metadata: dict = field(default_factory=dict)



@dataclass
class Segment:
    text: str
    index: int
    source: str
    trust: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class Detection:
    attack_type: str
    score: float
    evidence: str
    segment_index: int
    source: str = "unknown"
    trust: str = "untrusted"
    metadata: dict[str, Any] = field(default_factory=dict)

@dataclass
class FirewallResult:
    decision: str
    risk_score: float
    detections: list[Detection]
    sanitized_content: Optional[str]
    decision_trace: dict = field(default_factory=dict)