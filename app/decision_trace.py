from dataclasses import asdict
from typing import Any, Optional


def build_decision_trace(
    *,
    source: str,
    trust: str,
    detections: list,
    risk_score: float,
    decision: str,
    llm_result: Optional[dict] = None,
) -> dict[str, Any]:

    trace = {
        "source": source,
        "trust": trust,
        "detections": [
            {
                "attack_type": d.attack_type,
                "score": d.score,
                "evidence": d.evidence,
                "segment_index": d.segment_index,
                "source": d.source,
                "trust": d.trust,
            }
            for d in detections
        ],
        "risk_score": risk_score,
        "decision": decision,
    }

    if llm_result:
        trace["llm_analysis"] = {
            "provider": "cohere",
            "is_injection": llm_result.get("is_injection"),
            "attack_types": llm_result.get("attack_types", []),
            "confidence": llm_result.get("confidence", 0.0),
            "reason": llm_result.get("reason", ""),
            "recommended_action": llm_result.get(
                "recommended_action",
                "",
            ),
        }

    return trace