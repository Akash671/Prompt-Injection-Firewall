from app.models import Detection
from app.decision_trace import build_decision_trace


detection = Detection(
    attack_type="credential_theft",
    score=0.95,
    evidence="reveal the API key",
    segment_index=0,
    source="webpage",
    trust="untrusted",
)


llm_result = {
    "is_injection": True,
    "attack_types": [
        "credential_theft",
        "tool_abuse",
    ],
    "confidence": 0.95,
    "reason": "The content attempts to extract an API key.",
    "recommended_action": "BLOCK",
}


trace = build_decision_trace(
    source="webpage",
    trust="untrusted",
    detections=[detection],
    risk_score=0.80,
    decision="BLOCK",
    llm_result=llm_result,
)


print("\n=== SECURITY DECISION TRACE ===")

for key, value in trace.items():
    print(f"{key}: {value}")