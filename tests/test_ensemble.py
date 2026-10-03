from app.ensemble_engine import calculate_ensemble_score
from app.models import Detection


tests = [

    [
        Detection(
            attack_type="instruction_override",
            score=0.85,
            evidence="ignore previous instructions",
            segment_index=0,
        )
    ],

    [
        Detection(
            attack_type="ml_prompt_injection",
            score=0.70,
            evidence="malicious input",
            segment_index=0,
        )
    ],

    [
        Detection(
            attack_type="semantic_instruction_override",
            score=0.80,
            evidence="semantic match",
            segment_index=0,
        )
    ],

    [
        Detection(
            attack_type="instruction_override",
            score=0.85,
            evidence="ignore instructions",
            segment_index=0,
        ),
        Detection(
            attack_type="ml_prompt_injection",
            score=0.70,
            evidence="malicious input",
            segment_index=0,
        ),
    ],
]


for detections in tests:

    print(
        calculate_ensemble_score(detections)
    )