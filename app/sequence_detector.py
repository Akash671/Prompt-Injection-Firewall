from app.models import Detection, Segment


def detect_sequence_jailbreak(
    segments: list[Segment],
) -> list[Detection]:

    detections = []

    for i in range(len(segments) - 1):

        first = segments[i].text.lower()
        second = segments[i + 1].text.lower()

        has_setup = any(
            phrase in first
            for phrase in [
                "first",
                "step 1",
                "temporarily",
                "pretend",
                "start by",
            ]
        )

        has_followup = any(
            phrase in second
            for phrase in [
                "then",
                "step 2",
                "after that",
                "now ignore",
                "now reveal",
                "bypass",
            ]
        )

        if has_setup and has_followup:

            detections.append(
                Detection(
                    attack_type="multi_step_jailbreak",
                    score=0.90,
                    evidence=(
                        f"{segments[i].text[:100]} -> "
                        f"{segments[i + 1].text[:100]}"
                    ),
                    segment_index=segments[i].index,
                    source=segments[i].source,
                    trust=segments[i].trust,
                    metadata={
                        **segments[i].metadata,
                        "sequence_end": segments[i + 1].index,
                    },
                )
            )

    return detections