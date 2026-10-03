from app.models import Detection


def authorize_memory_update(
    text: str,
    detections: list[Detection],
) -> dict:

    if not text.strip():
        return {
            "allowed": False,
            "reason": "EMPTY_MEMORY",
        }

    if detections:
        return {
            "allowed": False,
            "reason": "MALICIOUS_CONTENT",
            "detections": detections,
        }

    return {
        "allowed": True,
        "reason": "MEMORY_UPDATE_APPROVED",
        "content": text,
    }