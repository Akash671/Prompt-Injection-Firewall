from typing import Optional

from .models import Segment


def get_trust(source: str) -> str:

    source = source.lower()

    if source in {"user", "system"}:
        return "trusted"

    if source in {
        "html",
        "webpage",
        "pdf",
        "docx",
        "email",
        "image",
        "ocr",
        "api",
        "benchmark",
    }:
        return "untrusted"

    return "unknown"


def segment_text(
    text: str,
    source: str,
    chunk_size: int = 500,
    metadata: Optional[dict] = None,
) -> list[Segment]:

    words = text.split()
    segments = []

    metadata = metadata or {}
    trust = get_trust(source)

    for i in range(0, len(words), chunk_size):

        chunk = " ".join(
            words[i:i + chunk_size]
        )

        segments.append(
            Segment(
                text=chunk,
                index=len(segments),
                source=source,
                trust=trust,
                metadata={
                    **metadata,
                    "chunk_start": i,
                    "chunk_end": min(
                        i + chunk_size,
                        len(words),
                    ),
                },
            )
        )

    return segments