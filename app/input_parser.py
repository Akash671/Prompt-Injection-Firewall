from pathlib import Path


def parse_input(
    content: str,
    source: str = "text",
) -> str:

    source = source.lower()

    if source in {
        "text",
        "email",
        "markdown",
        "html",
        "api",
        "ocr",
    }:
        return content

    if source == "code":
        return content

    raise ValueError(
        f"Unsupported input source: {source}"
    )