import html
import re
import unicodedata


def normalize(text: str) -> str:
    # Unicode normalization
    text = unicodedata.normalize("NFKC", text)

    # HTML entities
    text = html.unescape(text)

    # Remove zero-width characters
    text = re.sub(r"[\u200B-\u200D\uFEFF]", "", text)

    # Normalize whitespace
    text = re.sub(r"\s+", " ", text)

    return text.strip()