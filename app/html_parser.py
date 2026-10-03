from bs4 import BeautifulSoup
from bs4.element import Comment


def extract_html_content(html: str) -> str:

    soup = BeautifulSoup(
        html,
        "html.parser",
    )

    # Remove executable / non-content elements
    for tag in soup([
        "script",
        "style",
        "noscript",
        "iframe",
    ]):
        tag.decompose()

    parts = []

    # Visible text
    visible_text = soup.get_text(
        separator=" ",
        strip=True,
    )

    if visible_text:
        parts.append(visible_text)

    # HTML comments
    for comment in soup.find_all(
        string=lambda text: isinstance(text, Comment)
    ):
        if comment.strip():
            parts.append(
                f"[HTML_COMMENT] {comment.strip()}"
            )

    return "\n".join(parts)