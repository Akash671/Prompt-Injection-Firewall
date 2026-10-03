from io import BytesIO

from pypdf import PdfReader


def extract_pdf_text(data: bytes) -> str:

    reader = PdfReader(
        BytesIO(data)
    )

    pages = []

    for page in reader.pages:

        text = page.extract_text()

        if text:
            pages.append(text)

    return "\n".join(pages)