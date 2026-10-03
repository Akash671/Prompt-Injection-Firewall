from io import BytesIO

from PIL import Image
import pytesseract


pytesseract.pytesseract.tesseract_cmd = (
    r"C:\Program Files\Tesseract-OCR\tesseract.exe"
)


def extract_ocr_text(data: bytes) -> str:

    image = Image.open(
        BytesIO(data)
    )

    text = pytesseract.image_to_string(
        image
    )

    return text.strip()