from app.pdf_parser import extract_pdf_text


with open(
    "tests/sample.pdf",
    "rb",
) as f:

    data = f.read()


text = extract_pdf_text(data)

print(text)