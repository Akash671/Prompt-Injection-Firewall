from app.segmenter import segment_text


tests = [
    ("user", "User content"),
    ("html", "Webpage content"),
    ("pdf", "PDF content"),
    ("email", "Email content"),
    ("api", "API response"),
]


for source, text in tests:

    segment = segment_text(
        text,
        source=source,
    )[0]

    print(
        source,
        "->",
        segment.trust,
    )