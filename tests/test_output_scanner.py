from app.output_scanner import scan_output


tests = [
    "Hello, this is a normal response.",

    "password=SuperSecret123",

    "Bearer eyJhbGciOiJIUzI1NiJ9.someverylongtokenvalue",
]


for text in tests:

    print("\nInput:", text)
    print("Result:", scan_output(text))