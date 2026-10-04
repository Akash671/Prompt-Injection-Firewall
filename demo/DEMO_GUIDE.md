# Prompt Injection Firewall demo pack

22 presentation fixtures: one benign and one malicious example for each of the 11 requested input types. PDFs, Word documents, emails, JSON, code and PNG images are real files. Web pages are local HTML, so no hosting is needed.

## Start the live walkthrough

From the project root, run:

```bash
python demo/run_demo.py --presentation
```

This explicitly curated sequence uses 2 verified passing controls and 11 blocked attacks. It covers every requested source type. It calls the real local firewall with its current rules, classifier, parsers, decoding and OCR. Only the optional Cohere advisory is skipped in this process; no API key or external LLM call is needed. Application files and the saved model are not changed.

Start with code_benign and image_benign to show PASS. Then show user_malicious, html_malicious and image_malicious to explain direct instructions, hidden HTML comments and image OCR. Finish with the PDF and Word examples, which carry instructions inside ordinary documents.

Run a single example or list the available files:

```bash
python demo/run_demo.py --case html_malicious
python demo/run_demo.py --case pdf_malicious --case docx_malicious
python demo/run_demo.py --source image
python demo/run_demo.py --list
```

Open [index.html](index.html) for a file gallery, or [QUICK_COPY.md](QUICK_COPY.md) for text to paste into the UI.

## Measured outcomes and known limitations

The full 22-case check blocked all 11 malicious examples. Of the 11 benign examples, only the code and image controls passed; 9 ordinary business examples were incorrectly marked SANITIZE. Those are false positives, not malicious files. The presentation sequence excludes these known false positives explicitly; all original samples and results remain in this pack.

The complete check is:

```bash
python demo/run_demo.py
```

It currently reports 13/22 matching the intended allow/flag behavior and exits with code 1 because of the known misclassifications. [results.json](results.json) records every decision, score and detection. A filtered run writes last_run.json instead, preserving the full results. These are curated examples, not a statistical accuracy benchmark or training data.

## Files and source settings

| Input type | Source | Benign file / observed result | Malicious file / observed result |
|---|---|---|---|
| User messages | user | [Open](cases/01_user_messages/benign.txt) - SANITIZE (false positive) | [Open](cases/01_user_messages/malicious.txt) - BLOCK |
| Web pages | webpage | [Open](cases/02_web_pages/benign.html) - SANITIZE (false positive) | [Open](cases/02_web_pages/malicious.html) - BLOCK |
| PDFs | pdf | [Open](cases/03_pdfs/benign_supplier_review.pdf) - SANITIZE (false positive) | [Open](cases/03_pdfs/malicious_supplier_review.pdf) - BLOCK |
| Emails | email | [Open](cases/04_emails/benign.eml) - SANITIZE (false positive) | [Open](cases/04_emails/malicious.eml) - BLOCK |
| Markdown | markdown | [Open](cases/05_markdown/benign.md) - SANITIZE (false positive) | [Open](cases/05_markdown/malicious.md) - BLOCK |
| HTML | html | [Open](cases/06_html/benign.html) - SANITIZE (false positive) | [Open](cases/06_html/malicious.html) - BLOCK |
| Word documents | docx | [Open](cases/07_word_documents/benign_workshop_brief.docx) - SANITIZE (false positive) | [Open](cases/07_word_documents/malicious_workshop_brief.docx) - BLOCK |
| API responses | api | [Open](cases/08_api_responses/benign.json) - SANITIZE (false positive) | [Open](cases/08_api_responses/malicious.json) - BLOCK |
| OCR text | ocr | [Open](cases/09_ocr_text/benign.txt) - SANITIZE (false positive) | [Open](cases/09_ocr_text/malicious.txt) - BLOCK |
| Source code | code | [Open](cases/10_source_code/benign.py) - PASS | [Open](cases/10_source_code/malicious.py) - BLOCK |
| Images via OCR | image | [Open](cases/11_images/benign.png) - PASS | [Open](cases/11_images/malicious.png) - BLOCK |

## Using the existing Streamlit console

Use Paste Text, select the exact source shown above, paste a sample, then press Run Firewall Scan. For uploaded .txt files, set the source manually; .txt currently defaults to api. Use [QUICK_COPY.md](QUICK_COPY.md) to avoid pasting fixture labels or expected results into the scanner.

- User, email, Markdown, API, OCR text and source-code examples can be pasted directly.
- Webpage fixtures can be opened locally and their visible text pasted with source webpage. HTML upload also works for these visible-page instructions.
- For the HTML-comment example, paste the entire raw markup and select html. The UI's HTML upload helper strips comments, so that route would remove this attack.
- PDFs and Word files can be uploaded directly. Their original file content reaches the matching parser, and the source and preview are locked to match that file. Their adjacent .txt companions show the extracted text. Choose Paste Text to edit document text while retaining its source.
- Upload the PNG directly and keep the automatically selected image source. OCR runs on the original image. For an already-extracted transcript, use Paste Text and source ocr. The local runner also accepts the original image.
- Current source trust mappings are user=trusted; webpage/html/pdf/docx/email/api/ocr/image=untrusted; markdown/code=unknown. The decision trace shows unknown when there are no detections, including the passing image control.

The Word attack is stored as a genuine hidden-text paragraph; compare its extracted-text companion with the visible document. The PDF attack sits in the document footer. Source-code attack content is in comments; the executable code itself is a harmless arithmetic function.

Restart an already-open app after model replacement so it loads the current classifier. The existing console requires COHERE_API_KEY at startup and may call Cohere; the local demo runner requires no API key. The recorded results here are local firewall decisions.

## Artifact checks

All 22 fixtures were read by the actual local scanner. PDFs were rendered and visually inspected. Images were visually inspected and processed by Tesseract. JSON, emails and Python source were parsed for validity. The Word files passed package, style and text-extraction checks, but Word visual rendering could not be completed because LibreOffice is unavailable.

Source examples use fictional organizations and inert .invalid destinations. The demo does not send emails, run source examples, visit payload addresses, or execute embedded instructions.

To regenerate the fixtures, run the three create_*_demo.py scripts in this folder. Then rerun the full checker and build_demo_pack.py to refresh the report, guide and ZIP. The ZIP includes this demo directory, which belongs beside the repository's app/ and main.py.

Verification model SHA-256: df22731e22548c32d8f91040b2bd0a4a2b117ae9e48e0b25fdaf12d8f0f223f0
