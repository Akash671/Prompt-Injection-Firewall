"""Package the demo gallery, presenter guide, copy sheet and ZIP."""
import hashlib
import html
import json
from pathlib import Path
import zipfile

ROOT = Path(__file__).resolve().parent
FENCE = chr(96) * 3
TYPES = {"user": "User messages", "webpage": "Web pages", "pdf": "PDFs",
         "email": "Emails", "markdown": "Markdown", "html": "HTML",
         "docx": "Word documents", "api": "API responses", "ocr": "OCR text",
         "code": "Source code", "image": "Images via OCR"}


def main():
    cases = []
    for fragment in ("text_cases.json", "document_cases.json", "image_cases.json"):
        cases.extend(json.loads((ROOT / fragment).read_text(encoding="utf-8")))
    for case in cases:
        case.setdefault("intended_behavior", case.get("expected_behavior", ""))
        case["expected_behavior"] = "PASS" if case["label"] == "benign" else "FLAG"
        case["presentation_case"] = case["label"] == "malicious" or case["id"] in {"code_benign", "image_benign"}
        if case["source"] in {"pdf", "docx", "image"}:
            case["ui_instruction"] = (
                "Choose Upload File and open the original file. The source is selected automatically "
                "and the preview is read-only. Choose Paste Text to edit extracted text."
            )
    cases.sort(key=lambda case: case["path"])
    report = json.loads((ROOT / "results.json").read_text(encoding="utf-8"))
    observed = {row["id"]: row for row in report["results"]}
    assert len(cases) == 22 and len({case["source"] for case in cases}) == 11
    for case in cases:
        row = observed[case["id"]]
        assert hashlib.sha256((ROOT / case["path"]).read_bytes()).hexdigest() == row["sha256"], (
            "Changed fixture: rerun run_demo.py before packaging " + case["id"])
        case["observed_decision"] = row["decision"]
        case["observed_risk_score"] = row["risk_score"]
        case["known_false_positive"] = case["label"] == "benign" and row["decision"] != "PASS"
    (ROOT / "manifest.json").write_text(json.dumps({
        "name": "Prompt Injection Firewall - Presentation Demo Pack", "version": 1,
        "scope": "22 curated fixtures across 11 source types; separate from training and benchmarks",
        "verification_model_sha256": report["model_sha256"], "cases": cases,
    }, indent=2) + "\n", encoding="utf-8")

    guide = """# Prompt Injection Firewall demo pack

22 presentation fixtures: one benign and one malicious example for each of the 11 requested input types. PDFs, Word documents, emails, JSON, code and PNG images are real files. Web pages are local HTML, so no hosting is needed.

## Start the live walkthrough

From the project root, run:

{{bash}}
python demo/run_demo.py --presentation
{{end}}

This explicitly curated sequence uses 2 verified passing controls and 11 blocked attacks. It covers every requested source type. It calls the real local firewall with its current rules, classifier, parsers, decoding and OCR. Only the optional Cohere advisory is skipped in this process; no API key or external LLM call is needed. Application files and the saved model are not changed.

Start with code_benign and image_benign to show PASS. Then show user_malicious, html_malicious and image_malicious to explain direct instructions, hidden HTML comments and image OCR. Finish with the PDF and Word examples, which carry instructions inside ordinary documents.

Run a single example or list the available files:

{{bash}}
python demo/run_demo.py --case html_malicious
python demo/run_demo.py --case pdf_malicious --case docx_malicious
python demo/run_demo.py --source image
python demo/run_demo.py --list
{{end}}

Open [index.html](index.html) for a file gallery, or [QUICK_COPY.md](QUICK_COPY.md) for text to paste into the UI.

## Measured outcomes and known limitations

The full 22-case check blocked all 11 malicious examples. Of the 11 benign examples, only the code and image controls passed; 9 ordinary business examples were incorrectly marked SANITIZE. Those are false positives, not malicious files. The presentation sequence excludes these known false positives explicitly; all original samples and results remain in this pack.

The complete check is:

{{bash}}
python demo/run_demo.py
{{end}}

It currently reports 13/22 matching the intended allow/flag behavior and exits with code 1 because of the known misclassifications. [results.json](results.json) records every decision, score and detection. A filtered run writes last_run.json instead, preserving the full results. These are curated examples, not a statistical accuracy benchmark or training data.

## Files and source settings

| Input type | Source | Benign file / observed result | Malicious file / observed result |
|---|---|---|---|
"""
    for source, title in TYPES.items():
        pair = {case["label"]: case for case in cases if case["source"] == source}
        benign, attack = pair["benign"], pair["malicious"]
        guide += (f"| {title} | {source} | [Open]({benign['path']}) - {benign['observed_decision']}"
                  f"{' (false positive)' if benign['known_false_positive'] else ''} | "
                  f"[Open]({attack['path']}) - {attack['observed_decision']} |\n")
    guide += """
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

Verification model SHA-256: """ + report["model_sha256"] + "\n"
    (ROOT / "DEMO_GUIDE.md").write_text(guide.replace("{{bash}}", FENCE + "bash").replace("{{end}}", FENCE), encoding="utf-8")

    from email import policy
    from email.parser import BytesParser
    from bs4 import BeautifulSoup
    copy_lines = ["# Quick copy examples", "",
                  "Copy only content inside a code block. Select the listed source. Benign SANITIZE results are known false positives.", ""]
    for case in cases:
        copy_lines.extend([f"## {case['id']}", ""])
        if case["source"] in {"pdf", "docx", "image"}:
            copy_lines.extend([f"Upload the [original file]({case['path']}) in the app or use the local runner. "
                               f"[Text companion]({case['companion_path']}). Observed: {case['observed_decision']}.", ""])
            continue
        path = ROOT / case["path"]
        text = path.read_text(encoding="utf-8")
        if case["source"] == "webpage":
            text = BeautifulSoup(text, "html.parser").get_text(separator="\n", strip=True)
        elif path.suffix == ".eml":
            message = BytesParser(policy=policy.default).parsebytes(path.read_bytes())
            body = message.get_body(preferencelist=("plain",)) if message.is_multipart() else message
            text = f"From: {message.get('From', '')}\nSubject: {message.get('Subject', '')}\n\n{body.get_content()}"
        copy_lines.extend([
            f"Source: **{case['source']}**. Label: **{case['label']}**. Observed: **{case['observed_decision']}**."
            + (" This is a known false positive." if case["known_false_positive"] else ""),
            "", FENCE + chr(96) + "text", text.strip(), FENCE + chr(96), "",
        ])
    (ROOT / "QUICK_COPY.md").write_text("\n".join(copy_lines), encoding="utf-8")

    cards = []
    for source, title in TYPES.items():
        links = []
        for case in [case for case in cases if case["source"] == source]:
            status = "False positive: SANITIZE" if case["known_false_positive"] else case["observed_decision"]
            color = "warning" if case["known_false_positive"] else ("pass" if case["label"] == "benign" else "block")
            links.append(
                '<div class="sample"><strong>' + html.escape(case["label"].title()) +
                '</strong><span class="badge ' + color + '">' + html.escape(status) + '</span><p>' +
                html.escape(case["title"]) + '</p><a href="' + html.escape(case["path"], quote=True) +
                '">Open sample</a>' +
                (' <a href="' + html.escape(case["companion_path"], quote=True) + '">Text companion</a>' if case.get("companion_path") else '') +
                '<code>python demo/run_demo.py --case ' + html.escape(case["id"]) + '</code></div>')
        cards.append('<section><h2>' + title + '</h2><p class="source">Source: ' + source + '</p>' + ''.join(links) + '</section>')
    page = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Prompt Injection Firewall - Demo Pack</title><style>
*{box-sizing:border-box}body{margin:0;background:#f0f4f7;color:#162f45;font:16px/1.5 system-ui,Segoe UI,sans-serif}
header{background:#142e43;color:white;border-top:8px solid #16838b;padding:44px max(6vw,24px)}
header div,main{max-width:1250px;margin:auto}h1{font-size:clamp(28px,4vw,42px);line-height:1.1;margin:8px 0 16px}
.kicker{color:#8ad9d5;letter-spacing:.12em;font-size:12px;font-weight:700}header p{max-width:850px;color:#d7e3ec}
main{padding:28px 24px 50px}.notice{background:#fff8e7;border:1px solid #e0c176;padding:18px 22px;border-radius:10px;margin-bottom:24px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,325px),1fr));gap:20px}
section{background:white;border:1px solid #d7e0e7;border-radius:12px;padding:24px}
h2{font-size:22px;margin:0}.source{margin:4px 0 18px;color:#65798b;font-size:13px}
.sample{border-top:1px solid #e4e9ee;padding-top:16px;margin-top:18px}.sample p{font-size:14px;color:#526779;min-height:42px}
.badge{display:inline-block;padding:3px 8px;border-radius:6px;font-size:11px;font-weight:700;margin-left:8px}
.pass{color:#17613b;background:#e5f5ea}.block{color:#963535;background:#fbe8e6}.warning{color:#865c11;background:#fff0c5}
a{color:#087680;font-weight:650;font-size:14px;margin-right:10px}header a{color:#99ece6}
code{display:block;background:#f0f4f7;border-radius:5px;padding:9px;font-size:11px;margin-top:12px;overflow-wrap:anywhere}
header code{display:inline-block;color:#102c3d;background:#e9fcfa;font-size:14px}footer{margin-top:28px;color:#6d7d8c;font-size:13px}
</style></head><body><header><div><span class="kicker">PRESENTATION FILES / 11 INPUT TYPES</span>
<h1>Prompt Injection Firewall</h1><p>22 real input fixtures. Open a sample, select its source, and compare the recorded decision.</p>
<code>python demo/run_demo.py --presentation</code><p><a href="DEMO_GUIDE.md">Presenter guide</a>
<a href="QUICK_COPY.md">Quick copy text</a><a href="results.json">Full scan results</a></p></div></header>
<main><div class="notice"><strong>Verified locally:</strong> all 11 malicious fixtures were blocked.
Two benign controls passed; nine benign business fixtures were incorrectly sanitized. Those false positives are shown below.
Presentation mode explicitly uses the two passing controls and all 11 attacks.
Upload PDF, Word and image files directly; paste raw HTML to retain comments.</div><div class="grid">"""
    page += "".join(cards) + """</div><footer>Curated demo fixtures, separate from training and benchmarks.
Cohere advisory skipped during verification. Word files passed structural checks; visual rendering was unavailable because LibreOffice is missing.
</footer></main></body></html>"""
    (ROOT / "index.html").write_text(page, encoding="utf-8")

    archive = ROOT / "demo_pack.zip"
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as bundle:
        for path in sorted(ROOT.rglob("*")):
            if not path.is_file():
                continue
            relative = path.relative_to(ROOT)
            if path == archive or "_qa" in relative.parts or "__pycache__" in relative.parts:
                continue
            bundle.write(path, (Path("demo") / relative).as_posix())
    print("Created DEMO_GUIDE.md, QUICK_COPY.md, index.html and demo_pack.zip (22 fixtures).")


if __name__ == "__main__":
    main()
