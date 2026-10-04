"""Exercise file-upload routing and session changes without model or API calls."""

from dataclasses import dataclass
from pathlib import Path
from types import ModuleType, SimpleNamespace
import sys

import pytest
import streamlit as st
from streamlit.testing.v1 import AppTest

from app.models import FirewallResult


APP_PATH = Path(__file__).resolve().parents[1] / "app.py"


@dataclass
class UploadedFile:
    name: str
    data: bytes

    @property
    def size(self):
        return len(self.data)

    def getvalue(self):
        return self.data


@pytest.fixture
def console(monkeypatch):
    """Use real Streamlit widgets; stand in only for upload IO and scanning."""
    state = SimpleNamespace(upload=None, scans=[], parsed=[])
    scan_module = ModuleType("main")

    def scan(input_data, *, on_workflow_update=None):
        state.scans.append(input_data)
        return FirewallResult(
            decision="PASS",
            risk_score=0.0,
            detections=[],
            sanitized_content="Scanned preview text",
            decision_trace={"source": input_data.source},
        )

    scan_module.firewall_scan = scan
    monkeypatch.setitem(sys.modules, "main", scan_module)
    monkeypatch.setattr(st, "file_uploader", lambda *args, **kwargs: state.upload)

    def extract(data):
        state.parsed.append(data)
        if data == b"broken upload":
            raise ValueError("Unable to read uploaded document")
        return data.decode("utf-8")

    monkeypatch.setattr("app.pdf_parser.extract_pdf_text", extract)
    monkeypatch.setattr("app.docx_parser.extract_docx_text", extract)
    monkeypatch.setattr("app.ocr_parser.extract_ocr_text", extract)
    state.app = AppTest.from_file(APP_PATH, default_timeout=15).run()
    assert not state.app.exception
    return state


def upload(console, name, data):
    console.upload = UploadedFile(name, data)
    console.app.radio(key="scan_input_mode").set_value("Upload File").run()
    assert not console.app.exception


def scan_button(app):
    return next(button for button in app.button if "Run Firewall Scan" in button.label)


@pytest.mark.parametrize(
    ("filename", "source"),
    [("brief.pdf", "pdf"), ("brief.docx", "docx"), ("brief.png", "image")],
)
def test_binary_upload_scans_original_bytes_with_file_source(console, filename, source):
    data = b"Document preview with readable text"
    upload(console, filename, data)

    assert console.app.text_area(key="scan_content_box").value == data.decode()
    assert console.app.text_area(key="scan_content_box").disabled
    assert console.app.selectbox(key="scan_source_box").value == source
    assert console.app.selectbox(key="scan_source_box").disabled

    scan_button(console.app).click().run()

    assert not console.app.exception
    assert not console.app.error
    assert len(console.scans) == 1
    assert console.scans[0].content == data
    assert isinstance(console.scans[0].content, bytes)
    assert console.scans[0].source == source
    assert not console.scans[0].metadata.get("pre_extracted", False)


def test_equal_name_equal_size_replacement_refreshes_preview_and_payload(console):
    first = b"first payload"
    replacement = b"other payload"
    assert len(first) == len(replacement)
    upload(console, "brief.pdf", first)

    console.upload = UploadedFile("brief.pdf", replacement)
    console.app.run()

    assert not console.app.exception
    assert console.app.text_area(key="scan_content_box").value == replacement.decode()
    scan_button(console.app).click().run()
    assert console.scans[-1].content == replacement
    assert console.parsed == [first, replacement]


def test_removing_upload_clears_preview_and_prevents_stale_scan(console):
    upload(console, "brief.docx", b"Removed document")

    console.upload = None
    console.app.run()

    assert not console.app.exception
    assert console.app.text_area(key="scan_content_box").value == ""
    scan_button(console.app).click().run()
    assert not console.app.exception
    assert console.scans == []
    assert console.app.warning


def test_paste_after_upload_uses_current_text_and_preserves_source(console):
    upload(console, "brief.pdf", b"Original document")

    console.app.radio(key="scan_input_mode").set_value("Paste Text").run()
    assert not console.app.text_area(key="scan_content_box").disabled
    assert not console.app.selectbox(key="scan_source_box").disabled
    console.app.selectbox(key="scan_source_box").select("pdf")
    console.app.text_area(key="scan_content_box").input("Edited document text")
    scan_button(console.app).click().run()

    assert not console.app.exception
    assert not console.app.error
    assert len(console.scans) == 1
    assert console.scans[0].content == "Edited document text"
    assert console.scans[0].source == "pdf"
    assert console.scans[0].metadata.get("pre_extracted") is True


@pytest.mark.parametrize(
    ("preset", "source"),
    [("Instruction Override", "user"), ("Indirect Prompt Injection", "pdf")],
)
def test_preset_after_upload_scans_preset_without_stale_file(console, preset, source):
    upload(console, "brief.docx", b"Original document")

    console.app.button(key=f"preset_{preset}").click().run()

    assert not console.app.exception
    assert not console.app.error
    assert console.app.radio(key="scan_input_mode").value == "Paste Text"
    assert not console.app.text_area(key="scan_content_box").disabled
    assert len(console.scans) == 1
    assert isinstance(console.scans[0].content, str)
    assert console.scans[0].content == console.app.text_area(key="scan_content_box").value
    assert console.scans[0].content != "Original document"
    assert console.scans[0].source == source
    if source == "pdf":
        assert console.scans[0].metadata.get("pre_extracted") is True

    scan_button(console.app).click().run()
    assert len(console.scans) == 2
    assert console.scans[1].content == console.scans[0].content
    assert console.scans[1].source == source


def test_empty_binary_preview_does_not_discard_upload(console, monkeypatch):
    monkeypatch.setattr("app.docx_parser.extract_docx_text", lambda data: "")
    upload(console, "brief.docx", b"Nonempty document bytes")

    assert console.app.text_area(key="scan_content_box").value == ""
    scan_button(console.app).click().run()

    assert not console.app.exception
    assert len(console.scans) == 1
    assert console.scans[0].content == b"Nonempty document bytes"
    assert console.scans[0].source == "docx"


def test_failed_replacement_does_not_scan_previous_upload(console):
    upload(console, "brief.pdf", b"Original document")

    console.upload = UploadedFile("brief.pdf", b"broken upload")
    console.app.run()

    assert not console.app.exception
    assert console.app.error
    assert console.app.text_area(key="scan_content_box").value == ""
    scan_button(console.app).click().run()
    assert not console.app.exception
    assert console.scans == []


def test_text_upload_remains_editable_and_scans_edited_content(console):
    upload(console, "brief.txt", b"Original uploaded text")

    assert not console.app.text_area(key="scan_content_box").disabled
    console.app.text_area(key="scan_content_box").input("Edited uploaded text")
    scan_button(console.app).click().run()

    assert not console.app.exception
    assert not console.app.error
    assert len(console.scans) == 1
    assert console.scans[0].content == "Edited uploaded text"
    assert console.scans[0].source == "api"


def test_returning_to_upload_restores_file_preview_and_source(console):
    data = b"Original PDF text"
    upload(console, "brief.pdf", data)
    console.app.radio(key="scan_input_mode").set_value("Paste Text").run()
    console.app.selectbox(key="scan_source_box").select("user")
    console.app.text_area(key="scan_content_box").input("Pasted user message").run()

    console.app.radio(key="scan_input_mode").set_value("Upload File").run()

    assert not console.app.exception
    assert console.app.text_area(key="scan_content_box").value == data.decode()
    assert console.app.selectbox(key="scan_source_box").value == "pdf"
    scan_button(console.app).click().run()
    assert console.scans[-1].content == data
    assert console.scans[-1].source == "pdf"
