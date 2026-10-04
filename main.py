from typing import Optional

from app.models import InputContent
from app.normalizer import normalize
from app.decoder import decode_content
from app.segmenter import segment_text
from app.rules import detect_rules
from app.risk_engine import calculate_risk
from app.tool_detector import detect_tool_abuse
from app.context_detector import detect_context_poisoning
from app.jailbreak_detector import detect_jailbreak
from app.ensemble_detector import detect_ensemble
from app.html_parser import extract_html_content
from app.pdf_parser import extract_pdf_text
from app.docx_parser import extract_docx_text
from app.ocr_parser import extract_ocr_text
from app.output_scanner import scan_output
from app.indirect_detector import detect_indirect_injection
from app.sequence_detector import detect_sequence_jailbreak
from app.decision_trace import build_decision_trace
from app.execution_trace import WorkflowCallback, WorkflowTrace
from app.llm_detector import analyze_with_cohere
from app.llm_policy import should_escalate_to_llm


def firewall_scan(
    input_data: InputContent,
    *,
    on_workflow_update: Optional[WorkflowCallback] = None,
):
    workflow = WorkflowTrace(on_workflow_update)

    # 1. Parse input. Text supplied explicitly by the UI's paste workflow
    # retains document provenance without being reparsed as a binary file.
    with workflow.step("parse", "Preparing input.") as stage:
        source = input_data.source.lower()
        if input_data.metadata.get("pre_extracted") is True:
            if not isinstance(input_data.content, str):
                raise TypeError("Pre-extracted content must be text")
            normalized = normalize(input_data.content)
            stage["detail"] = "Pre-extracted text normalization; source retained."
        elif source == "pdf":
            if not isinstance(input_data.content, bytes):
                raise TypeError("PDF content must be bytes")
            normalized = extract_pdf_text(input_data.content)
            stage["detail"] = "PDF extraction completed."
        elif source == "docx":
            if not isinstance(input_data.content, bytes):
                raise TypeError("DOCX content must be bytes")
            normalized = extract_docx_text(input_data.content)
            stage["detail"] = "DOCX extraction completed."
        elif source == "image":
            if not isinstance(input_data.content, bytes):
                raise TypeError("Image content must be bytes")
            normalized = extract_ocr_text(input_data.content)
            stage["detail"] = "Image OCR completed."
        else:
            normalized = normalize(input_data.content)
            if source == "html":
                normalized = extract_html_content(normalized)
                stage["detail"] = "Text normalization and HTML extraction completed."
            else:
                stage["detail"] = "Text normalization completed."

    # 2. Decode obfuscated content.
    with workflow.step("decode", "Checking supported encodings.") as stage:
        decoded = decode_content(normalized)
        stage["detail"] = (
            f"Checked Base64 and hexadecimal; found {len(decoded.decoded)} decoded payload(s)."
        )

    # 3. Create original and decoded segments with source/trust provenance.
    with workflow.step("segment", "Creating original and decoded segments.") as stage:
        segments = []
        segments.extend(
            segment_text(
                normalized,
                source=input_data.source,
                metadata={"encoding": None, "origin": "original"},
            )
        )
        for item in decoded.decoded:
            segments.extend(
                segment_text(
                    item.text,
                    source=input_data.source,
                    metadata={"encoding": item.encoding, "origin": "decoded"},
                )
            )
        stage["detail"] = f"Created {len(segments)} segment(s) with source and trust labels."

    # 4. Preserve the existing detector order within EACH segment. Workflow
    # entries aggregate all actual calls; they are not extra detector passes.
    detections = []
    detectors = (
        ("rules", detect_rules),
        ("tool", detect_tool_abuse),
        ("context", detect_context_poisoning),
        ("jailbreak", detect_jailbreak),
        ("indirect", detect_indirect_injection),
        ("ml", detect_ensemble),
    )
    if not segments:
        for stage_id, _ in detectors:
            workflow.skip(stage_id, "No segments to scan.")

    for segment_number, segment in enumerate(segments, start=1):
        for stage_id, detector in detectors:
            with workflow.step(
                stage_id, f"Checking segment {segment_number} of {len(segments)}."
            ) as stage:
                previous_count = len(detections)
                detections.extend(detector(segment))
                stage["detection_count"] += len(detections) - previous_count
                stage["detail"] = f"Checked {segment_number} of {len(segments)} segments."

    # Multi-segment detection still runs exactly once, including empty input.
    with workflow.step("sequence", "Checking patterns across segments.") as stage:
        previous_count = len(detections)
        detections.extend(detect_sequence_jailbreak(segments))
        stage["detection_count"] = len(detections) - previous_count
        stage["detail"] = f"Checked {len(segments)} segment(s) together."

    # 5. Existing deterministic risk decision and representative trust.
    with workflow.step("risk", "Applying risk thresholds and policy.") as stage:
        result = calculate_risk(
            detections=detections,
            original_text=(
                normalized if isinstance(input_data.content, bytes) else input_data.content
            ),
        )
        trust = "unknown"
        if detections:
            trust = (
                "untrusted"
                if any(d.trust == "untrusted" for d in detections)
                else detections[0].trust
            )
        stage["detail"] = f"Applied policy to {len(detections)} detector finding(s)."
        stage["decision"] = result.decision
        stage["risk_score"] = result.risk_score

    # 6. Cohere remains advisory only, using the unchanged escalation policy.
    llm_result = None
    with workflow.step(
        "llm", "Checking whether advisory review is needed.", count_attempt=False
    ) as stage:
        should_call_llm = should_escalate_to_llm(detections, result.risk_score)
        if should_call_llm:
            stage["attempts"] = 1
            # Send normalized/parsed text, never raw binary input.
            llm_result = analyze_with_cohere(normalized[:12000])
            if llm_result is None:
                stage["status"] = "skipped"
                stage["detail"] = "Advisory call returned no analysis; review unavailable."
            else:
                stage["detail"] = "Advisory review returned; policy decision unchanged."
        else:
            stage["status"] = "skipped"
            stage["detail"] = "Advisory review was not needed by the escalation policy."

    # 7. Attach both the existing explanation and the measured execution trace.
    with workflow.step("decision", "Assembling the security decision.") as stage:
        trace = build_decision_trace(
            source=input_data.source,
            trust=trust,
            detections=detections,
            risk_score=result.risk_score,
            decision=result.decision,
            llm_result=llm_result,
        )
        result.decision_trace = trace
        stage["detail"] = f"Final action: {result.decision}."
        stage["decision"] = result.decision
        stage["risk_score"] = result.risk_score
    result.decision_trace["workflow"] = workflow.snapshot()
    return result


def scan_agent_output(text: str):
    return scan_output(text)
