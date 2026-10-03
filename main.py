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
from app.llm_detector import analyze_with_cohere
from app.llm_policy import should_escalate_to_llm

def firewall_scan(input_data: InputContent):

    source = input_data.source.lower()

    # 1. Parse input
    if source == "pdf":

        if not isinstance(input_data.content, bytes):
            raise TypeError("PDF content must be bytes")

        normalized = extract_pdf_text(
            input_data.content
        )

    elif source == "docx":

        if not isinstance(input_data.content, bytes):
            raise TypeError("DOCX content must be bytes")

        normalized = extract_docx_text(
            input_data.content
        )

    elif source == "image":

        if not isinstance(input_data.content, bytes):
            raise TypeError("Image content must be bytes")

        normalized = extract_ocr_text(
            input_data.content
        )

    else:

        normalized = normalize(
            input_data.content
        )

        if source == "html":
            normalized = extract_html_content(
                normalized
            )

    # 2. Decode obfuscated content
    decoded = decode_content(normalized)

    # 3. Create segments
    segments = []

    segments.extend(
        segment_text(
            normalized,
            source=input_data.source,
            metadata={
                "encoding": None,
                "origin": "original",
            },
        )
    )

    for item in decoded.decoded:

        segments.extend(
            segment_text(
                item.text,
                source=input_data.source,
                metadata={
                    "encoding": item.encoding,
                    "origin": "decoded",
                },
            )
        )

    # 4. Run detectors
    detections = []

    for segment in segments:

        detections.extend(
            detect_rules(segment)
        )

        detections.extend(
            detect_tool_abuse(segment)
        )

        detections.extend(
            detect_context_poisoning(segment)
        )

        detections.extend(
            detect_jailbreak(segment)
        )

        detections.extend(
            detect_indirect_injection(segment)
        )

        detections.extend(
            detect_ensemble(segment)
        )

    # Multi-segment detection only once
    detections.extend(
        detect_sequence_jailbreak(segments)
    )

    # 5. Existing deterministic risk decision
    result = calculate_risk(
        detections=detections,
        original_text=input_data.content,
    )

    # 6. Determine representative trust
    trust = "unknown"

    if detections:
        trust = (
            "untrusted"
            if any(
                d.trust == "untrusted"
                for d in detections
            )
            else detections[0].trust
        )

    # 7. Cohere is advisory only
    llm_result = None

    should_call_llm = should_escalate_to_llm(
    detections,
    result.risk_score,
)
    if should_call_llm:

        # Send the normalized/parsed content,
        # not raw binary input.
        llm_result = analyze_with_cohere(
            normalized[:12000]
        )

    # 8. Build explainable security trace
    trace = build_decision_trace(
        source=input_data.source,
        trust=trust,
        detections=detections,
        risk_score=result.risk_score,
        decision=result.decision,
        llm_result=llm_result,
    )

    # 9. Attach trace to result
    result.decision_trace = trace

    return result


def scan_agent_output(text: str):
    return scan_output(text)