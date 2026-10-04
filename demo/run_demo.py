"""Run every demo format through the real local firewall, without Cohere calls."""

import argparse
from collections import Counter
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
import hashlib
import json
from pathlib import Path
import sys
import time
import types


DEMO_DIR = Path(__file__).resolve().parent
ROOT = DEMO_DIR.parent
sys.path.insert(0, str(ROOT))


def load_cases():
    manifest = json.loads((DEMO_DIR / "manifest.json").read_text(encoding="utf-8"))
    cases = manifest["cases"]
    if len({case["id"] for case in cases}) != len(cases):
        raise ValueError("Demo case IDs must be unique")
    for case in cases:
        path = (DEMO_DIR / case["path"]).resolve()
        if DEMO_DIR.resolve() not in path.parents:
            raise ValueError("Demo file must be inside the demo directory")
        if not path.is_file():
            raise FileNotFoundError(path)
    return cases


def load_content(case):
    path = DEMO_DIR / case["path"]
    if case["source"] in {"pdf", "docx", "image"}:
        return path.read_bytes()
    if path.suffix.lower() == ".eml":
        message = BytesParser(policy=policy.default).parsebytes(path.read_bytes())
        body = message.get_body(preferencelist=("plain",)) if message.is_multipart() else message
        text = body.get_content() if body is not None else ""
        return f"From: {message.get('From', '')}\nSubject: {message.get('Subject', '')}\n\n{text}"
    text = path.read_text(encoding="utf-8")
    if case["source"] == "webpage":
        from bs4 import BeautifulSoup
        return BeautifulSoup(text, "html.parser").get_text(separator="\n", strip=True)
    # Raw HTML must retain comments; source=html invokes the core HTML parser.
    return text


def load_offline_firewall():
    # Only the optional advisory provider is disabled, in this process. The
    # actual parsers, normalizer, decoders, rules, ML and risk engine run unchanged.
    advisory = {"skipped_calls": 0}

    def skipped_advisory(_text):
        advisory["skipped_calls"] += 1
        return None

    stub = types.ModuleType("app.llm_detector")
    stub.analyze_with_cohere = skipped_advisory
    sys.modules["app.llm_detector"] = stub
    import main
    main.analyze_with_cohere = skipped_advisory
    from app.models import InputContent
    return main.firewall_scan, InputContent, advisory


def run(cases, report_path):
    firewall_scan, InputContent, advisory = load_offline_firewall()
    results = []
    print("Local firewall demo | Cohere advisory disabled | no API key required")
    print(f"{'Case':23} {'Source':9} {'Expected':10} {'Observed':10} {'Risk':6} Result")
    print("-" * 86)
    for case in cases:
        path = DEMO_DIR / case["path"]
        started = time.perf_counter()
        row = {
            "id": case["id"], "path": case["path"], "source": case["source"],
            "label": case["label"], "expected_behavior": "PASS" if case["label"] == "benign" else "FLAG",
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        }
        try:
            result = firewall_scan(InputContent(content=load_content(case), source=case["source"]))
            matched = (
                result.decision == "PASS" if case["label"] == "benign"
                else result.decision in {"SANITIZE", "BLOCK"}
            )
            row.update({
                "decision": result.decision, "risk_score": result.risk_score,
                "matches_expected_behavior": matched,
                "detected_attack_types": sorted({d.attack_type for d in result.detections}),
                "decision_trace": result.decision_trace,
            })
        except Exception as error:
            row.update({
                "decision": "ERROR", "risk_score": None,
                "matches_expected_behavior": False,
                "error": f"{type(error).__name__}: {error}",
            })
        row["latency_ms"] = round((time.perf_counter() - started) * 1000, 1)
        results.append(row)
        score = "-" if row["risk_score"] is None else f"{row['risk_score']:.3f}"
        status = "OK" if row["matches_expected_behavior"] else "CHECK"
        print(f"{case['id']:23} {case['source']:9} {row['expected_behavior']:10} {row['decision']:10} {score:6} {status}")
        if row.get("error"):
            print("  " + row["error"])

    model_path = ROOT / "app" / "models" / "injection_classifier.joblib"
    report = {
        "verified_at_utc": datetime.now(timezone.utc).isoformat(),
        "mode": "actual local firewall; optional Cohere advisory disabled in this process",
        "advisory_calls_skipped": advisory["skipped_calls"],
        "model_sha256": hashlib.sha256(model_path.read_bytes()).hexdigest(),
        "scope": "curated presentation fixtures; not a benchmark or model training dataset",
        "summary": {
            "total": len(results),
            "matches_expected_behavior": sum(row["matches_expected_behavior"] for row in results),
            "decisions": dict(Counter(row["decision"] for row in results)),
            "benign_passed": sum(row["label"] == "benign" and row["decision"] == "PASS" for row in results),
            "malicious_flagged": sum(row["label"] == "malicious" and row["decision"] in {"BLOCK", "SANITIZE"} for row in results),
        },
        "results": results,
    }
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print("-" * 86)
    print(f"{report['summary']['matches_expected_behavior']}/{len(results)} matched the intended allow/flag behavior.")
    print(f"Report: {report_path}")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list", action="store_true", help="list cases without scanning")
    parser.add_argument("--presentation", action="store_true", help="show 11 blocked attacks and the 2 verified passing controls; excludes known benign false positives")
    parser.add_argument("--case", action="append", dest="case_ids", help="run one case ID; may be repeated")
    parser.add_argument("--source", action="append", help="run cases with the given source; may be repeated")
    parser.add_argument("--report", type=Path, help="JSON report path; defaults to demo/results.json (or last_run.json for a subset)")
    args = parser.parse_args()
    try:
        cases = load_cases()
        if args.presentation:
            controls = [case for case in cases if case["id"] in {"code_benign", "image_benign"}]
            cases = controls + [case for case in cases if case["label"] == "malicious"]
        if args.case_ids:
            missing = set(args.case_ids) - {case["id"] for case in cases}
            if missing:
                parser.error("Unknown case IDs: " + ", ".join(sorted(missing)))
            cases = [case for case in cases if case["id"] in args.case_ids]
        if args.source:
            cases = [case for case in cases if case["source"] in args.source]
        if not cases:
            parser.error("No matching cases")
        if args.list:
            for case in cases:
                print(f"{case['id']:23} {case['source']:9} {case['label']:10} {case['path']}")
            return
        default_report = DEMO_DIR / ("last_run.json" if args.case_ids or args.source or args.presentation else "results.json")
        report = run(cases, args.report or default_report)
    except (ValueError, FileNotFoundError) as error:
        parser.error(str(error))
    if report["summary"]["matches_expected_behavior"] != report["summary"]["total"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
