import subprocess
import sys

tests = [
    "test_firewall",
    "test_ensemble",
    "test_html_parser",
    "test_html_firewall",
    "test_indirect_detector",
    "test_memory_guard",
    "test_ml",
    "test_ocr_firewall",
    "test_output_pipeline",
    "test_output_scanner",
    "test_pdf_parser",
    "test_provenance",
    "test_semantic",
    "test_sequence_detector",
    "test_tool_gateway",
    "test_trust_boundary",
    "test_action_guard",
]

failed = []

for test in tests:
    print(f"\n{'=' * 60}")
    print(f"RUNNING: {test}")
    print("=" * 60)

    result = subprocess.run(
        [sys.executable, "-m", f"tests.{test}"]
    )

    if result.returncode != 0:
        failed.append(test)

print("\n" + "=" * 60)

if failed:
    print("FAILED:")
    for test in failed:
        print(f"  - {test}")
    sys.exit(1)

print("ALL TEST SCRIPTS PASSED")