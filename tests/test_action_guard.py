from app.action_guard import (
    authorize_action,
    scan_tool_output,
)
from app.models import FirewallResult


blocked_result = FirewallResult(
    decision="BLOCK",
    risk_score=0.90,
    detections=[],
    sanitized_content=None,
)

safe_result = FirewallResult(
    decision="PASS",
    risk_score=0.10,
    detections=[],
    sanitized_content="safe",
)


print(
    authorize_action(
        blocked_result,
        "delete_files",
        {},
    )
)

print(
    authorize_action(
        safe_result,
        "search",
        {"query": "3GPP"},
    )
)


print("\nTool output:")
print(
    scan_tool_output(
        "Search completed successfully."
    )
)

print(
    scan_tool_output(
        "API key: sk-123456789012345678901234"
    )
)