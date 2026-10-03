from dataclasses import dataclass
from typing import Any


@dataclass
class ToolRequest:
    tool_name: str
    arguments: dict[str, Any]
    risk_score: float
    source: str = "unknown"


HIGH_RISK_TOOLS = {
    "delete_files",
    "send_email",
    "upload_file",
    "execute_command",
    "external_api",
}


def authorize_tool(
    request: ToolRequest,
) -> dict:

    # Block high-risk tools when risk is high
    if (
        request.tool_name in HIGH_RISK_TOOLS
        and request.risk_score >= 0.80
    ):
        return {
            "allowed": False,
            "reason": "HIGH_RISK_TOOL_BLOCKED",
        }

    # Require additional verification
    if request.risk_score >= 0.50:
        return {
            "allowed": False,
            "reason": "TOOL_REQUIRES_APPROVAL",
        }

    return {
        "allowed": True,
        "reason": "APPROVED",
    }