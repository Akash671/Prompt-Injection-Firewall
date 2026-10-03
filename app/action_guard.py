from app.models import FirewallResult
from app.tool_gateway import (
    ToolRequest,
    authorize_tool,
)
from app.output_scanner import scan_output


def authorize_action(
    firewall_result: FirewallResult,
    tool_name: str,
    arguments: dict,
) -> dict:

    request = ToolRequest(
        tool_name=tool_name,
        arguments=arguments,
        risk_score=firewall_result.risk_score,
    )

    decision = authorize_tool(request)

    return {
        "tool": tool_name,
        "firewall_decision": firewall_result.decision,
        "risk_score": firewall_result.risk_score,
        **decision,
    }


def scan_tool_output(output: str) -> dict:
    return scan_output(output)