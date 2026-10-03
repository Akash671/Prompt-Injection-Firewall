from app.tool_gateway import (
    ToolRequest,
    authorize_tool,
)


tests = [

    ToolRequest(
        tool_name="delete_files",
        arguments={},
        risk_score=0.90,
    ),

    ToolRequest(
        tool_name="send_email",
        arguments={
            "to": "external@example.com"
        },
        risk_score=0.70,
    ),

    ToolRequest(
        tool_name="search",
        arguments={
            "query": "3GPP specification"
        },
        risk_score=0.10,
    ),
]


for request in tests:

    print(
        request.tool_name,
        "->",
        authorize_tool(request),
    )