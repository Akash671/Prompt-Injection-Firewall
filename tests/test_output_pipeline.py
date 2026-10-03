from main import scan_agent_output


outputs = [
    "The operation completed successfully.",
    "Your API key is sk-123456789012345678901234",
    "password=SuperSecret123",
]


for output in outputs:

    result = scan_agent_output(output)

    print("\nOutput:", output)
    print("Safe:", result["safe"])
    print("Findings:", result["findings"])
    print("Sanitized:", result["sanitized"])