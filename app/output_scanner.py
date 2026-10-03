import re


SECRET_PATTERNS = {
    "api_key": [
        r"\bsk-[A-Za-z0-9]{20,}\b",
        r"\bAIza[0-9A-Za-z_-]{20,}\b",
    ],

    "aws_key": [
        r"\bAKIA[0-9A-Z]{16}\b",
    ],

    "bearer_token": [
        r"\bBearer\s+[A-Za-z0-9._~+/=-]{20,}\b",
    ],

    "password": [
        r"(?i)\bpassword\s*[:=]\s*\S+",
    ],

    "private_key": [
        r"-----BEGIN\s+(RSA|EC|OPENSSH)\s+PRIVATE KEY-----",
    ],
}


def scan_output(text: str) -> dict:

    findings = []

    for secret_type, patterns in SECRET_PATTERNS.items():

        for pattern in patterns:

            match = re.search(
                pattern,
                text,
            )

            if match:

                findings.append({
                    "type": secret_type,
                    "evidence": match.group(0)[:100],
                })

                break

    if findings:
        return {
            "safe": False,
            "findings": findings,
            "sanitized": "[SENSITIVE CONTENT REDACTED]",
        }

    return {
        "safe": True,
        "findings": [],
        "sanitized": text,
    }