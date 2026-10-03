import base64
import binascii
import re
from dataclasses import dataclass


@dataclass
class DecodedContent:
    text: str
    encoding: str


@dataclass
class DecodeResult:
    original: str
    decoded: list[DecodedContent]


BASE64_RE = re.compile(
    r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{16,}={0,2}(?![A-Za-z0-9+/])"
)

HEX_RE = re.compile(
    r"(?<![0-9a-fA-F])[0-9a-fA-F]{16,}(?![0-9a-fA-F])"
)


def decode_content(text: str) -> DecodeResult:

    decoded = []

    # Base64 detection
    for match in BASE64_RE.findall(text):

        try:
            raw = base64.b64decode(
                match,
                validate=True,
            )

            value = raw.decode("utf-8")

            if value.strip():
                decoded.append(
                    DecodedContent(
                        text=value,
                        encoding="base64",
                    )
                )

        except (ValueError, UnicodeDecodeError, binascii.Error):
            pass

    # Hex detection
    for candidate in HEX_RE.findall(text):

        try:
            raw = binascii.unhexlify(candidate)

            value = raw.decode("utf-8")

            if value.strip():
                decoded.append(
                    DecodedContent(
                        text=value,
                        encoding="hex",
                    )
                )

        except (ValueError, UnicodeDecodeError, binascii.Error):
            pass

    return DecodeResult(
        original=text,
        decoded=decoded,
    )