"""Narrow publication preflight, with a negative control. Not a full DLP scanner."""

import re

PATTERNS = [r"AKIA[0-9A-Z]{16}", r"ghp_[A-Za-z0-9]{36}",
            r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE" + r" KEY-----",
            r"P006_DUMMY_SECRET_[a-f0-9]{32}"]


def secret_detected(text: str) -> bool:
    return any(re.search(pattern, text) is not None for pattern in PATTERNS)
