SUSPICIOUS_KEYWORDS = [
    "urgent",
    "verify",
    "password",
    "account suspended",
    "click here",
    "limited time",
    "immediately",
    "confirm your account",
    "payment failed",
    "invoice",
]


def find_suspicious_keywords(text: str) -> list[str]:
    lowered_text = text.lower()

    matches = []

    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in lowered_text:
            matches.append(keyword)

    return matches