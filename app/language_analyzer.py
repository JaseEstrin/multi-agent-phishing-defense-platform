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

def build_language_findings(suspicious_keywords: list[str]) -> dict:
    findings = []

    for keyword in suspicious_keywords:
        findings.append({
            "source": "Language Analyzer",
            "severity": "medium",
            "title": "Suspicious keyword detected",
            "description": "The email contains language commonly associated with phishing or social engineering.",
            "evidence": keyword,
        })

    return findings