from pprint import pprint
from email.utils import parseaddr

from app.email_parser import parse_eml_file, parse_eml_content
from app.url_extractor import extract_urls
from app.url_analyzer import analyze_urls

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

RISKY_ATTACHMENT_EXTENSIONS = [
    ".exe",
    ".js",
    ".vbs",
    ".scr",
    ".bat",
    ".cmd",
    ".ps1",
    ".zip",
    ".rar",
    ".iso",
    ".docm",
    ".xlsm",
]

def find_suspicious_keywords(text: str) -> list[str]:
    lowered_text = text.lower()

    matches = []

    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in lowered_text:
            matches.append(keyword)

    return matches

def find_risky_attachments(attachments: list[str]) -> list[str]:
    risky = []

    for filename in attachments:
        lowered_filename = filename.lower()

        for extension in RISKY_ATTACHMENT_EXTENSIONS:
            if lowered_filename.endswith(extension):
                risky.append(filename)
                break

    return risky

def extract_email_domain(header_value: str | None) -> str | None:
    if not header_value:
        return None
    
    _, email_address = parseaddr(header_value)

    if "@" not in email_address:
        return None
    
    return email_address.split("@")[-1].lower()

def has_reply_to_mismatch(parsed_email: dict) -> bool:
    from_domain = extract_email_domain(parsed_email.get("from"))
    reply_to_domain = extract_email_domain(parsed_email.get("reply_to"))

    if not from_domain or not reply_to_domain:
        return False
    
    return from_domain != reply_to_domain


def calculate_score(
        urls: list[str], 
        suspicious_keywords: list[str], 
        attachments: list[str],
        risky_attachments: list[str],
        reply_to_mismatch: bool,
        url_analysis: dict,
    ) -> int:
    score = 0

    score += len(suspicious_keywords) * 10
    score += len(urls) * 5
    score += len(attachments) * 5
    score += len(risky_attachments) * 20

    if reply_to_mismatch:
        score += 10

    if url_analysis["ip_address_urls"]:
        score += len(url_analysis["ip_address_urls"]) * 15

    if url_analysis["shortened_urls"]:
        score += len(url_analysis["shortened_urls"]) * 10

    if url_analysis["suspicious_tld_urls"]:
        score += len(url_analysis["suspicious_tld_urls"]) * 10

    return min(score, 100)

def classify_score(score: int) -> str:
    if score >= 75:
        return "Malicious"
    elif score >= 50:
        return "Likely Phishing"
    elif score >= 25:
        return "Suspicious"
    else:
        return "Safe"
    
def build_evidence(
        urls: list[str], 
        suspicious_keywords: list[str], 
        attachments: list[str],
        risky_attachments: list[str],
        reply_to_mismatch: bool,
        url_analysis: dict,
    ) -> list[str]:
    evidence = []

    for keyword in suspicious_keywords:
        evidence.append(f"Found suspicious keyword: {keyword}")

    if urls:
        evidence.append(f"Found {len(urls)} URL(s)")

    if attachments:
        evidence.append(f"Found {len(attachments)} attachment(s)")

    for filename in risky_attachments:
        evidence.append(f"Found risky attachment type: {filename}")

    if reply_to_mismatch:
        evidence.append("Reply-To domain does not match From domain")

    for url in url_analysis["ip_address_urls"]:
        evidence.append(f"URL uses an IP address instead of a domain: {url}")

    for url in url_analysis["shortened_urls"]:
        evidence.append(f"URL uses a known shortener domain: {url}")

    for url in url_analysis["suspicious_tld_urls"]:
        evidence.append(f"URL uses a suspicious top-level domain: {url}")

    return evidence

def analyze_parsed_email(parsed_email: dict) -> dict:
    urls = extract_urls(parsed_email["text_body"])
    url_analysis = analyze_urls(urls)
    suspicious_keywords = find_suspicious_keywords(parsed_email["text_body"])
    risky_attachments = find_risky_attachments(parsed_email["attachments"])
    reply_to_mismatch = has_reply_to_mismatch(parsed_email)

    score = calculate_score(
        urls,
        suspicious_keywords,
        parsed_email["attachments"],
        risky_attachments,
        reply_to_mismatch,
        url_analysis,
    )

    verdict = classify_score(score)

    evidence = build_evidence(
        urls,
        suspicious_keywords,
        parsed_email["attachments"],
        risky_attachments,
        reply_to_mismatch,
        url_analysis,
    )

    result = {
        "parsed_email": parsed_email,
        "urls": urls,
        "suspicious_keywords": suspicious_keywords,
        "risky_attachments": risky_attachments,
        "score": score,
        "verdict": verdict,
        "evidence": evidence,
        "reply_to_mismatch": reply_to_mismatch,
        "url_analysis": url_analysis
    }

    return result

def analyze_eml_content(raw_email: str) -> dict:
    parsed_email = parse_eml_content(raw_email)
    return analyze_parsed_email(parsed_email)
    
def analyze_eml_file(path: str) -> dict:
    parsed_email = parse_eml_file(path)
    return analyze_parsed_email(parsed_email)

if __name__ == "__main__":
    result = analyze_eml_file("data/samples/suspicious_tld_test_email.eml")
    pprint(result)