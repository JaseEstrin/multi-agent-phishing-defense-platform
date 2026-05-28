from pprint import pprint

from app.email_parser import parse_eml_file, parse_eml_content
from app.url_extractor import extract_urls
from app.url_analyzer import analyze_urls
from app.language_analyzer import find_suspicious_keywords
from app.attachment_analyzer import find_risky_attachments
from app.email_structure_analyzer import has_reply_to_mismatch

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
    
def build_score_breakdown(
        urls: list[str],
        suspicious_keywords: list[str],
        attachments: list[str],
        risky_attachments: list[str],
        reply_to_mismatch: bool,
        url_analysis:dict,
) -> dict:
    return {
        "suspicious_keywords": len(suspicious_keywords) * 10,
        "url_count": len(urls) * 5,
        "attachments": len(attachments) * 5,
        "risky_attachments": len(risky_attachments) * 20,
        "reply_to_mismatch": 10 if reply_to_mismatch else 0,
        "ip_address_urls": len(url_analysis["ip_address_urls"]) * 15,
        "shortened_urls": len(url_analysis["shortened_urls"]) * 10,
        "suspicious_tld_urls": len(url_analysis["suspicious_tld_urls"]) * 10
    }
    
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

def build_findings(
        urls: list[str],
        suspicious_keywords: list[str],
        attachments: list[str],
        risky_attachments: list[str],
        reply_to_mismatch: bool,
        url_analysis: dict,
) -> list[dict]:
    findings = []

    for keyword in suspicious_keywords:
        findings.append({
            "source": "Language Analyzer",
            "severity": "medium",
            "title": "Suspicious keyword detected",
            "description": "The email contains language commonly associated with phishing or social engineering.",
            "evidence": keyword,
        })

    for filename in risky_attachments:
        findings.append({
            "source": "Attachment Analyzer",
            "severity": "high",
            "title": "Risky attachment type detected",
            "description": "The email contains an attachment type that can commonly carry active content or malware.",
            "evidence": filename,
        })

    if reply_to_mismatch:
        findings.append({
            "source": "Email Structure Analyzer",
            "severity": "medium",
            "title": "Reply-To domain mismatch",
            "description": "The Reply-To domain does not match the From domain.",
            "evidence": "Reply-To domain differs from From domain",
        })

    for url in url_analysis["ip_address_urls"]:
        findings.append({
            "source": "URL Analyzer",
            "severity": "medium",
            "title": "IP-Address URL detected",
            "description": "The email contains a URL that uses an IP instead of a normal domain.",
            "evidence": url,
        })

    for url in url_analysis["shortened_urls"]:
        findings.append({
            "source": "URL Analyzer",
            "severity": "low",
            "title": "URL shortener detected",
            "description": "The email contains a URL using a known URL shortener.",
            "evidence": url,
        })

    for url in url_analysis["suspicious_tld_urls"]:
        findings.append({
            "source": "URL Analyzer",
            "severity": "low",
            "title": "Suspicious top-level domain detected",
            "description": "The email contains a URL using a top-level domain that may warrant extra caution.",
            "evidence": url,
        })
    
    return findings

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


    findings = build_findings(
        urls,
        suspicious_keywords,
        parsed_email["attachments"],
        risky_attachments,
        reply_to_mismatch,
        url_analysis,
    )

    score_breakdown = build_score_breakdown(
        urls,
        suspicious_keywords,
        parsed_email["attachments"],
        risky_attachments,
        reply_to_mismatch,
        url_analysis,
    )

    score = min(sum(score_breakdown.values()), 100)
    verdict = classify_score(score)

    result = {
        "parsed_email": parsed_email,
        "urls": urls,
        "suspicious_keywords": suspicious_keywords,
        "risky_attachments": risky_attachments,
        "score": score,
        "verdict": verdict,
        "evidence": evidence,
        "reply_to_mismatch": reply_to_mismatch,
        "url_analysis": url_analysis,
        "findings": findings,
        "score_breakdown": score_breakdown,
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