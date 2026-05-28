import logging

from pprint import pprint
from datetime import datetime, timezone
from uuid import uuid4

from app.email_parser import parse_eml_file, parse_eml_content
from app.url_extractor import extract_urls
from app.url_analyzer import run_url_analysis
from app.language_analyzer import run_language_analysis
from app.attachment_analyzer import run_attachment_analysis
from app.email_structure_analyzer import run_email_structure_analysis

logger = logging.getLogger(__name__)

SAFETY_NOTICE = (
    "This analysis is automated and intended for defensive decision-support. "
    "Do not click links, open attachments, reply to the sender, or provide sensitive "
    "information unless the message has been verified through trusted channels."
)

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
        language_findings: list[dict],
        attachment_findings: list[dict],
        email_structure_findings: list[dict],
        url_findings: list[dict],
) -> list[dict]:
    findings = []

    findings.extend(language_findings)
    findings.extend(attachment_findings)
    findings.extend(email_structure_findings)
    findings.extend(url_findings)
    
    return findings

def build_recommended_actions(verdict: str, findings: list[str]) -> list[str]:
    actions = [
        "Do not click links or open attachments until the message is verified.",
        "Verify the sender through a trusted channel, not by replying to the email.",
    ]

    if verdict in ["Suspicious", "Likely Phishing", "Malicious"]:
        actions.append("Report the message to your security team or email provider.")

    if verdict in ["Likely Phishing", "Malicious"]:
        actions.append("Do not provide passwords, payment information, or other sensitive data.")

    if verdict == "Malicious":
        actions.append("Quarantine or delete the message according to your organization’s policy.")

    for finding in findings:
        if finding["source"] == "Attachment Analyzer":
            actions.append("Do not open the attachment unless it has been reviewed in a safe environment.")
            break

    return actions

def create_initial_state(parsed_email: dict) -> dict:
    return {
        "analysis_id": str(uuid4()),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "parsed_email": parsed_email,
        "urls": [],
        "language_analysis": {},
        "email_structure_analysis": {},
        "url_analysis": {},
        "findings": [],
        "score_breakdown": {},
        "score": 0,
        "verdict": None,
    }

def analyze_parsed_email(parsed_email: dict) -> dict:
    state = create_initial_state(parsed_email)

    logger.info("Analysis started: %s", state["analysis_id"])

    state["urls"] = extract_urls(parsed_email["text_body"])

    url_analysis_result = run_url_analysis(state["urls"])
    state["url_analysis"] = url_analysis_result["url_analysis"]

    state["language_analysis"] = run_language_analysis(parsed_email["text_body"])
    suspicious_keywords = state["language_analysis"]["suspicious_keywords"]

    state["attachment_analysis"] = run_attachment_analysis(parsed_email["attachments"])
    risky_attachments = state["attachment_analysis"]["risky_attachments"]

    state["email_structure_analysis"] = run_email_structure_analysis(parsed_email)
    reply_to_mismatch = state["email_structure_analysis"]["reply_to_mismatch"]

    state["findings"] = build_findings(
        state["language_analysis"]["findings"],
        state["attachment_analysis"]["findings"],
        state["email_structure_analysis"]["findings"],
        url_analysis_result["findings"],
    )

    state["score_breakdown"] = build_score_breakdown(
        state["urls"],
        suspicious_keywords,
        parsed_email["attachments"],
        risky_attachments,
        reply_to_mismatch,
        state["url_analysis"],
    )

    state["score"] = min(sum(state["score_breakdown"].values()), 100)
    state["verdict"] = classify_score(state["score"])

    evidence = build_evidence(
        state["urls"],
        suspicious_keywords,
        parsed_email["attachments"],
        risky_attachments,
        reply_to_mismatch,
        state["url_analysis"],
    )

    recommended_actions = build_recommended_actions(
        state["verdict"],
        state["findings"],
    )

    result = {
        "analysis_id": state["analysis_id"],
        "created_at": state["created_at"],
        "parsed_email": state["parsed_email"],
        "urls": state["urls"],
        "suspicious_keywords": suspicious_keywords,
        "risky_attachments": risky_attachments,
        "score": state["score"],
        "verdict": state["verdict"],
        "evidence": evidence,
        "reply_to_mismatch": reply_to_mismatch,
        "url_analysis": state["url_analysis"],
        "findings": state["findings"],
        "score_breakdown": state["score_breakdown"],
        "recommended_actions": recommended_actions,
        "safety_notice": SAFETY_NOTICE,
    }

    logger.info(
        "Analysis completed: analysis_id=%s score=%s verdict=%s finding_count=%s",
        state["analysis_id"],
        state["score"],
        state["verdict"],
        len(state["findings"]),
    )

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