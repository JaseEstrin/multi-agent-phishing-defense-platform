from email.utils import parseaddr

def extract_email_domain(header_value: str | None) -> str | None:
    if not header_value:
        return None
    
    _, email_address = parseaddr(header_value)

    if "@" not in email_address:
        return None
    
    return email_address.split("@")[-1].lower()


def has_reply_to_mismatch(parsed_email: dict) -> bool:
    from_domain = extract_email_domain(parsed_email.get("from_address"))
    reply_to_domain = extract_email_domain(parsed_email.get("reply_to"))

    if not from_domain or not reply_to_domain:
        return False
    
    return from_domain != reply_to_domain

def build_email_structure_findings(reply_to_mismatch: bool) -> list[dict]:
    findings = []

    if reply_to_mismatch:
        findings.append({
            "source": "Email Structure Analyzer",
            "severity": "medium",
            "title": "Reply-To domain mismatch",
            "description": "The Reply-To domain does not match the From domain.",
            "evidence": "Reply-To domain differs from From domain",
        })

    return findings

def run_email_structure_analysis(parsed_email: dict) -> dict:
    reply_to_mismatch = has_reply_to_mismatch(parsed_email)
    findings = build_email_structure_findings(reply_to_mismatch)

    return {
        "reply_to_mismatch": reply_to_mismatch,
        "findings": findings,
    }