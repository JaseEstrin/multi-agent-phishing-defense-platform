from app.email_structure_analyzer import (
    extract_email_domain,
    has_reply_to_mismatch,
    build_email_structure_findings,
)


def test_extract_email_domain():
    header = "Billing Notices <billing@example.com>"

    assert extract_email_domain(header) == "example.com"


def test_has_reply_to_mismatch_detects_different_domain():
    parsed_email = {
        "from_address": "Billing Notices <billing@example.com>",
        "reply_to": "Support <support@example.net>",
    }

    assert has_reply_to_mismatch(parsed_email) is True

def test_build_email_structure_findings_for_reply_to_mismatch():
    findings = build_email_structure_findings(reply_to_mismatch=True)

    assert len(findings) == 1
    assert findings[0]["source"] == "Email Structure Analyzer"
    assert findings[0]["severity"] == "medium"
    assert findings[0]["title"] == "Reply-To domain mismatch"
    assert findings[0]["evidence"] == "Reply-To domain differs from From domain"