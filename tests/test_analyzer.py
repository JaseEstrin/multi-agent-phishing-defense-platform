from app.analyzer import (
    classify_score,
    extract_email_domain,
    has_reply_to_mismatch,
)

def test_classify_score_safe():
    assert classify_score(0) == "Safe"
    assert classify_score(24) == "Safe"


def test_classify_score_suspicious():
    assert classify_score(25) == "Suspicious"
    assert classify_score(49) == "Suspicious"


def test_classify_score_likely_phishing():
    assert classify_score(50) == "Likely Phishing"
    assert classify_score(74) == "Likely Phishing"


def test_classify_score_malicious():
    assert classify_score(75) == "Malicious"
    assert classify_score(100) == "Malicious"


def test_extract_email_domain():
    header = "Billing Notices <billing@example.com>"

    assert extract_email_domain(header) == "example.com"


def test_has_reply_to_mismatch_detects_different_domain():
    parsed_email = {
        "from_address": "Billing Notices <billing@example.com>",
        "reply_to": "Support <support@example.net>",
    }

    assert has_reply_to_mismatch(parsed_email) is True