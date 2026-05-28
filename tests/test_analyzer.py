from app.analyzer import classify_score
from app.analyzer import build_score_breakdown

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


def test_build_score_for_suspicious_tlds():
    urls = ["https://account-alert.xyz/login"]
    suspicious_keywords = []
    attachments = []
    risky_attachments = []
    reply_to_mismatch = False
    url_analysis = {
        "ip_address_urls": [],
        "shortened_urls": [],
        "suspicious_tld_urls": ["https://account-alert.xyz/login"],
        "url_count": 1,
    }

    breakdown = build_score_breakdown(
        urls,
        suspicious_keywords,
        attachments,
        risky_attachments,
        reply_to_mismatch,
        url_analysis,
    )

    assert breakdown == {
        "suspicious_keywords": 0,
        "url_count": 5,
        "attachments": 0,
        "risky_attachments": 0,
        "reply_to_mismatch": 0,
        "ip_address_urls": 0,
        "shortened_urls": 0,
        "suspicious_tld_urls": 10,
    }

    assert sum(breakdown.values()) == 15