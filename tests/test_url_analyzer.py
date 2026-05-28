from app.url_analyzer import (
    extract_domain_from_url,
    is_ip_address_url,
    is_url_shortener,
    has_suspicious_tld,
    analyze_urls,
    build_url_findings,
)

def test_extract_domain_from_url():
    url = "https://example.com/review"

    assert extract_domain_from_url(url) == "example.com"

def test_is_ip_address_url_detects_ip():
    url = "http://203.0.113.50/login"

    assert is_ip_address_url(url) is True

def test_is_url_shortener_detects_bitly():
    url = "https://bit.ly/safe-test"

    assert is_url_shortener(url) is True

def test_has_suspicious_tld_detects_xyz():
    url = "https://account-alert.xyz/login"

    assert has_suspicious_tld(url) is True

def test_build_urls_for_suspicious_tld():
    url_analysis = {
        "ip_address_urls": [],
        "shortened_urls": [],
        "suspicious_tld_urls": ["https://account-alert.xyz/login"],
        "url_count": 1,
    }

    findings = build_url_findings(url_analysis)

    assert len(findings) == 1
    assert findings[0]["source"] == "URL Analyzer"
    assert findings[0]["severity"] == "low"
    assert findings[0]["title"] == "Suspicious top-level domain detected"
    assert findings[0]["evidence"] == "https://account-alert.xyz/login"