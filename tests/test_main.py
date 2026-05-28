from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def test_root_endpoint():
    response = client.get("/")

    assert response.status_code == 200
    assert response.json() == {"message": "Phishing Defense API is running."}


def test_analyze_email_endpoint_with_raw_email():
    raw_email = """From: Test Notification <notice@example.com>
To: user@example.com
Subject: Synthetic Suspicious TLD Test
Reply-To: notice@example.com
Date: Tue, 26 May 2026 13:30:00 -0400
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"

Hello,

This is a synthetic test email for defensive phishing analysis.

This sample contains a URL with a suspicious top-level domain:
https://account-alert.xyz/login

This is for safe testing only.

Thank you.
"""

    response = client.post(
        "/analyze-email",
        json={"raw_email": raw_email},
    )

    assert response.status_code == 200

    data = response.json()

    assert data["score"] == 15

    score_breakdown = data["score_breakdown"]

    assert score_breakdown["suspicious_keywords"] == 0
    assert score_breakdown["url_count"] == 5
    assert score_breakdown["attachments"] == 0
    assert score_breakdown["risky_attachments"] == 0
    assert score_breakdown["reply_to_mismatch"] == 0
    assert score_breakdown["ip_address_urls"] == 0
    assert score_breakdown["shortened_urls"] == 0
    assert score_breakdown["suspicious_tld_urls"] == 10

    assert sum(score_breakdown.values()) == data["score"]

    assert data["verdict"] == "Safe"
    assert data["url_analysis"]["suspicious_tld_urls"] == [
        "https://account-alert.xyz/login"
    ]

    assert "findings" in data
    assert data["findings"][0]["source"] == "URL Analyzer"
    assert data["findings"][0]["title"] == "Suspicious top-level domain detected"
    assert data["findings"][0]["severity"] == "low"
    assert data["findings"][0]["evidence"] == "https://account-alert.xyz/login"

    assert "analysis_id" in data
    assert isinstance(data["analysis_id"], str)
    assert len(data["analysis_id"]) > 0

    assert "created_at" in data
    assert isinstance(data["created_at"], str)
    assert len(data["created_at"]) > 0

def test_analyze_email_response_includes_structured_parsed_email():
    raw_email = """From: Test Notification <notice@example.com>
To: user@example.com
Subject: Synthetic Parsed Email Model Test
Reply-To: notice@example.com
Date: Tue, 26 May 2026 14:00:00 -0400
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"

Hello,

This is a synthetic test email for checking the structured parsed_email response.

Visit https://example.com/parsed-email-test for this safe test.

Thank you.
"""

    response = client.post(
        "/analyze-email",
        json={"raw_email": raw_email},
    )

    assert response.status_code == 200

    data = response.json()
    parsed_email = data["parsed_email"]

    assert parsed_email["from_address"] == "Test Notification <notice@example.com>"
    assert parsed_email["to_address"] == "user@example.com"
    assert parsed_email["reply_to"] == "notice@example.com"
    assert parsed_email["subject"] == "Synthetic Parsed Email Model Test"
    assert parsed_email["date"] == "Tue, 26 May 2026 14:00:00 -0400"
    assert "structured parsed_email response" in parsed_email["text_body"]
    assert parsed_email["html_body"] == ""
    assert parsed_email["attachments"] == []