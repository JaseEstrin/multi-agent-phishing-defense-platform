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
    assert data["verdict"] == "Safe"
    assert data["url_analysis"]["suspicious_tld_urls"] == [
        "https://account-alert.xyz/login"
    ]