from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def test_root_endpoint():
    response = client.get("/")

    assert response.status_code == 200
    assert response.json() == {"message": "Phishing Defense API is running."}


def test_analyze_email_endpoint_with_sample_file():
    response = client.post(
        "/analyze-email",
        params={"file_path": "data/samples/suspicious_tld_test_email.eml"},
    )

    assert response.status_code == 200

    data = response.json()

    assert data["score"] == 15
    assert data["verdict"] == "Safe"
    assert "url_analysis" in data
    assert data["url_analysis"]["suspicious_tld_urls"] == [
        "https://account-alert.xyz/login"
    ]