from app.language_analyzer import find_suspicious_keywords

def test_find_suspicious_keywords():
    text = "This is urgent. Please verify your account immediately."

    matches = find_suspicious_keywords(text)

    assert "urgent" in matches
    assert "verify" in matches
    assert "immediately" in matches