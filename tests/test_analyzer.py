from app.analyzer import classify_score

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


