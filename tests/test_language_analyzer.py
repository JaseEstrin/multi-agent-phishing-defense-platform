from app.language_analyzer import find_suspicious_keywords, build_language_findings, run_language_analysis

def test_find_suspicious_keywords():
    text = "This is urgent. Please verify your account immediately."

    matches = find_suspicious_keywords(text)

    assert "urgent" in matches
    assert "verify" in matches
    assert "immediately" in matches

def test_build_language_findings_for_suspicious_keyword():
    suspicious_keywords = ["urgent"]

    findings = build_language_findings(suspicious_keywords)

    assert len(findings) == 1
    assert findings[0]["source"] == "Language Analyzer"
    assert findings[0]["severity"] == "medium"
    assert findings[0]["title"] == "Suspicious keyword detected"
    assert findings[0]["evidence"] == "urgent"

def test_run_language_analysis_returns_keywords_and_findings():
    text = "Urgent: please verify your account immediately."

    result = run_language_analysis(text)

    assert result["suspicious_keywords"] == ["urgent", "verify", "immediately"]
    assert len(result["findings"]) == 3
    assert result["findings"][0]["source"] == "Language Analyzer"