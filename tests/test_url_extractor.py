from app.url_extractor import extract_urls

def test_extract_urls_finds_url():
    text = "Please visit https://example.com/review for details."
    urls = extract_urls(text)

    assert urls == ["https://example.com/review"]

def test_extract_urls_removes_trailing_period():
    text = "Please visit https://example.com/review."
    urls = extract_urls(text)

    assert urls == ["https://example.com/review"]