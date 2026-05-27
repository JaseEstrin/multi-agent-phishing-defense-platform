import re


def extract_urls(text: str) -> list[str]:
    pattern = r"https?://[^\s]+"
    raw_urls = re.findall(pattern, text)

    cleaned_urls = []
    for url in raw_urls:
        cleaned_url = url.strip(".,!?;:")
        cleaned_urls.append(cleaned_url)

    return cleaned_urls