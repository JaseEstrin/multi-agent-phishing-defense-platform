import ipaddress
from urllib.parse import urlparse

URL_SHORTENER_DOMAINS = [
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "rebrand.ly",
    "cutt.ly",
]

SUSPICIOUS_TLDS = [
    ".zip",
    ".mov",
    ".top",
    ".xyz",
    ".click",
    ".work",
    ".tk",
    ".ml",
    ".ga",
    ".cf",
]

def extract_domain_from_url(url: str) -> str | None:
    parsed = urlparse(url)
    return parsed.netloc.lower() if parsed.netloc else None

def is_url_shortener(url: str) -> bool:
    domain = extract_domain_from_url(url)

    if not domain:
        return False
    
    return domain in URL_SHORTENER_DOMAINS or any(
        domain.endswith("." + shortener) for shortener in URL_SHORTENER_DOMAINS
    )

def is_ip_address_url(url: str) -> bool:
    domain = extract_domain_from_url(url)

    if not domain:
        return False
    
    try:
        ipaddress.ip_address(domain)
        return True
    except ValueError:
        return False
    
def has_suspicious_tld(url: str) -> bool:
    domain = extract_domain_from_url(url)

    if not domain:
        return False
    
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            return True
        
    return False
    
def analyze_urls(urls: list[str]) -> dict:
    ip_address_urls = []
    shortened_urls = []
    suspicious_tld_urls = []

    for url in urls:
        if is_ip_address_url(url):
            ip_address_urls.append(url)

        if is_url_shortener(url):
            shortened_urls.append(url)

        if has_suspicious_tld(url):
            suspicious_tld_urls.append(url)
    
    return {
        "ip_address_urls": ip_address_urls,
        "shortened_urls": shortened_urls,
        "suspicious_tld_urls": suspicious_tld_urls,
        "url_count": len(urls)
    }
    
if __name__ == "__main__":
    test_urls = [
        "https://example.com/review",
        "http://203.0.113.50/login",
        "https://account-alert.xyz/login",
        "https://bit.ly/safe-test",
    ]

    result = analyze_urls(test_urls)
    print(result)