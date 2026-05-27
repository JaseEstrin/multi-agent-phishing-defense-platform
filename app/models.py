from enum import Enum
from pydantic import BaseModel

class FinalVerdict(str, Enum):
    SAFE = "Safe"
    SUSPICIOUS = "Suspicious"
    LIKELY_PHISHING = "Likely Phishing"
    MALICIOUS = "Malicious"

class EmailInput(BaseModel):
    raw_email: str

class URLAnalysis(BaseModel):
    ip_address_urls: list[str]
    shortened_urls: list[str]
    suspicious_tld_urls: list[str]
    url_count: int

class ParsedEmail(BaseModel):
    from_address: str | None
    to_address: str | None
    reply_to: str | None
    subject: str | None
    date: str | None
    text_body: str
    html_body: str
    attachments: list[str]

class PhishingAnalysisResult(BaseModel):
    parsed_email: ParsedEmail
    urls: list[str]
    suspicious_keywords: list[str]
    risky_attachments: list[str]
    score: int
    verdict: FinalVerdict
    evidence: list[str]
    reply_to_mismatch: bool
    url_analysis: URLAnalysis