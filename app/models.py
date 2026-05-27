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

class PhishingAnalysisResult(BaseModel):
    parsed_email: dict
    urls: list[str]
    suspicious_keywords: list[str]
    risky_attachments: list[str]
    score: int
    verdict: FinalVerdict
    evidence: list[str]
    reply_to_mismatch: bool
    url_analysis: URLAnalysis