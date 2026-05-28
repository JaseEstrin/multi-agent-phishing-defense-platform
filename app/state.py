from typing import TypedDict, Any


class AnalysisState(TypedDict, total=False):
    analysis_id: str
    created_at: str
    parsed_email: dict[str, Any]

    urls: list[str]

    language_analysis: dict[str, Any]
    language_findings: list[dict[str, Any]]

    attachment_analysis: dict[str, Any]
    attachment_findings: list[dict[str, Any]]

    email_structure_analysis: dict[str, Any]
    email_structure_findings: list[dict[str, Any]]

    url_analysis: dict[str, Any]
    url_findings: list[dict[str, Any]]

    findings: list[dict[str, Any]]
    score_breakdown: dict[str, int]
    score: int
    verdict: str | None

    evidence: list[str]
    recommended_actions: list[str]
    safety_notice:str