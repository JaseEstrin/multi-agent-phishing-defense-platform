import logging

from app.state import AnalysisState
from app.url_extractor import extract_urls
from app.url_analyzer import run_url_analysis
from app.language_analyzer import run_language_analysis
from app.attachment_analyzer import run_attachment_analysis
from app.email_structure_analyzer import run_email_structure_analysis

from app.scoring import (
    classify_score,
    build_score_breakdown,
    build_evidence,
    build_findings,
)

from app.recommendations import build_recommended_actions

logger = logging.getLogger(__name__)

def run_language_step(state: AnalysisState) -> AnalysisState:
    logger.info("Language agent started: analysis_id=%s", state.get("analysis_id"))

    parsed_email = state["parsed_email"]

    combined_body = (
        parsed_email.get("text_body", "")
        + "\n"
        + parsed_email.get("html_body", "")
    )

    language_analysis_result = run_language_analysis(combined_body)
    state["language_analysis"] = language_analysis_result
    state["language_findings"] = language_analysis_result["findings"]

    logger.info(
        "Language agent completed: analysis_id=%s keyword_count=%s finding_count=%s",
        state.get("analysis_id"),
        len(state["language_analysis"]["suspicious_keywords"]),
        len(state["language_findings"]),
    )

    state["audit_trail"].append(
        f"Language Agent found {len(state['language_analysis']['suspicious_keywords'])} suspicious keyword(s)."
    )

    return state

def run_attachment_step(state: AnalysisState) -> AnalysisState:
    logger.info("Attachment agent started: analysis_id=%s", state.get("analysis_id"))

    parsed_email = state["parsed_email"]

    attachment_analysis_result = run_attachment_analysis(
        parsed_email.get("attachments", [])
    )

    state["attachment_analysis"] = attachment_analysis_result
    state["attachment_findings"] = attachment_analysis_result["findings"]

    logger.info(
        "Attachment agent completed: analysis_id=%s attachment_count=%s risky_attachment_count=%s finding_count=%s",
        state.get("analysis_id"),
        len(parsed_email.get("attachments", [])),
        len(state["attachment_analysis"]["risky_attachments"]),
        len(state["attachment_findings"]),
    )

    state["audit_trail"].append(
        f"Attachment Agent reviewed {len(parsed_email.get('attachments', []))} attachment(s) and flagged {len(state['attachment_findings'])} issue(s)."
    )

    return state

def run_email_structure_step(state: AnalysisState) -> AnalysisState:
    logger.info("Email structure agent started: analysis_id=%s", state.get("analysis_id"))

    parsed_email = state["parsed_email"]

    email_structure_result = run_email_structure_analysis(parsed_email)

    state["email_structure_analysis"] = email_structure_result
    state["email_structure_findings"] = email_structure_result["findings"]

    logger.info(
        "Email structure agent completed: analysis_id=%s reply_to_mismatch=%s finding_count=%s",
        state.get("analysis_id"),
        state["email_structure_analysis"]["reply_to_mismatch"],
        len(state["email_structure_findings"]),
    )

    state["audit_trail"].append(
        f"Email Structure Agent checked sender metadata and produced {len(state['email_structure_findings'])} finding(s)."
    )

    return state

def run_url_step(state: AnalysisState) -> AnalysisState:
    logger.info("URL agent started: analysis_id=%s", state.get("analysis_id"))

    parsed_email = state["parsed_email"]

    combined_body = (
        parsed_email.get("text_body", "")
        + "\n"
        + parsed_email.get("html_body", "")
    )

    state["urls"] = extract_urls(combined_body)

    url_analysis_result = run_url_analysis(state["urls"])
    state["url_analysis"] = url_analysis_result["url_analysis"]
    state["url_findings"] = url_analysis_result["findings"]

    logger.info(
        "URL agent completed: analysis_id=%s url_count=%s finding_count=%s",
        state.get("analysis_id"),
        len(state["urls"]),
        len(state["url_findings"]),
    )

    state["audit_trail"].append(
        f"URL Agent analyzed {len(state['urls'])} URL(s) and produced {len(state['url_findings'])} finding(s)."
    )

    return state

def run_verdict_step(state: AnalysisState) -> AnalysisState:
    logger.info("Verdict agent started: analysis_id=%s", state.get("analysis_id"))

    parsed_email = state["parsed_email"]

    suspicious_keywords = state["language_analysis"]["suspicious_keywords"]
    risky_attachments = state["attachment_analysis"]["risky_attachments"]
    reply_to_mismatch = state["email_structure_analysis"]["reply_to_mismatch"]

    state["findings"] = build_findings(
        state["language_findings"],
        state["attachment_findings"],
        state["email_structure_findings"],
        state["url_findings"],
    )

    state["score_breakdown"] = build_score_breakdown(
        state["urls"],
        suspicious_keywords,
        parsed_email.get("attachments", []),
        risky_attachments,
        reply_to_mismatch,
        state["url_analysis"],
    )

    state["score"] = min(sum(state["score_breakdown"].values()), 100)
    state["verdict"] = classify_score(state["score"])

    state["evidence"] = build_evidence(
        state["urls"],
        suspicious_keywords,
        parsed_email.get("attachments", []),
        risky_attachments,
        reply_to_mismatch,
        state["url_analysis"],
    )

    state["recommended_actions"] = build_recommended_actions(
        state["verdict"],
        state["findings"],
    )

    logger.info(
        "Verdict agent completed: analysis_id=%s score=%s verdict=%s finding_count=%s",
        state.get("analysis_id"),
        state["score"],
        state["verdict"],
        len(state["findings"]),
    )

    state["audit_trail"].append(
        f"Verdict Agent assigned verdict '{state['verdict']}' with score {state['score']}."
    )

    return state