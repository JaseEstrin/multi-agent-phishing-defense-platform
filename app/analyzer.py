import logging

from pprint import pprint
from datetime import datetime, timezone
from uuid import uuid4

from app.state import AnalysisState
from app.email_parser import parse_eml_file, parse_eml_content
from app.workflow import run_analysis_workflow
from app.recommendations import SAFETY_NOTICE

logger = logging.getLogger(__name__)

def create_initial_state(parsed_email: dict) -> AnalysisState:
    return {
        "analysis_id": str(uuid4()),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "parsed_email": parsed_email,
        "urls": [],
        "language_analysis": {},
        "language_findings": [],
        "attachment_analysis": {},
        "attachment_findings": [],
        "email_structure_analysis": {},
        "email_structure_findings": [],
        "url_analysis": {},
        "url_findings": [],
        "findings": [],
        "score_breakdown": {},
        "score": 0,
        "verdict": None,
        "evidence": [],
        "recommended_actions": [],
        "safety_notice": SAFETY_NOTICE,
    }

def build_analysis_result(state: AnalysisState) -> AnalysisState:
    return {
        "analysis_id": state["analysis_id"],
        "created_at": state["created_at"],
        "parsed_email": state["parsed_email"],
        "urls": state["urls"],
        "suspicious_keywords": state["language_analysis"]["suspicious_keywords"],
        "risky_attachments": state["attachment_analysis"]["risky_attachments"],
        "score": state["score"],
        "verdict": state["verdict"],
        "evidence": state["evidence"],
        "reply_to_mismatch": state["email_structure_analysis"]["reply_to_mismatch"],
        "url_analysis": state["url_analysis"],
        "findings": state["findings"],
        "score_breakdown": state["score_breakdown"],
        "recommended_actions": state["recommended_actions"],
        "safety_notice": state["safety_notice"],
    }

def analyze_parsed_email(parsed_email: dict) -> dict:
    state: AnalysisState = create_initial_state(parsed_email)

    logger.info("Analysis started: %s", state["analysis_id"])

    state = run_analysis_workflow(state)

    result = build_analysis_result(state)

    logger.info(
        "Analysis completed: analysis_id=%s score=%s verdict=%s finding_count=%s",
        state["analysis_id"],
        state["score"],
        state["verdict"],
        len(state["findings"]),
    )

    return result

def analyze_eml_content(raw_email: str) -> dict:
    parsed_email = parse_eml_content(raw_email)
    return analyze_parsed_email(parsed_email)
    
def analyze_eml_file(path: str) -> dict:
    parsed_email = parse_eml_file(path)
    return analyze_parsed_email(parsed_email)

if __name__ == "__main__":
    result = analyze_eml_file("data/samples/suspicious_tld_test_email.eml")
    pprint(result)