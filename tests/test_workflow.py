from app.analyzer import create_initial_state
from app.email_parser import parse_eml_content
from app.workflow import run_analysis_workflow


def test_run_analysis_workflow_completes_state():
    raw_email = """From: Test Notification <notice@example.com>
To: user@example.com
Subject: Synthetic Workflow Test
Reply-To: notice@example.com
Date: Tue, 26 May 2026 16:00:00 -0400
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"

Hello,

This is a synthetic workflow test email.

Please review this safe test link:
https://account-alert.xyz/workflow-test

Thank you.
"""

    parsed_email = parse_eml_content(raw_email)
    state = create_initial_state(parsed_email)

    result_state = run_analysis_workflow(state)

    assert result_state["score"] == 15
    assert result_state["verdict"] == "Safe"
    assert result_state["url_analysis"]["suspicious_tld_urls"] == [
        "https://account-alert.xyz/workflow-test"
    ]
    assert len(result_state["url_findings"]) == 1
    assert len(result_state["findings"]) == 1
    assert result_state["recommended_actions"]

    assert "audit_trail" in result_state
    assert len(result_state["audit_trail"]) == 5
    assert result_state["audit_trail"][-1].startswith("Verdict Agent assigned verdict")