from app.attachment_analyzer import find_risky_attachments, build_attachment_findings, run_attachment_analysis

def test_find_risky_attachments_detects_xlsm():
    attachments = ["invoice.pdf", "payment_details.xlsm"]

    risky = find_risky_attachments(attachments)

    assert risky == ["payment_details.xlsm"]

def test_build_attachment_findings_for_risky_attachment():
    risky_attachments = ["invoice_details.xlsm"]

    findings = build_attachment_findings(risky_attachments)

    assert len(findings) == 1
    assert findings[0]["source"] == "Attachment Analyzer"
    assert findings[0]["severity"] == "high"
    assert findings[0]["title"] == "Risky attachment type detected"
    assert findings[0]["evidence"] == "invoice_details.xlsm"

def test_run_attachment_analysis_returns_risky_attachments_and_findings():
    attachments = ["invoice.pdf", "invoice_details.xlsm"]

    result = run_attachment_analysis(attachments)

    assert result["risky_attachments"] == ["invoice_details.xlsm"]
    assert len(result["findings"]) == 1
    assert result["findings"][0]["source"] == "Attachment Analyzer"