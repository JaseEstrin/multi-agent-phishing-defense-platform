from app.attachment_analyzer import find_risky_attachments, build_attachment_findings

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