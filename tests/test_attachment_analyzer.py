from app.attachment_analyzer import find_risky_attachments

def test_find_risky_attachments_detects_xlsm():
    attachments = ["invoice.pdf", "payment_details.xlsm"]

    risky = find_risky_attachments(attachments)

    assert risky == ["payment_details.xlsm"]