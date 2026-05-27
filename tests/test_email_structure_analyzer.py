from app.email_structure_analyzer import (
    extract_email_domain,
    has_reply_to_mismatch,
)


def test_extract_email_domain():
    header = "Billing Notices <billing@example.com>"

    assert extract_email_domain(header) == "example.com"


def test_has_reply_to_mismatch_detects_different_domain():
    parsed_email = {
        "from_address": "Billing Notices <billing@example.com>",
        "reply_to": "Support <support@example.net>",
    }

    assert has_reply_to_mismatch(parsed_email) is True