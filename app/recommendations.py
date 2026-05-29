SAFETY_NOTICE = (
    "This analysis is automated and intended for defensive decision-support. "
    "Do not click links, open attachments, reply to the sender, or provide sensitive "
    "information unless the message has been verified through trusted channels."
)

def build_recommended_actions(verdict: str, findings: list[dict]) -> list[str]:
    actions = [
        "Do not click links or open attachments until the message is verified.",
        "Verify the sender through a trusted channel, not by replying to the email.",
    ]

    if verdict in ["Suspicious", "Likely Phishing", "Malicious"]:
        actions.append("Report the message to your security team or email provider.")

    if verdict in ["Likely Phishing", "Malicious"]:
        actions.append("Do not provide passwords, payment information, or other sensitive data.")

    if verdict == "Malicious":
        actions.append("Quarantine or delete the message according to your organization’s policy.")

    for finding in findings:
        if finding["source"] == "Attachment Analyzer":
            actions.append("Do not open the attachment unless it has been reviewed in a safe environment.")
            break

    return actions