RISKY_ATTACHMENT_EXTENSIONS = [
    ".exe",
    ".js",
    ".vbs",
    ".scr",
    ".bat",
    ".cmd",
    ".ps1",
    ".zip",
    ".rar",
    ".iso",
    ".docm",
    ".xlsm",
]


def find_risky_attachments(attachments: list[str]) -> list[str]:
    risky = []

    for filename in attachments:
        lowered_filename = filename.lower()

        for extension in RISKY_ATTACHMENT_EXTENSIONS:
            if lowered_filename.endswith(extension):
                risky.append(filename)
                break

    return risky

def build_attachment_findings(risky_attachments: list[str]) -> list[dict]:
    findings = []

    for filename in risky_attachments:
        findings.append({
            "source": "Attachment Analyzer",
            "severity": "high",
            "title": "Risky attachment type detected",
            "description": "The email includes an attachment type that can commonly carry active content or malware.",
            "evidence": filename,
        })

    return findings