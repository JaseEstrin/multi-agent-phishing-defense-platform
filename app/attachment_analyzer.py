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