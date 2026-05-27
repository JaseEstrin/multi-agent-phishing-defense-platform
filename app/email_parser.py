from email import policy
from email.parser import Parser
from email.parser import BytesParser

from app.url_extractor import extract_urls

def parse_eml_content(raw_email: str) -> dict:
    msg = Parser(policy=policy.default).parsestr(raw_email)

    parsed = {
        "from_address": msg.get("From"),
        "to_address": msg.get("To"),
        "reply_to": msg.get("Reply-To"),
        "subject": msg.get("Subject"),
        "date": msg.get("Date"),
        "text_body": "",
        "html_body": "",
        "attachments": [],
    }

    for part in msg.walk():
        content_type = part.get_content_type()
        filename = part.get_filename()

        if filename:
            parsed["attachments"].append(filename)
            continue

        if content_type == "text/plain":
            parsed["text_body"] += part.get_content()

        elif content_type == "text/html":
            parsed["html_body"] += part.get_content()

    return parsed

def parse_eml_file(path: str) -> dict:
    with open(path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)

    parsed = {
        "from_address": msg.get("From"),
        "to_address": msg.get("To"),
        "reply_to": msg.get("Reply-To"),
        "subject": msg.get("Subject"),
        "date": msg.get("Date"),
        "text_body": "",
        "html_body": "",
        "attachments": [],
    }

    for part in msg.walk():
        content_type = part.get_content_type()
        filename = part.get_filename()

        if filename:
            parsed["attachments"].append(filename)
            continue

        if content_type == "text/plain":
            parsed["text_body"] += part.get_content()

        elif content_type == "text/html":
            parsed["html_body"] += part.get_content()

    return parsed

if __name__ == "__main__":
    result = parse_eml_file("data/samples/test_email.eml")
    urls = extract_urls(result["text_body"])

    print(result)
    print("#"*20)
    print(urls)