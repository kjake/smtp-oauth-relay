import re
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses, parsedate_to_datetime

BARE_LF_PATTERN = re.compile(br"(?<!\r)\n")


def validate_rfc5322_message(raw_message: bytes) -> str | None:
    if BARE_LF_PATTERN.search(raw_message):
        return "550 5.6.0 Message contains bare LF line endings"

    parsed_message = BytesParser(policy=policy.SMTP).parsebytes(raw_message)
    from_header = parsed_message.get("From")
    date_header = parsed_message.get("Date")
    if not from_header:
        return "554 5.6.0 Missing required header: From"
    if not date_header:
        return "554 5.6.0 Missing required header: Date"

    addresses = [addr for _, addr in getaddresses([from_header]) if addr]
    if not addresses or any("@" not in addr for addr in addresses):
        return "554 5.6.0 Invalid From header"

    try:
        if parsedate_to_datetime(date_header) is None:
            return "554 5.6.0 Invalid Date header"
    except (TypeError, ValueError):
        return "554 5.6.0 Invalid Date header"
    return None


def split_raw_message(raw_message: bytes) -> tuple[bytes, bytes, bytes]:
    header_end = raw_message.find(b"\r\n\r\n")
    separator = b"\r\n\r\n"
    if header_end == -1:
        header_end = raw_message.find(b"\n\n")
        separator = b"\n\n"
    if header_end == -1:
        if raw_message.startswith(b"\r\n"):
            return b"", b"\r\n", raw_message[len(b"\r\n"):]
        if raw_message.startswith(b"\n"):
            return b"", b"\n", raw_message[len(b"\n"):]
        return raw_message, b"", b""
    header_bytes = raw_message[:header_end]
    body_bytes = raw_message[header_end + len(separator):]
    return header_bytes, separator, body_bytes


def update_raw_headers(raw_message: bytes, updates: dict[str, str | None]) -> bytes:
    header_bytes, separator, body_bytes = split_raw_message(raw_message)
    line_ending = b"\r\n" if b"\r\n" in header_bytes else b"\n"

    updated_keys = {key.lower() for key in updates}
    new_lines: list[bytes] = []
    skip_header = False

    for line in header_bytes.splitlines(keepends=True):
        if line.startswith((b" ", b"\t")):
            if skip_header:
                continue
            new_lines.append(line)
            continue

        header_name = line.split(b":", 1)[0].decode("utf-8", "replace").strip().lower()
        skip_header = header_name in updated_keys
        if skip_header:
            continue
        new_lines.append(line)

    for header_name, header_value in updates.items():
        if header_value is None:
            continue
        new_lines.append(f"{header_name}: {header_value}".encode() + line_ending)

    rebuilt_headers = b"".join(new_lines)
    if separator:
        return rebuilt_headers + separator + body_bytes
    if body_bytes:
        return rebuilt_headers + (line_ending + line_ending) + body_bytes
    return rebuilt_headers


def build_reply_to_value(existing_reply_to: str | None, original_from: str) -> str:
    if not existing_reply_to:
        return original_from
    existing_addresses = {
        addr.lower() for _, addr in getaddresses([existing_reply_to]) if addr
    }
    original_addresses = [addr for _, addr in getaddresses([original_from]) if addr]
    if not original_addresses:
        return existing_reply_to
    if any(addr.lower() not in existing_addresses for addr in original_addresses):
        return f"{existing_reply_to}, {original_from}"
    return existing_reply_to
