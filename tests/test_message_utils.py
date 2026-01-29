from email import policy
from email.parser import BytesParser

import pytest

import constants
import message_utils


def test_split_raw_message_variants() -> None:
    header, separator, body = message_utils.split_raw_message(b"Subject: Hi\r\n\r\nBody")
    assert header == b"Subject: Hi"
    assert separator == b"\r\n\r\n"
    assert body == b"Body"

    header, separator, body = message_utils.split_raw_message(b"Subject: Hi\n\nBody")
    assert header == b"Subject: Hi"
    assert separator == b"\n\n"
    assert body == b"Body"

    header, separator, body = message_utils.split_raw_message(b"Body only")
    assert header == b"Body only"
    assert separator == b""
    assert body == b""


def test_split_raw_message_leading_blank() -> None:
    assert message_utils.split_raw_message(b"\r\nBody") == (b"", b"\r\n", b"Body")
    assert message_utils.split_raw_message(b"\nBody") == (b"", b"\n", b"Body")


def test_update_raw_headers_replaces_existing() -> None:
    raw = b"From: old@example.com\r\nSubject: Test\r\n\r\nBody"
    updated = message_utils.update_raw_headers(raw, {"From": "new@example.com", "X-Test": "yes"})
    assert b"From: old@example.com" not in updated
    assert b"From: new@example.com" in updated
    assert b"X-Test: yes" in updated


def test_update_raw_headers_appends_with_line_endings() -> None:
    raw = b"From: old@example.com\r\nSubject: Test\r\n\r\nBody"
    updated = message_utils.update_raw_headers(raw, {"X-Test": "yes"})
    parsed = BytesParser(policy=policy.SMTP).parsebytes(updated)
    assert parsed.get("Subject") == "Test"
    assert parsed.get("X-Test") == "yes"


def test_update_raw_headers_no_headers() -> None:
    raw = b"Body"
    updated = message_utils.update_raw_headers(raw, {"X-Test": "yes"})
    assert b"X-Test: yes" in updated


def test_apply_header_updates_noop() -> None:
    raw = b"From: a@b.com\r\n\r\nBody"
    parsed = BytesParser(policy=policy.SMTP).parsebytes(raw)
    assert message_utils.apply_header_updates(raw, parsed, {}, []) == raw


def test_apply_header_updates_removes_header() -> None:
    raw = b"Subject: Test\r\nX-Remove: yes\r\n\r\nBody"
    parsed = BytesParser(policy=policy.SMTP).parsebytes(raw)
    updated = message_utils.apply_header_updates(raw, parsed, {"X-Remove": None}, ["test"])
    assert b"X-Remove" not in updated


def test_build_reply_to_value_appends() -> None:
    existing = "ops@example.com"
    original = "Group <group@example.com>"
    reply_to = message_utils.build_reply_to_value(existing, original)
    assert reply_to == "ops@example.com, Group <group@example.com>"


def test_build_reply_to_value_no_change() -> None:
    assert (
        message_utils.build_reply_to_value("ops@example.com", "invalid <>")
        == "ops@example.com"
    )


def test_validate_rfc5322_requires_date() -> None:
    raw_message = b"From: sender@example.com\r\n\r\nBody"
    assert message_utils.validate_rfc5322_message(raw_message).startswith("554")


def test_validate_rfc5322_missing_from() -> None:
    raw_message = b"Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n\r\nBody"
    assert message_utils.validate_rfc5322_message(raw_message) == constants.SMTP_MISSING_FROM


def test_validate_rfc5322_allows_missing_from_with_failback() -> None:
    raw_message = b"Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n\r\nBody"
    assert (
        message_utils.validate_rfc5322_message(
            raw_message,
            allow_invalid_from=True,
        )
        is None
    )


def test_validate_rfc5322_allows_invalid_from_with_failback() -> None:
    raw_message = b"From: <>\r\nDate: Mon, 01 Jan 2024 00:00:00 +0000\r\n\r\nBody"
    assert (
        message_utils.validate_rfc5322_message(
            raw_message,
            allow_invalid_from=True,
        )
        is None
    )


def test_validate_rfc5322_variants() -> None:
    assert (
        message_utils.validate_rfc5322_message(b"From: a@b.com\n\nBody")
        == constants.SMTP_BARE_LF
    )

    missing_date = b"From: a@b.com\r\n\r\nBody"
    assert message_utils.validate_rfc5322_message(missing_date) == constants.SMTP_MISSING_DATE

    invalid_date = b"From: a@b.com\r\nDate: nope\r\n\r\nBody"
    assert message_utils.validate_rfc5322_message(invalid_date) == constants.SMTP_INVALID_DATE

    invalid_from = b"From: <>\r\nDate: Mon, 01 Jan 2024 00:00:00 +0000\r\n\r\nBody"
    assert message_utils.validate_rfc5322_message(invalid_from) == constants.SMTP_INVALID_FROM


def test_validate_rfc5322_invalid_date_none(monkeypatch: pytest.MonkeyPatch) -> None:
    raw_message = b"From: sender@example.com\r\nDate: Mon, 01 Jan 2024 00:00:00 +0000\r\n\r\nBody"
    monkeypatch.setattr(message_utils, "parsedate_to_datetime", lambda _value: None)
    assert message_utils.validate_rfc5322_message(raw_message) == constants.SMTP_INVALID_DATE


def test_update_raw_headers_skips_folded_lines() -> None:
    raw = b"Subject: Test\r\n\tcontinued\r\nX-Test: yes\r\n\r\nBody"
    updated = message_utils.update_raw_headers(raw, {"Subject": "New"})
    parsed = BytesParser(policy=policy.SMTP).parsebytes(updated)
    assert parsed.get("Subject") == "New"


def test_update_raw_headers_no_separator_body(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        message_utils,
        "split_raw_message",
        lambda _raw: (b"Header: value", b"", b"Body"),
    )
    updated = message_utils.update_raw_headers(b"ignored", {"X-Test": "yes"})
    assert b"X-Test: yes" in updated
    assert b"\r\n\r\nBody" in updated or b"\n\nBody" in updated


def test_apply_header_updates_debug_logging(caplog: pytest.LogCaptureFixture) -> None:
    raw = b"Subject: Test\r\nX-Remove: yes\r\n\r\nBody"
    parsed = BytesParser(policy=policy.SMTP).parsebytes(raw)
    with caplog.at_level("DEBUG"):
        updated = message_utils.apply_header_updates(
            raw,
            parsed,
            {"X-Remove": None, "X-Add": "yes"},
            ["test"],
        )
    assert b"X-Remove" not in updated


def test_build_reply_to_value_existing_match() -> None:
    assert (
        message_utils.build_reply_to_value("ops@example.com", "ops@example.com")
        == "ops@example.com"
    )


def test_message_utils_logging_helpers() -> None:
    message_utils.log_recipient_header_remap()
    message_utils.log_envelope_recipient_remap()
    message_utils.log_failback_sender_used("example.com")
    message_utils.log_failback_sender_missing()
    message_utils.log_from_remap_applied("example.com", "sender@example.com")
    message_utils.log_from_remap_missing("example.com")
    message_utils.log_failure_notification_missing_sender("example.com")
    message_utils.log_rfc5322_validation_failed("error")
    message_utils.log_invalid_x_sender("bad", "sender@example.com", "return", "from")
    message_utils.log_invalid_x_sender("bad", None, "return", "from")
