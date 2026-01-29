import types
from email import policy
from email.parser import BytesParser

import pytest

import main


def test_handler_requires_auth_token() -> None:
    handler = main.Handler()
    session = types.SimpleNamespace()
    envelope = types.SimpleNamespace(
        mail_from="sender@example.com",
        rcpt_tos=["recipient@example.com"],
        content=(
            b"From: sender@example.com\r\n"
            b"To: recipient@example.com\r\n"
            b"Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n"
            b"\r\nBody"
        )
    )
    response = __import__("asyncio").run(handler.handle_DATA(None, session, envelope))
    assert response.startswith("530")


def test_handler_sends_email(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(main.graph_client, "send_email", lambda *args, **kwargs: (True, None, 202))

    handler = main.Handler()
    session = types.SimpleNamespace(access_token="token", lookup_from_email=None)
    envelope = types.SimpleNamespace(
        mail_from="sender@example.com",
        rcpt_tos=["recipient@example.com"],
        content=(
            b"From: sender@example.com\r\n"
            b"To: recipient@example.com\r\n"
            b"Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n"
            b"\r\nBody"
        )
    )
    response = __import__("asyncio").run(handler.handle_DATA(None, session, envelope))
    assert response == "250 OK"


def test_handler_inserts_reply_to_when_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    captured = {}

    def fake_send_email(access_token, body, from_email):
        captured["body"] = body
        return True, None, 202

    monkeypatch.setattr(main.graph_client, "send_email", fake_send_email)

    handler = main.Handler()
    session = types.SimpleNamespace(access_token="token", lookup_from_email=None)
    envelope = types.SimpleNamespace(
        mail_from="sender@example.com",
        rcpt_tos=["recipient@example.com"],
        content=(
            b"From: Sender Name <sender@example.com>\r\n"
            b"To: recipient@example.com\r\n"
            b"Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n"
            b"\r\nBody"
        )
    )

    response = __import__("asyncio").run(handler.handle_DATA(None, session, envelope))
    assert response == "250 OK"

    parsed = BytesParser(policy=policy.SMTP).parsebytes(captured["body"])
    assert parsed.get("Reply-To") == "Sender Name <sender@example.com>"


def test_handler_normalizes_invalid_x_sender(monkeypatch: pytest.MonkeyPatch) -> None:
    captured = {}

    def fake_send_email(access_token, body, from_email):
        captured["body"] = body
        captured["from_email"] = from_email
        return True, None, 202

    monkeypatch.setattr(main.graph_client, "send_email", fake_send_email)

    handler = main.Handler()
    session = types.SimpleNamespace(access_token="token", lookup_from_email=None)
    envelope = types.SimpleNamespace(
        mail_from="<>",
        rcpt_tos=["recipient@example.com"],
        content=(
            b"x-sender: <>\r\n"
            b"From: sender@example.com\r\n"
            b"To: recipient@example.com\r\n"
            b"Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n"
            b"\r\nBody"
        )
    )

    response = __import__("asyncio").run(handler.handle_DATA(None, session, envelope))
    assert response == "250 OK"

    parsed = BytesParser(policy=policy.SMTP).parsebytes(captured["body"])
    assert parsed.get("X-Sender") == "sender@example.com"


def test_handle_mail_rejects_invalid_sender() -> None:
    handler = main.Handler()
    response = __import__("asyncio").run(
        handler.handle_MAIL(None, None, None, "invalid address", [])
    )
    assert response.startswith("553")


def test_handle_mail_accepts_valid_sender() -> None:
    handler = main.Handler()
    response = __import__("asyncio").run(
        handler.handle_MAIL(None, None, None, "sender@example.com", [])
    )
    assert response is main.MISSING


def test_handle_rcpt_rejects_null_recipient() -> None:
    handler = main.Handler()
    response = __import__("asyncio").run(
        handler.handle_RCPT(None, None, None, "<>", [])
    )
    assert response.startswith("553")


def test_handle_rcpt_accepts_valid_recipient() -> None:
    handler = main.Handler()
    response = __import__("asyncio").run(
        handler.handle_RCPT(None, None, None, "recipient@example.com", [])
    )
    assert response is main.MISSING
