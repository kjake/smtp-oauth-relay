import types
from email import policy
from email.parser import BytesParser

import pytest

import graph_client


def test_send_email_success(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeResponse:
        status_code = 202
        text = ""

    monkeypatch.setattr(graph_client.requests, "post", lambda *args, **kwargs: FakeResponse())
    assert graph_client.send_email("token", b"Body", "user@example.com") == (True, None, 202)


def test_send_email_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeResponse:
        status_code = 400
        text = "bad"

    monkeypatch.setattr(graph_client.requests, "post", lambda *args, **kwargs: FakeResponse())
    success, error_detail, status_code = graph_client.send_email("token", b"body", "user@x.com")
    assert success is False
    assert status_code == 400
    assert "Status code 400" in error_detail


def test_send_email_exception(monkeypatch: pytest.MonkeyPatch) -> None:
    def raise_error(*_args, **_kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(graph_client.requests, "post", raise_error)
    success, error_detail, status_code = graph_client.send_email("token", b"body", "user@x.com")
    assert success is False
    assert status_code is None
    assert "boom" in error_detail


def test_send_failure_notification(monkeypatch: pytest.MonkeyPatch) -> None:
    captured = {}

    def fake_send_email(access_token, body, from_email):
        captured["body"] = body
        captured["from_email"] = from_email
        return True, None, 202

    monkeypatch.setattr(graph_client, "send_email", fake_send_email)

    parsed_message = BytesParser(policy=policy.SMTP).parsebytes(
        b"From: sender@example.com\r\n"
        b"To: recipient@example.com\r\n"
        b"Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n"
        b"Subject: Test\r\n"
        b"Message-ID: <id@example.com>\r\n\r\nBody"
    )
    envelope = types.SimpleNamespace(
        mail_from="sender@example.com",
        rcpt_tos=["recipient@example.com"]
    )

    graph_client.send_failure_notification(
        access_token="token",
        from_email="notify@example.com",
        notification_address="alerts@example.com",
        parsed_message=parsed_message,
        envelope=envelope,
        error_detail="Boom"
    )

    message = BytesParser(policy=policy.SMTP).parsebytes(captured["body"])
    assert message["Subject"].startswith("SMTP relay failure")
    assert message["To"] == "alerts@example.com"
    assert message["From"] == "notify@example.com"


def test_send_failure_notification_logs_error(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setattr(graph_client, "send_email", lambda *args, **kwargs: (False, "oops", 500))
    parsed_message = BytesParser(policy=policy.SMTP).parsebytes(
        b"From: sender@example.com\r\n"
        b"To: recipient@example.com\r\n"
        b"Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n"
        b"Subject: Test\r\n"
        b"Message-ID: <id@example.com>\r\n\r\nBody"
    )
    envelope = types.SimpleNamespace(
        mail_from="sender@example.com",
        rcpt_tos=["recipient@example.com"]
    )
    with caplog.at_level("ERROR"):
        graph_client.send_failure_notification(
            access_token="token",
            from_email="notify@example.com",
            notification_address="alerts@example.com",
            parsed_message=parsed_message,
            envelope=envelope,
            error_detail="Boom"
        )
    assert "Failed to send failure notification" in caplog.text
