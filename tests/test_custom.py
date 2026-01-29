import asyncio

import pytest

import constants
import custom


def test_custom_smtp_auth_and_starttls(monkeypatch: pytest.MonkeyPatch) -> None:
    loop = asyncio.new_event_loop()
    smtp = custom.CustomSMTP(handler=None, loop=loop, enable_SMTPUTF8=True)

    captured = {}

    async def fake_super_auth(self, arg):
        captured["arg"] = arg
        return "ok"

    async def fake_super_starttls(self, arg):
        raise custom.TLSSetupException("boom")

    monkeypatch.setattr(custom.SMTP, "smtp_AUTH", fake_super_auth)
    monkeypatch.setattr(custom.SMTP, "smtp_STARTTLS", fake_super_starttls)

    assert loop.run_until_complete(smtp.smtp_AUTH("login foo")) == "ok"
    assert captured["arg"] == "LOGIN foo"

    assert loop.run_until_complete(smtp.smtp_STARTTLS("")) == constants.SMTP_TLS_NOT_AVAILABLE

    loop.close()


def test_custom_session_login_data() -> None:
    loop = asyncio.new_event_loop()
    session = custom.CustomSession(loop)
    session.login_data = "value"
    assert session.login_data == "value"
    loop.close()


def test_custom_session_factory() -> None:
    loop = asyncio.new_event_loop()
    smtp = custom.CustomSMTP(handler=None, loop=loop, enable_SMTPUTF8=True)
    session = smtp._create_session()
    assert isinstance(session, custom.CustomSession)
    loop.close()
