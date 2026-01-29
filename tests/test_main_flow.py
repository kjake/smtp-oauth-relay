import asyncio
import types
from email import policy
from email.parser import BytesParser

import pytest

import config_resolver
import constants
import main
import remap


def _make_envelope(content: bytes, mail_from: str = "sender@example.com") -> types.SimpleNamespace:
    return types.SimpleNamespace(
        mail_from=mail_from,
        rcpt_tos=["recipient@example.com"],
        content=content
    )


def test_handle_data_rfc_validation_error(monkeypatch: pytest.MonkeyPatch) -> None:
    handler = main.Handler()
    session = types.SimpleNamespace(access_token="token", lookup_from_email=None)
    content = b"From: sender@example.com\r\n\r\nBody"
    envelope = _make_envelope(content)
    monkeypatch.setattr(
        main.config_resolver,
        "resolve_domain_context",
        lambda *args, **kwargs: config_resolver.DomainContext(None, None, None, None),
    )
    response = asyncio.run(handler.handle_DATA(None, session, envelope))
    assert response == constants.SMTP_MISSING_DATE


def test_handle_data_send_email_failure_404(monkeypatch: pytest.MonkeyPatch) -> None:
    handler = main.Handler()
    session = types.SimpleNamespace(access_token="token", lookup_from_email=None)
    content = (
        b"From: sender@example.com\r\n"
        b"To: recipient@example.com\r\n"
        b"Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n\r\nBody"
    )
    envelope = _make_envelope(content)
    monkeypatch.setattr(
        main.config_resolver,
        "resolve_domain_context",
        lambda *args, **kwargs: config_resolver.DomainContext(None, None, None, None),
    )

    def send_fail(*_args, **_kwargs):
        return False, "err", 404

    monkeypatch.setattr(main.graph_client, "send_email", send_fail)
    response = asyncio.run(handler.handle_DATA(None, session, envelope))
    assert response == constants.SMTP_USER_NOT_LOCAL


def test_handle_data_send_email_failure_500(monkeypatch: pytest.MonkeyPatch) -> None:
    handler = main.Handler()
    session = types.SimpleNamespace(access_token="token", lookup_from_email=None)
    content = (
        b"From: sender@example.com\r\n"
        b"To: recipient@example.com\r\n"
        b"Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n\r\nBody"
    )
    envelope = _make_envelope(content)
    monkeypatch.setattr(
        main.config_resolver,
        "resolve_domain_context",
        lambda *args, **kwargs: config_resolver.DomainContext(None, None, None, None),
    )

    def send_fail(*_args, **_kwargs):
        return False, "err", 500

    monkeypatch.setattr(main.graph_client, "send_email", send_fail)
    response = asyncio.run(handler.handle_DATA(None, session, envelope))
    assert response == constants.SMTP_ACTION_ABORTED


def test_handle_data_failure_notification(monkeypatch: pytest.MonkeyPatch) -> None:
    handler = main.Handler()
    session = types.SimpleNamespace(access_token="token", lookup_from_email=None)
    content = (
        b"From: sender@example.com\r\n"
        b"To: recipient@example.com\r\n"
        b"Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n\r\nBody"
    )
    envelope = _make_envelope(content)
    context = config_resolver.DomainContext(
        domain="example.com",
        settings=None,
        failure_notification="ops@example.com",
        failback_address=None,
    )
    monkeypatch.setattr(
        main.config_resolver,
        "resolve_domain_context",
        lambda *args, **kwargs: context,
    )

    def send_fail(*_args, **_kwargs):
        return False, "err", 500

    monkeypatch.setattr(main.graph_client, "send_email", send_fail)
    captured = {}

    def fake_notify(**kwargs):
        captured["notification_address"] = kwargs["notification_address"]

    monkeypatch.setattr(main.graph_client, "send_failure_notification", fake_notify)
    response = asyncio.run(handler.handle_DATA(None, session, envelope))
    assert response == constants.SMTP_ACTION_ABORTED
    assert captured["notification_address"] == "ops@example.com"


def test_handle_data_exception(monkeypatch: pytest.MonkeyPatch) -> None:
    handler = main.Handler()
    session = types.SimpleNamespace(access_token="token", lookup_from_email=None)
    content = (
        b"From: sender@example.com\r\n"
        b"To: recipient@example.com\r\n"
        b"Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n\r\nBody"
    )
    envelope = _make_envelope(content)
    monkeypatch.setattr(
        main.config_resolver,
        "resolve_domain_context",
        lambda *args, **kwargs: config_resolver.DomainContext(None, None, None, None),
    )

    def raise_error(*_args, **_kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(main.graph_client, "send_email", raise_error)
    response = asyncio.run(handler.handle_DATA(None, session, envelope))
    assert response == constants.SMTP_TRANSACTION_FAILED


def test_handle_data_applies_failback_sender(monkeypatch: pytest.MonkeyPatch) -> None:
    handler = main.Handler()
    session = types.SimpleNamespace(access_token="token", lookup_from_email=None)
    content = b"Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n\r\nBody"
    envelope = _make_envelope(content, mail_from="<>")
    context = config_resolver.DomainContext(
        domain="example.com",
        settings=None,
        failure_notification=None,
        failback_address="failback@example.com",
    )
    monkeypatch.setattr(
        main.config_resolver,
        "resolve_domain_context",
        lambda *args, **kwargs: context,
    )
    captured = {}

    def fake_send_email(access_token, body, from_email):
        captured["body"] = body
        captured["from_email"] = from_email
        return True, None, 202

    monkeypatch.setattr(main.graph_client, "send_email", fake_send_email)
    response = asyncio.run(handler.handle_DATA(None, session, envelope))
    assert response == constants.SMTP_OK
    parsed = BytesParser(policy=policy.SMTP).parsebytes(captured["body"])
    assert parsed.get("From") == "failback@example.com"
    assert parsed.get("X-Sender") == "failback@example.com"


def test_handle_data_remap_and_lookup(monkeypatch: pytest.MonkeyPatch) -> None:
    handler = main.Handler()
    session = types.SimpleNamespace(access_token="token", lookup_from_email="lookup@example.com")
    content = (
        b"From: Sender <sender@example.com>\r\n"
        b"To: recipient@example.com\r\n"
        b"Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n\r\nBody"
    )
    envelope = _make_envelope(content)
    context = config_resolver.DomainContext(
        domain="example.com",
        settings=None,
        failure_notification=None,
        failback_address="failback@example.com",
    )
    monkeypatch.setattr(
        main.config_resolver,
        "resolve_domain_context",
        lambda *args, **kwargs: context,
    )
    def remap_enabled(*_args, **_kwargs):
        return True

    def remap_headers(*_args, **_kwargs):
        return {"To": "new@example.com"}

    def remap_list(*_args, **_kwargs):
        return ["new@example.com"]

    monkeypatch.setattr(remap, "is_remap_enabled", remap_enabled)
    monkeypatch.setattr(remap, "remap_recipient_headers", remap_headers)
    monkeypatch.setattr(remap, "remap_recipient_list", remap_list)
    captured = {}

    def fake_send_email(access_token, body, from_email):
        captured["body"] = body
        captured["from_email"] = from_email
        return True, None, 202

    monkeypatch.setattr(main.graph_client, "send_email", fake_send_email)
    response = asyncio.run(handler.handle_DATA(None, session, envelope))
    assert response == constants.SMTP_OK
    assert envelope.rcpt_tos == ["new@example.com"]
    parsed = BytesParser(policy=policy.SMTP).parsebytes(captured["body"])
    assert parsed.get("From") == "lookup@example.com"
    assert parsed.get("Reply-To") == "Sender <sender@example.com>"
    assert parsed.get("To") == "new@example.com"
    assert captured["from_email"] == "lookup@example.com"


def test_amain_tls_off(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeController:
        def __init__(self, *args, **kwargs):
            self.started = False

        def start(self):
            self.started = True

        def stop(self):
            pass

    monkeypatch.setattr(main, "CustomController", FakeController)
    monkeypatch.setattr(main.config, "TLS_SOURCE", "off")
    monkeypatch.setattr(main.config, "REQUIRE_TLS", False)
    monkeypatch.setattr(main.config, "SERVER_GREETING", "Test")

    asyncio.run(main.amain())


def test_amain_invalid_tls_source(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(main.config, "TLS_SOURCE", "nope")
    with pytest.raises(ValueError):
        asyncio.run(main.amain())


def test_amain_keyvault_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(main.config, "TLS_SOURCE", "keyvault")
    monkeypatch.setattr(main.config, "AZURE_KEY_VAULT_URL", None)
    monkeypatch.setattr(main.config, "AZURE_KEY_VAULT_CERT_NAME", None)
    with pytest.raises(ValueError):
        asyncio.run(main.amain())


def test_amain_keyvault_success(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeContext:
        def get_ciphers(self):
            return [{"name": "TLS_AES_128_GCM_SHA256"}]

    class FakeController:
        def __init__(self, *args, **kwargs):
            pass

        def start(self):
            return None

        def stop(self):
            return None

    monkeypatch.setattr(main.sslContext, "from_keyvault", lambda *_args, **_kwargs: FakeContext())
    monkeypatch.setattr(main, "CustomController", FakeController)
    monkeypatch.setattr(main.config, "TLS_SOURCE", "keyvault")
    monkeypatch.setattr(main.config, "AZURE_KEY_VAULT_URL", "https://vault")
    monkeypatch.setattr(main.config, "AZURE_KEY_VAULT_CERT_NAME", "cert")
    monkeypatch.setattr(main.config, "TLS_CIPHER_SUITE", None)
    monkeypatch.setattr(main.config, "REQUIRE_TLS", False)
    monkeypatch.setattr(main.config, "SERVER_GREETING", "Test")

    asyncio.run(main.amain())


def test_amain_tls_file_with_cipher(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeContext:
        def __init__(self):
            self.set_called = False

        def set_ciphers(self, _value):
            self.set_called = True

        def get_ciphers(self):
            return [{"name": "TLS_AES_128_GCM_SHA256"}]

    class FakeController:
        def __init__(self, *args, **kwargs):
            pass

        def start(self):
            return None

        def stop(self):
            return None

    monkeypatch.setattr(main.sslContext, "from_file", lambda *_args, **_kwargs: FakeContext())
    monkeypatch.setattr(main, "CustomController", FakeController)
    monkeypatch.setattr(main.config, "TLS_SOURCE", "file")
    monkeypatch.setattr(main.config, "TLS_CIPHER_SUITE", "TLS_AES_128_GCM_SHA256")
    monkeypatch.setattr(main.config, "REQUIRE_TLS", False)
    monkeypatch.setattr(main.config, "SERVER_GREETING", "Test")

    asyncio.run(main.amain())


def test_amain_start_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeController:
        def __init__(self, *args, **kwargs):
            pass

        def start(self):
            raise RuntimeError("boom")

        def stop(self):
            return None

    monkeypatch.setattr(main.sslContext, "from_file", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(main, "CustomController", FakeController)
    monkeypatch.setattr(main.config, "TLS_SOURCE", "file")
    monkeypatch.setattr(main.config, "REQUIRE_TLS", False)
    monkeypatch.setattr(main.config, "SERVER_GREETING", "Test")

    with pytest.raises(RuntimeError):
        asyncio.run(main.amain())
