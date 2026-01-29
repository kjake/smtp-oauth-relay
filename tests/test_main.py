import base64
import types
import uuid
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser

import pytest

import addressing
import auth
import domain_settings
import graph_client
import main
import message_utils
import remap


def test_parse_email_address_rejects_empty() -> None:
    assert addressing.parse_email_address("") is None
    assert addressing.parse_email_address("<>") is None
    assert addressing.parse_email_address("not-an-email") is None


def test_parse_email_address_accepts_valid() -> None:
    assert addressing.parse_email_address("User <user@example.com>") == "user@example.com"


def test_extract_domain_hint() -> None:
    assert addressing.extract_domain_hint("from <user@example.com>") == "example.com"
    assert addressing.extract_domain_hint(None, "nope") is None


def test_failback_env_var_name() -> None:
    assert addressing.failback_env_var_name("example.com") == "EXAMPLE_COM_FROM_FAILBACK"


def test_lookup_failback_address(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("EXAMPLE_COM_FROM_FAILBACK", "noreply@example.com")
    assert addressing.lookup_failback_address("example.com") == "noreply@example.com"
    assert addressing.lookup_failback_address(None) is None


def test_failure_notification_env_var_name() -> None:
    assert (
        addressing.failure_notification_env_var_name("example.com")
        == "EXAMPLE_COM_FAILURE_NOTIFICATION"
    )


def test_lookup_failure_notification_address(monkeypatch: pytest.MonkeyPatch) -> None:
    domain = "example.com"
    monkeypatch.setenv("EXAMPLE_COM_FAILURE_NOTIFICATION", "alert@example.com")
    assert addressing.lookup_failure_notification_address(domain, None) == "alert@example.com"


def test_to_failback_env_var_name() -> None:
    assert addressing.to_failback_env_var_name("example.com") == "EXAMPLE_COM_TO_FAILBACK"


def test_lookup_to_failback_address(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("EXAMPLE_COM_TO_FAILBACK", "postmaster@example.com")
    assert addressing.lookup_to_failback_address("example.com") == "postmaster@example.com"
    assert addressing.lookup_to_failback_address(None) is None


def test_decode_uuid_or_base64url_roundtrip() -> None:
    value = uuid.uuid4()
    encoded = base64.urlsafe_b64encode(value.bytes).decode().rstrip("=")
    assert auth.decode_uuid_or_base64url(str(value)) == str(value)
    assert auth.decode_uuid_or_base64url(encoded) == str(value)


def test_decode_uuid_or_base64url_invalid() -> None:
    with pytest.raises(ValueError):
        auth.decode_uuid_or_base64url("not-base64")


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


def test_update_raw_headers_replaces_existing() -> None:
    raw = b"From: old@example.com\r\nSubject: Test\r\n\r\nBody"
    updated = message_utils.update_raw_headers(raw, {"From": "new@example.com", "X-Test": "yes"})
    assert b"From: old@example.com" not in updated
    assert b"From: new@example.com" in updated
    assert b"X-Test: yes" in updated


def test_build_reply_to_value_appends() -> None:
    existing = "ops@example.com"
    original = "Group <group@example.com>"
    reply_to = message_utils.build_reply_to_value(existing, original)
    assert reply_to == "ops@example.com, Group <group@example.com>"


def test_is_remap_enabled_checks_env_and_table(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(remap, "FROM_REMAP_DOMAINS", {"example.com"})
    monkeypatch.setattr(remap, "FROM_REMAP_ADDRESSES", {"accounting@example.com"})
    assert remap.is_remap_enabled("example.com", None, None)
    assert remap.is_remap_enabled("other.com", None, "accounting@example.com")
    settings = domain_settings.DomainSettings(
        from_remap=True,
        remap_addresses={"ops@example.com"},
        failure_notification=None
    )
    assert remap.is_remap_enabled("other.com", settings, None)
    assert remap.is_remap_enabled("other.com", settings, "ops@example.com")


def test_is_recipient_remap_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(remap, "TO_REMAP_DOMAINS", {"example.com"})
    monkeypatch.setattr(remap, "TO_REMAP_ADDRESSES", {"postmaster@example.com"})
    assert remap.is_recipient_remap_enabled("postmaster@example.com")
    assert remap.is_recipient_remap_enabled("user@example.com")
    assert not remap.is_recipient_remap_enabled("user@other.com")


def test_remap_recipient_headers(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(remap, "TO_REMAP_DOMAINS", {"example.com"})
    monkeypatch.setattr(remap, "TO_REMAP_ADDRESSES", set())
    monkeypatch.setenv("EXAMPLE_COM_TO_FAILBACK", "postmaster@example.com")

    message = EmailMessage()
    message["To"] = "User <user@example.com>, other@other.com"
    updates = remap.remap_recipient_headers(message)
    assert updates["To"] == "User <postmaster@example.com>, other@other.com"


def test_remap_recipient_list(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(remap, "TO_REMAP_DOMAINS", {"example.com"})
    monkeypatch.setattr(remap, "TO_REMAP_ADDRESSES", set())
    monkeypatch.setenv("EXAMPLE_COM_TO_FAILBACK", "postmaster@example.com")

    recipients = remap.remap_recipient_list(["user@example.com", "user@example.com"])
    assert recipients == ["postmaster@example.com"]


def test_lookup_user_success(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(auth, "AZURE_TABLES_URL", "https://example.com/table")

    class FakeClient:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def query_entities(self, query_filter):
            return iter([
                {
                    "tenant_id": "tenant",
                    "client_id": "client",
                    "from_email": "sender@example.com",
                }
            ])

    monkeypatch.setattr(auth, "DefaultAzureCredential", lambda: object())
    monkeypatch.setattr(auth.TableClient, "from_table_url", lambda *args, **kwargs: FakeClient())

    tenant_id, client_id, from_email = auth.lookup_user("lookup")
    assert tenant_id == "tenant"
    assert client_id == "client"
    assert from_email == "sender@example.com"


def test_parse_username_lookup(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(auth, "USERNAME_DELIMITER", "@")
    monkeypatch.setattr(
        auth,
        "lookup_user",
        lambda lookup_id: ("tenant", "client", "from@example.com"),
    )
    tenant_id, client_id, from_email = auth.parse_username("app@lookup")
    assert tenant_id == "tenant"
    assert client_id == "client"
    assert from_email == "from@example.com"


def test_parse_username_base64(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(auth, "USERNAME_DELIMITER", "@")
    tenant_uuid = uuid.uuid4()
    client_uuid = uuid.uuid4()
    tenant_b64 = base64.urlsafe_b64encode(tenant_uuid.bytes).decode().rstrip("=")
    client_b64 = base64.urlsafe_b64encode(client_uuid.bytes).decode().rstrip("=")
    tenant_id, client_id, from_email = auth.parse_username(f"{tenant_b64}@{client_b64}.local")
    assert tenant_id == str(tenant_uuid)
    assert client_id == str(client_uuid)
    assert from_email is None


def test_get_access_token(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeResponse:
        def raise_for_status(self):
            return None

        def json(self):
            return {"access_token": "token"}

    monkeypatch.setattr(auth.requests, "post", lambda *args, **kwargs: FakeResponse())
    assert auth.get_access_token("tenant", "client", "secret") == "token"


def test_send_email_success(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeResponse:
        status_code = 202
        text = ""

    monkeypatch.setattr(graph_client.requests, "post", lambda *args, **kwargs: FakeResponse())
    assert graph_client.send_email("token", b"Body", "user@example.com") == (True, None, 202)


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


def test_authenticator_success(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(auth, "parse_username", lambda _: ("tenant", "client", None))
    monkeypatch.setattr(auth, "get_access_token", lambda *args, **kwargs: "token")

    session = types.SimpleNamespace()
    auth_data = types.SimpleNamespace(login=b"user", password=b"secret")

    result = auth.Authenticator()(None, session, None, "LOGIN", auth_data)
    assert result.success is True
    assert session.access_token == "token"


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


def test_handle_mail_rejects_invalid_sender() -> None:
    handler = main.Handler()
    response = __import__("asyncio").run(
        handler.handle_MAIL(None, None, None, "invalid address", [])
    )
    assert response.startswith("553")


def test_handle_rcpt_rejects_null_recipient() -> None:
    handler = main.Handler()
    response = __import__("asyncio").run(
        handler.handle_RCPT(None, None, None, "<>", [])
    )
    assert response.startswith("553")


def test_validate_rfc5322_requires_date() -> None:
    raw_message = b"From: sender@example.com\r\n\r\nBody"
    assert message_utils.validate_rfc5322_message(raw_message).startswith("554")


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
