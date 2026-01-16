import base64
import types
import uuid

import pytest

import main


def test_parse_email_address_rejects_empty() -> None:
    assert main.parse_email_address("") is None
    assert main.parse_email_address("<>") is None
    assert main.parse_email_address("not-an-email") is None


def test_parse_email_address_accepts_valid() -> None:
    assert main.parse_email_address("User <user@example.com>") == "user@example.com"


def test_extract_domain_hint() -> None:
    assert main.extract_domain_hint("from <user@example.com>") == "example.com"
    assert main.extract_domain_hint(None, "nope") is None


def test_failback_env_var_name() -> None:
    assert main.failback_env_var_name("example.com") == "EXAMPLE_COM_FROM_FAILBACK"


def test_lookup_failback_address(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("EXAMPLE_COM_FROM_FAILBACK", "noreply@example.com")
    assert main.lookup_failback_address("example.com") == "noreply@example.com"
    assert main.lookup_failback_address(None) is None


def test_decode_uuid_or_base64url_roundtrip() -> None:
    value = uuid.uuid4()
    encoded = base64.urlsafe_b64encode(value.bytes).decode().rstrip("=")
    assert main.decode_uuid_or_base64url(str(value)) == str(value)
    assert main.decode_uuid_or_base64url(encoded) == str(value)


def test_decode_uuid_or_base64url_invalid() -> None:
    with pytest.raises(ValueError):
        main.decode_uuid_or_base64url("not-base64")


def test_split_raw_message_variants() -> None:
    header, separator, body = main.split_raw_message(b"Subject: Hi\r\n\r\nBody")
    assert header == b"Subject: Hi"
    assert separator == b"\r\n\r\n"
    assert body == b"Body"

    header, separator, body = main.split_raw_message(b"Subject: Hi\n\nBody")
    assert header == b"Subject: Hi"
    assert separator == b"\n\n"
    assert body == b"Body"

    header, separator, body = main.split_raw_message(b"Body only")
    assert header == b"Body only"
    assert separator == b""
    assert body == b""


def test_update_raw_headers_replaces_existing() -> None:
    raw = b"From: old@example.com\r\nSubject: Test\r\n\r\nBody"
    updated = main.update_raw_headers(raw, {"From": "new@example.com", "X-Test": "yes"})
    assert b"From: old@example.com" not in updated
    assert b"From: new@example.com" in updated
    assert b"X-Test: yes" in updated


def test_parse_dkim_canonicalization() -> None:
    header, body = main.parse_dkim_canonicalization("relaxed/simple")
    assert header == b"relaxed"
    assert body == b"simple"

    with pytest.raises(ValueError):
        main.parse_dkim_canonicalization("invalid")


def test_normalize_dkim_private_key() -> None:
    key = """-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----"""
    assert main.normalize_dkim_private_key(key) == key

    with pytest.raises(ValueError):
        main.normalize_dkim_private_key("not a key")


def test_read_dkim_private_key_from_path(tmp_path) -> None:
    key_path = tmp_path / "key.pem"
    key_path.write_text("-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----", encoding="utf-8")
    assert "PRIVATE KEY" in main.read_dkim_private_key_from_path(str(key_path))

    with pytest.raises(ValueError):
        main.read_dkim_private_key_from_path(str(tmp_path / "missing.pem"))


def test_build_dkim_config_from_private_key() -> None:
    config = main.build_dkim_config(
        selector="relay",
        private_key="-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----",
        private_key_path=None,
        canonicalization="relaxed/relaxed",
        headers=["from"],
        source="test"
    )
    assert config.selector == "relay"
    assert config.source == "test"


def test_initialize_dkim_config_respects_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(main, "DKIM_ENABLED", False)
    monkeypatch.setattr(main, "DKIM_SELECTOR", None)
    monkeypatch.setattr(main, "DKIM_PRIVATE_KEY", None)
    monkeypatch.setattr(main, "DKIM_PRIVATE_KEY_PATH", None)
    main.initialize_dkim_config()
    assert main.DKIM_DEFAULT_CONFIG is None


def test_get_dkim_config_for_sender_returns_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(main, "DKIM_ENABLED", True)
    config = main.DkimConfig(
        selector="relay",
        private_key="-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----",
        canonicalization="relaxed/relaxed",
        headers=["from"],
        source="environment"
    )
    monkeypatch.setattr(main, "DKIM_DEFAULT_CONFIG", config)
    monkeypatch.setattr(main, "lookup_dkim_config", lambda domain: None)
    assert main.get_dkim_config_for_sender("user@example.com") == config


def test_sign_raw_message_with_dkim(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_sign(**kwargs):
        return b"DKIM-Signature: test\n\tvalue\n"

    monkeypatch.setattr(main.dkim, "sign", lambda **kwargs: fake_sign(**kwargs))
    raw = b"Received: by mx.example.com\nFrom: user@example.com\nSubject: Hi\n\nBody"
    signed = main.sign_raw_message_with_dkim(
        raw_message=raw,
        from_email="user@example.com",
        selector="relay",
        private_key="-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----",
        canonicalization="relaxed/relaxed",
        header_list=["from", "subject"]
    )
    header_block = signed.split(b"\r\n\r\n", 1)[0]
    header_lines = header_block.split(b"\r\n")
    assert header_lines[0] == b"DKIM-Signature: test"
    assert header_lines[1].startswith(b"\t")
    assert header_lines[2].startswith(b"Received:")


def test_lookup_user_success(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(main, "AZURE_TABLES_URL", "https://example.com/table")

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

    monkeypatch.setattr(main, "DefaultAzureCredential", lambda: object())
    monkeypatch.setattr(main.TableClient, "from_table_url", lambda *args, **kwargs: FakeClient())

    tenant_id, client_id, from_email = main.lookup_user("lookup")
    assert tenant_id == "tenant"
    assert client_id == "client"
    assert from_email == "sender@example.com"


def test_parse_username_lookup(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(main, "USERNAME_DELIMITER", "@")
    monkeypatch.setattr(main, "lookup_user", lambda lookup_id: ("tenant", "client", "from@example.com"))
    tenant_id, client_id, from_email = main.parse_username("app@lookup")
    assert tenant_id == "tenant"
    assert client_id == "client"
    assert from_email == "from@example.com"


def test_parse_username_base64(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(main, "USERNAME_DELIMITER", "@")
    tenant_uuid = uuid.uuid4()
    client_uuid = uuid.uuid4()
    tenant_b64 = base64.urlsafe_b64encode(tenant_uuid.bytes).decode().rstrip("=")
    client_b64 = base64.urlsafe_b64encode(client_uuid.bytes).decode().rstrip("=")
    tenant_id, client_id, from_email = main.parse_username(f"{tenant_b64}@{client_b64}.local")
    assert tenant_id == str(tenant_uuid)
    assert client_id == str(client_uuid)
    assert from_email is None


def test_get_access_token(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeResponse:
        def raise_for_status(self):
            return None

        def json(self):
            return {"access_token": "token"}

    monkeypatch.setattr(main.requests, "post", lambda *args, **kwargs: FakeResponse())
    assert main.get_access_token("tenant", "client", "secret") == "token"


def test_send_email_success(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeResponse:
        status_code = 202
        text = ""

    monkeypatch.setattr(main.requests, "post", lambda *args, **kwargs: FakeResponse())
    assert main.send_email("token", b"Body", "user@example.com") is True


def test_authenticator_success(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(main, "parse_username", lambda _: ("tenant", "client", None))
    monkeypatch.setattr(main, "get_access_token", lambda *args, **kwargs: "token")

    session = types.SimpleNamespace()
    auth_data = types.SimpleNamespace(login=b"user", password=b"secret")

    result = main.Authenticator()(None, session, None, "LOGIN", auth_data)
    assert result.success is True
    assert session.access_token == "token"


def test_handler_requires_auth_token() -> None:
    handler = main.Handler()
    session = types.SimpleNamespace()
    envelope = types.SimpleNamespace(
        mail_from="sender@example.com",
        rcpt_tos=["recipient@example.com"],
        content=b"From: sender@example.com\r\nTo: recipient@example.com\r\n\r\nBody"
    )
    response = __import__("asyncio").run(handler.handle_DATA(None, session, envelope))
    assert response.startswith("530")


def test_handler_sends_email(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(main, "send_email", lambda *args, **kwargs: True)
    monkeypatch.setattr(main, "DKIM_ENABLED", False)

    handler = main.Handler()
    session = types.SimpleNamespace(access_token="token", lookup_from_email=None)
    envelope = types.SimpleNamespace(
        mail_from="sender@example.com",
        rcpt_tos=["recipient@example.com"],
        content=b"From: sender@example.com\r\nTo: recipient@example.com\r\n\r\nBody"
    )
    response = __import__("asyncio").run(handler.handle_DATA(None, session, envelope))
    assert response == "250 OK"
