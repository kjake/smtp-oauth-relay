import base64
import types
import uuid

import pytest

import auth
import constants


def test_decode_uuid_or_base64url_roundtrip() -> None:
    value = uuid.uuid4()
    encoded = base64.urlsafe_b64encode(value.bytes).decode().rstrip("=")
    assert auth.decode_uuid_or_base64url(str(value)) == str(value)
    assert auth.decode_uuid_or_base64url(encoded) == str(value)


def test_decode_uuid_or_base64url_invalid() -> None:
    with pytest.raises(ValueError):
        auth.decode_uuid_or_base64url("not-base64")


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


def test_lookup_user_missing_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(auth, "AZURE_TABLES_URL", None)
    with pytest.raises(ValueError):
        auth.lookup_user("missing")


def test_lookup_user_table_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(auth, "AZURE_TABLES_URL", "https://example.com/table")

    def raise_client(*_args, **_kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(auth.TableClient, "from_table_url", raise_client)
    with pytest.raises(RuntimeError):
        auth.lookup_user("missing")


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


def test_parse_username_invalid() -> None:
    with pytest.raises(ValueError):
        auth.parse_username("invalid")
    with pytest.raises(ValueError):
        auth.parse_username("too@many@parts")


def test_get_access_token(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeResponse:
        def raise_for_status(self):
            return None

        def json(self):
            return {"access_token": "token"}

    monkeypatch.setattr(auth.requests, "post", lambda *args, **kwargs: FakeResponse())
    assert auth.get_access_token("tenant", "client", "secret") == "token"


def test_get_access_token_missing_token(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeResponse:
        def raise_for_status(self):
            return None

        def json(self):
            return {}

    monkeypatch.setattr(auth.requests, "post", lambda *args, **kwargs: FakeResponse())
    with pytest.raises(ValueError):
        auth.get_access_token("tenant", "client", "secret")


def test_get_access_token_request_exception(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeResponse:
        status_code = 500
        text = "nope"

    class FakeException(auth.requests.RequestException):
        def __init__(self):
            super().__init__("boom")
            self.response = FakeResponse()

    def raise_request(*_args, **_kwargs):
        raise FakeException()

    monkeypatch.setattr(auth.requests, "post", raise_request)
    with pytest.raises(auth.requests.RequestException):
        auth.get_access_token("tenant", "client", "secret")


def test_authenticator_success(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(auth, "parse_username", lambda _: ("tenant", "client", None))
    monkeypatch.setattr(auth, "get_access_token", lambda *args, **kwargs: "token")

    session = types.SimpleNamespace()
    auth_data = types.SimpleNamespace(login=b"user", password=b"secret")

    result = auth.Authenticator()(None, session, None, "LOGIN", auth_data)
    assert result.success is True
    assert session.access_token == "token"


def test_authenticator_plain_success(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(auth, "parse_username", lambda _: ("tenant", "client", None))
    monkeypatch.setattr(auth, "get_access_token", lambda *args, **kwargs: "token")

    session = types.SimpleNamespace()
    auth_data = types.SimpleNamespace(login=b"user", password=b"secret")
    result = auth.Authenticator()(None, session, None, "PLAIN", auth_data)
    assert result.success is True
    assert session.access_token == "token"


def test_authenticator_error_paths(monkeypatch: pytest.MonkeyPatch) -> None:
    authenticator = auth.Authenticator()
    session = types.SimpleNamespace()

    result = authenticator(
        None,
        session,
        None,
        "CRAM",
        types.SimpleNamespace(login=b"u", password=b"p")
    )
    assert result.message == constants.AUTH_UNSUPPORTED_MECHANISM

    result = authenticator(None, session, None, "LOGIN", None)
    assert result.message == constants.AUTH_CREDENTIALS_MISSING

    auth_data = types.SimpleNamespace(login=b"\xff", password=b"p")
    result = authenticator(None, session, None, "LOGIN", auth_data)
    assert result.message == constants.AUTH_INVALID_ENCODING

    def raise_value(_):
        raise ValueError("bad username")

    monkeypatch.setattr(auth, "parse_username", raise_value)
    auth_data = types.SimpleNamespace(login=b"u", password=b"p")
    result = authenticator(None, session, None, "LOGIN", auth_data)
    assert result.message == "535 5.7.8 bad username"

    def raise_runtime(_):
        raise RuntimeError("boom")

    monkeypatch.setattr(auth, "parse_username", raise_runtime)
    result = authenticator(None, session, None, "LOGIN", auth_data)
    assert result.message == constants.AUTH_UNEXPECTED_ERROR

    monkeypatch.setattr(auth, "parse_username", lambda _: ("tenant", "client", None))

    def raise_token(*_args, **_kwargs):
        raise RuntimeError("no token")

    monkeypatch.setattr(auth, "get_access_token", raise_token)
    result = authenticator(None, session, None, "LOGIN", auth_data)
    assert result.message == constants.AUTH_FAILED
