import sys
import types
from pathlib import Path
from types import ModuleType

import pytest

import sslContext


def test_ssl_from_file_loads_cert(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cert_path = tmp_path / "cert.pem"
    key_path = tmp_path / "key.pem"
    cert_path.write_text("cert", encoding="utf-8")
    key_path.write_text("key", encoding="utf-8")

    class FakeContext:
        def __init__(self):
            self.loaded = None

        def load_cert_chain(self, certfile, keyfile):
            self.loaded = (certfile, keyfile)

    monkeypatch.setattr(
        sslContext.ssl,
        "create_default_context",
        lambda *_args, **_kwargs: FakeContext()
    )
    context = sslContext.from_file(str(cert_path), str(key_path))
    assert context.loaded == (str(cert_path), str(key_path))


def test_ssl_from_file_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(FileNotFoundError):
        sslContext.from_file("/nope/cert.pem", "/nope/key.pem")


def test_ssl_from_file_bad_key(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cert_path = tmp_path / "cert.pem"
    key_path = tmp_path / "key.pem"
    cert_path.write_text("cert", encoding="utf-8")
    key_path.write_text("key", encoding="utf-8")

    class FakeContext:
        def load_cert_chain(self, certfile, keyfile):
            raise sslContext.ssl.SSLError("bad")

    monkeypatch.setattr(
        sslContext.ssl,
        "create_default_context",
        lambda *_args, **_kwargs: FakeContext()
    )
    with pytest.raises(sslContext.ssl.SSLError):
        sslContext.from_file(str(cert_path), str(key_path))


def test_ssl_from_keyvault_success(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeSecret:
        value = "dGVzdA=="

    class FakeClient:
        def __init__(self, *args, **kwargs):
            pass

        def get_secret(self, name):
            return FakeSecret()

    class FakeKey:
        def private_bytes(self, **_kwargs):
            return b"key"

    class FakeCert:
        def public_bytes(self, *_args, **_kwargs):
            return b"cert"

    fake_identity = ModuleType("azure.identity")
    fake_identity.DefaultAzureCredential = lambda: object()
    fake_secrets = ModuleType("azure.keyvault.secrets")
    fake_secrets.SecretClient = FakeClient
    fake_serialization = ModuleType("cryptography.hazmat.primitives.serialization")
    fake_serialization.Encoding = types.SimpleNamespace(PEM=b"pem")
    fake_serialization.NoEncryption = lambda: None
    fake_serialization.PrivateFormat = types.SimpleNamespace(TraditionalOpenSSL=object())
    fake_serialization.pkcs12 = types.SimpleNamespace(
        load_key_and_certificates=lambda *_args, **_kwargs: (FakeKey(), FakeCert(), None)
    )
    serialization_key = "cryptography.hazmat.primitives.serialization"
    monkeypatch.setitem(sys.modules, "azure.identity", fake_identity)
    monkeypatch.setitem(sys.modules, "azure.keyvault.secrets", fake_secrets)
    monkeypatch.setitem(sys.modules, serialization_key, fake_serialization)

    class FakeContext:
        def load_cert_chain(self, certfile, keyfile):
            pass

    monkeypatch.setattr(
        sslContext.ssl,
        "create_default_context",
        lambda *_args, **_kwargs: FakeContext()
    )
    sslContext.from_keyvault("https://vault", "cert")


def test_ssl_from_keyvault_missing_cert(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeSecret:
        value = "dGVzdA=="

    class FakeClient:
        def __init__(self, *args, **kwargs):
            pass

        def get_secret(self, name):
            return FakeSecret()

    fake_identity = ModuleType("azure.identity")
    fake_identity.DefaultAzureCredential = lambda: object()
    fake_secrets = ModuleType("azure.keyvault.secrets")
    fake_secrets.SecretClient = FakeClient
    fake_serialization = ModuleType("cryptography.hazmat.primitives.serialization")
    fake_serialization.Encoding = types.SimpleNamespace(PEM=b"pem")
    fake_serialization.NoEncryption = lambda: None
    fake_serialization.PrivateFormat = types.SimpleNamespace(TraditionalOpenSSL=object())
    fake_serialization.pkcs12 = types.SimpleNamespace(
        load_key_and_certificates=lambda *_args, **_kwargs: (None, None, None)
    )
    serialization_key = "cryptography.hazmat.primitives.serialization"
    monkeypatch.setitem(sys.modules, "azure.identity", fake_identity)
    monkeypatch.setitem(sys.modules, "azure.keyvault.secrets", fake_secrets)
    monkeypatch.setitem(sys.modules, serialization_key, fake_serialization)

    with pytest.raises(ValueError):
        sslContext.from_keyvault("https://vault", "cert")


def test_ssl_from_keyvault_missing_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeClient:
        def __init__(self, *args, **kwargs):
            pass

        def get_secret(self, name):
            return types.SimpleNamespace(value=None)

    fake_identity = ModuleType("azure.identity")
    fake_identity.DefaultAzureCredential = lambda: object()
    fake_secrets = ModuleType("azure.keyvault.secrets")
    fake_secrets.SecretClient = FakeClient
    fake_serialization = ModuleType("cryptography.hazmat.primitives.serialization")
    fake_serialization.Encoding = types.SimpleNamespace(PEM=b"pem")
    fake_serialization.NoEncryption = lambda: None
    fake_serialization.PrivateFormat = types.SimpleNamespace(TraditionalOpenSSL=object())
    fake_serialization.pkcs12 = types.SimpleNamespace(
        load_key_and_certificates=lambda *_args, **_kwargs: (None, None, None)
    )
    serialization_key = "cryptography.hazmat.primitives.serialization"

    monkeypatch.setitem(sys.modules, "azure.identity", fake_identity)
    monkeypatch.setitem(sys.modules, "azure.keyvault.secrets", fake_secrets)
    monkeypatch.setitem(sys.modules, serialization_key, fake_serialization)

    with pytest.raises(ValueError):
        sslContext.from_keyvault("https://vault", "cert")


def test_ssl_from_keyvault_pkcs12_error(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeSecret:
        value = "dGVzdA=="

    class FakeClient:
        def __init__(self, *args, **kwargs):
            pass

        def get_secret(self, name):
            return FakeSecret()

    fake_identity = ModuleType("azure.identity")
    fake_identity.DefaultAzureCredential = lambda: object()
    fake_secrets = ModuleType("azure.keyvault.secrets")
    fake_secrets.SecretClient = FakeClient
    fake_serialization = ModuleType("cryptography.hazmat.primitives.serialization")
    fake_serialization.pkcs12 = types.SimpleNamespace(
        load_key_and_certificates=lambda *_args, **_kwargs: (_ for _ in ()).throw(ValueError("bad"))
    )
    fake_serialization.Encoding = types.SimpleNamespace(PEM=b"pem")
    fake_serialization.NoEncryption = lambda: None
    fake_serialization.PrivateFormat = types.SimpleNamespace(TraditionalOpenSSL=object())

    serialization_key = "cryptography.hazmat.primitives.serialization"
    monkeypatch.setitem(sys.modules, "azure.identity", fake_identity)
    monkeypatch.setitem(sys.modules, "azure.keyvault.secrets", fake_secrets)
    monkeypatch.setitem(sys.modules, serialization_key, fake_serialization)

    with pytest.raises(ValueError):
        sslContext.from_keyvault("https://vault", "cert")


def test_ssl_from_keyvault_missing_private_key(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeSecret:
        value = "dGVzdA=="

    class FakeClient:
        def __init__(self, *args, **kwargs):
            pass

        def get_secret(self, name):
            return FakeSecret()

    class FakeCert:
        def public_bytes(self, *_args, **_kwargs):
            return b"cert"

    fake_identity = ModuleType("azure.identity")
    fake_identity.DefaultAzureCredential = lambda: object()
    fake_secrets = ModuleType("azure.keyvault.secrets")
    fake_secrets.SecretClient = FakeClient
    fake_serialization = ModuleType("cryptography.hazmat.primitives.serialization")
    fake_serialization.Encoding = types.SimpleNamespace(PEM=b"pem")
    fake_serialization.NoEncryption = lambda: None
    fake_serialization.PrivateFormat = types.SimpleNamespace(TraditionalOpenSSL=object())
    fake_serialization.pkcs12 = types.SimpleNamespace(
        load_key_and_certificates=lambda *_args, **_kwargs: (None, FakeCert(), None)
    )
    serialization_key = "cryptography.hazmat.primitives.serialization"
    monkeypatch.setitem(sys.modules, "azure.identity", fake_identity)
    monkeypatch.setitem(sys.modules, "azure.keyvault.secrets", fake_secrets)
    monkeypatch.setitem(sys.modules, serialization_key, fake_serialization)

    with pytest.raises(ValueError):
        sslContext.from_keyvault("https://vault", "cert")


def test_ssl_from_keyvault_cleanup_warning(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    class FakeSecret:
        value = "dGVzdA=="

    class FakeClient:
        def __init__(self, *args, **kwargs):
            pass

        def get_secret(self, name):
            return FakeSecret()

    class FakeKey:
        def private_bytes(self, **_kwargs):
            return b"key"

    class FakeCert:
        def public_bytes(self, *_args, **_kwargs):
            return b"cert"

    fake_identity = ModuleType("azure.identity")
    fake_identity.DefaultAzureCredential = lambda: object()
    fake_secrets = ModuleType("azure.keyvault.secrets")
    fake_secrets.SecretClient = FakeClient
    fake_serialization = ModuleType("cryptography.hazmat.primitives.serialization")
    fake_serialization.Encoding = types.SimpleNamespace(PEM=b"pem")
    fake_serialization.NoEncryption = lambda: None
    fake_serialization.PrivateFormat = types.SimpleNamespace(TraditionalOpenSSL=object())
    fake_serialization.pkcs12 = types.SimpleNamespace(
        load_key_and_certificates=lambda *_args, **_kwargs: (FakeKey(), FakeCert(), None)
    )
    serialization_key = "cryptography.hazmat.primitives.serialization"
    monkeypatch.setitem(sys.modules, "azure.identity", fake_identity)
    monkeypatch.setitem(sys.modules, "azure.keyvault.secrets", fake_secrets)
    monkeypatch.setitem(sys.modules, serialization_key, fake_serialization)

    class FakeContext:
        def load_cert_chain(self, certfile, keyfile):
            pass

    monkeypatch.setattr(
        sslContext.ssl,
        "create_default_context",
        lambda *_args, **_kwargs: FakeContext()
    )

    def fail_unlink(_path):
        raise OSError("nope")

    monkeypatch.setattr(sslContext.os, "unlink", fail_unlink)
    with caplog.at_level("WARNING"):
        sslContext.from_keyvault("https://vault", "cert")
    assert "Failed to remove temporary certificate file" in caplog.text


def test_ssl_from_file_not_file(tmp_path: Path) -> None:
    cert_path = tmp_path / "cert_dir"
    key_path = tmp_path / "key.pem"
    cert_path.mkdir()
    key_path.write_text("key", encoding="utf-8")
    with pytest.raises(FileNotFoundError):
        sslContext.from_file(str(cert_path), str(key_path))

def test_ssl_logging_helpers() -> None:
    sslContext.log_loaded_certificate_from_file("cert.pem")
    sslContext.log_loaded_certificate_from_keyvault("cert")
    sslContext.log_invalid_tls_source("invalid")
    sslContext.log_missing_keyvault_config()
    sslContext.log_tls_cipher_suites("TLS_AES_128_GCM_SHA256")
