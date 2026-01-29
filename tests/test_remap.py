from email.message import EmailMessage

import pytest

import domain_settings
import remap


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


def test_remap_recipient_address_missing_failback(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(remap, "TO_REMAP_DOMAINS", {"example.com"})
    monkeypatch.setattr(remap, "TO_REMAP_ADDRESSES", set())
    monkeypatch.setattr(remap, "lookup_to_failback_address", lambda _domain: None)
    assert remap.remap_recipient_address("user@example.com") is None


def test_remap_recipient_address_invalid() -> None:
    assert remap.remap_recipient_address("not-an-address") is None
