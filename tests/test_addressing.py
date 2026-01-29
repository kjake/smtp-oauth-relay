import pytest

import addressing
import domain_settings


def test_parse_email_address_rejects_empty() -> None:
    assert addressing.parse_email_address("") is None
    assert addressing.parse_email_address("<>") is None
    assert addressing.parse_email_address("not-an-email") is None


def test_parse_email_address_accepts_valid() -> None:
    assert addressing.parse_email_address("User <user@example.com>") == "user@example.com"


def test_extract_domain_hint() -> None:
    assert addressing.extract_domain_hint("from <user@example.com>") == "example.com"
    assert addressing.extract_domain_hint(None, "nope") is None


def test_extract_domain_hint_normalizes_case() -> None:
    assert addressing.extract_domain_hint("User <USER@EXAMPLE.COM>") == "example.com"
    assert addressing.extract_domain_hint(None, "not an address") is None


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


def test_lookup_failure_notification_address_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = domain_settings.DomainSettings(
        from_remap=False,
        remap_addresses=set(),
        failure_notification="ops@example.com",
    )
    assert (
        addressing.lookup_failure_notification_address("example.com", settings)
        == "ops@example.com"
    )
    monkeypatch.setenv("EXAMPLE_COM_FAILURE_NOTIFICATION", "env@example.com")
    assert (
        addressing.lookup_failure_notification_address("example.com", settings)
        == "env@example.com"
    )


def test_to_failback_env_var_name() -> None:
    assert addressing.to_failback_env_var_name("example.com") == "EXAMPLE_COM_TO_FAILBACK"


def test_lookup_to_failback_address(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("EXAMPLE_COM_TO_FAILBACK", "postmaster@example.com")
    assert addressing.lookup_to_failback_address("example.com") == "postmaster@example.com"
    assert addressing.lookup_to_failback_address(None) is None


def test_normalize_bool_variants() -> None:
    assert addressing.normalize_bool(True) is True
    assert addressing.normalize_bool(False) is False
    assert addressing.normalize_bool(None) is None
    assert addressing.normalize_bool(" yes ") is True
    assert addressing.normalize_bool("0") is False
    assert addressing.normalize_bool("maybe") is None


def test_is_valid_smtp_mailbox_variants() -> None:
    assert addressing.is_valid_smtp_mailbox("<>", allow_null=True) is True
    assert addressing.is_valid_smtp_mailbox("user@example.com") is True
    assert addressing.is_valid_smtp_mailbox("user@[127.0.0.1]") is True
    assert addressing.is_valid_smtp_mailbox("not-an-email") is False
    assert addressing.is_valid_smtp_mailbox("user@@example.com") is False
    assert addressing.is_valid_smtp_mailbox("user<@example.com") is False
    assert addressing.is_valid_smtp_mailbox("a" * 65 + "@example.com") is False
    assert addressing.is_valid_smtp_mailbox("user@" + ("b" * 64) + ".com") is False
