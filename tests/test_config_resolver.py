import pytest

import config_resolver
import domain_settings


def test_resolve_domain_context_no_hint() -> None:
    context = config_resolver.resolve_domain_context(None, "nope")
    assert context.domain is None
    assert context.settings is None
    assert context.failure_notification is None
    assert context.failback_address is None


def test_resolve_domain_context_prefers_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("EXAMPLE_COM_FAILURE_NOTIFICATION", "env@example.com")
    monkeypatch.setenv("EXAMPLE_COM_FROM_FAILBACK", "failback@example.com")

    settings = domain_settings.DomainSettings(
        from_remap=False,
        remap_addresses=set(),
        failure_notification="table@example.com",
    )
    monkeypatch.setattr(
        config_resolver.domain_settings,
        "lookup_domain_settings",
        lambda domain: settings,
    )

    context = config_resolver.resolve_domain_context("From: user@example.com")
    assert context.domain == "example.com"
    assert context.settings == settings
    assert context.failure_notification == "env@example.com"
    assert context.failback_address == "failback@example.com"
