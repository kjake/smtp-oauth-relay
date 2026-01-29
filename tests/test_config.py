import pytest

import config


def test_load_env_validation(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TEST_ENV", "yes")
    assert config.load_env("TEST_ENV", sanitize=str.lower) == "yes"
    monkeypatch.setenv("TEST_ENV", "bad")
    with pytest.raises(ValueError):
        config.load_env("TEST_ENV", valid_values=["good"])


def test_load_env_convert(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TEST_ENV_NUM", "5")
    assert config.load_env("TEST_ENV_NUM", convert=int) == 5
