import runpy

import pytest

import relay_logging


def _run_entrypoint(
    monkeypatch: pytest.MonkeyPatch,
    exc: Exception,
) -> dict[str, bool]:
    called = {
        "shutdown": False,
        "unexpected": False,
        "shutting_down": False,
        "cancelled": False,
    }

    class FakeTask:
        def cancel(self):
            called["cancelled"] = True

    class FakeLoop:
        def create_task(self, coro):
            coro.close()
            return object()

        def run_forever(self):
            raise exc

        def close(self):
            return None

    def log_shutdown():
        called["shutdown"] = True

    def log_unexpected(*_args):
        called["unexpected"] = True

    def log_shutting_down():
        called["shutting_down"] = True

    monkeypatch.setattr(relay_logging, "log_shutdown_requested", log_shutdown)
    monkeypatch.setattr(relay_logging, "log_unexpected_error", log_unexpected)
    monkeypatch.setattr(relay_logging, "log_shutting_down", log_shutting_down)

    import asyncio

    monkeypatch.setattr(asyncio, "new_event_loop", lambda: FakeLoop())
    monkeypatch.setattr(asyncio, "set_event_loop", lambda _loop: None)
    monkeypatch.setattr(asyncio, "all_tasks", lambda _loop: [FakeTask()])

    runpy.run_module("main", run_name="__main__")
    return called


def test_main_entrypoint_keyboard_interrupt(monkeypatch: pytest.MonkeyPatch) -> None:
    called = _run_entrypoint(monkeypatch, KeyboardInterrupt())
    assert called["shutdown"] is True
    assert called["shutting_down"] is True
    assert called["cancelled"] is True


def test_main_entrypoint_unexpected_exception(monkeypatch: pytest.MonkeyPatch) -> None:
    called = _run_entrypoint(monkeypatch, RuntimeError("boom"))
    assert called["unexpected"] is True
    assert called["shutting_down"] is True
    assert called["cancelled"] is True
