import os
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from telegram.error import Conflict
from telegram.request import HTTPXRequest
from test_bot import bot as bot

from healthcheck import PollingRequest, healthy


def test_health_requires_a_recent_successful_probe(tmp_path, monkeypatch):
    path = tmp_path / "heartbeat"
    monkeypatch.setenv("HEALTHCHECK_PATH", str(path))
    assert not healthy()
    path.touch()
    assert healthy()
    old = time.time() - 121
    os.utime(path, (old, old))
    assert not healthy()


async def test_polling_health_requires_successful_getupdates(monkeypatch):
    request = PollingRequest()
    try:
        assert not request.polling_healthy()
        post = AsyncMock(return_value=[])
        monkeypatch.setattr(HTTPXRequest, "post", post)
        await request.post("https://api.telegram.org/botfake/getUpdates")
        assert request.polling_healthy()
        request.last_success = time.monotonic() - 91
        post.side_effect = Conflict("another poller")
        with pytest.raises(Conflict):
            await request.post("https://api.telegram.org/botfake/getUpdates")
        assert not request.polling_healthy()
        post.side_effect = None
        await request.post("https://api.telegram.org/botfake/getUpdates")
        assert request.polling_healthy()
    finally:
        await request.shutdown()


async def test_getme_success_does_not_hide_broken_polling(bot, monkeypatch, tmp_path):
    path = tmp_path / "health"
    monkeypatch.setenv("HEALTHCHECK_PATH", str(path))
    bot.application.updater._running = True
    ctx = SimpleNamespace(bot=SimpleNamespace(get_me=AsyncMock()))
    try:
        await bot.maintenance(ctx)
        assert not path.exists()
        bot.polling_request.last_success = time.monotonic()
        await bot.maintenance(ctx)
        assert path.exists()
        path.unlink()
        bot.polling_request.last_success = time.monotonic() - 91
        await bot.maintenance(ctx)
        assert not path.exists()
    finally:
        bot.application.updater._running = False
