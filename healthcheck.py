"""Check the heartbeat written after a successful Telegram/SQLite probe."""

import os
import time
from pathlib import Path

from telegram.request import HTTPXRequest


class PollingRequest(HTTPXRequest):
    """Track successful update polling, including responses with no new messages."""

    def __init__(self):
        super().__init__()
        self.last_success = None

    async def post(self, url, *args, **kwargs):
        result = await super().post(url, *args, **kwargs)
        if url.endswith("/getUpdates") and isinstance(result, list):
            self.last_success = time.monotonic()
        return result

    def polling_healthy(self):
        return (
            self.last_success is not None
            and 0 <= time.monotonic() - self.last_success < 90
        )


def healthy():
    try:
        age = (
            time.time()
            - Path(os.environ.get("HEALTHCHECK_PATH", "/tmp/steamguard-tg.health"))
            .stat()
            .st_mtime
        )
        return 0 <= age < 120
    except OSError:
        return False


if __name__ == "__main__":
    raise SystemExit(0 if healthy() else 1)
