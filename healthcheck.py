"""Check the heartbeat written after a successful Telegram/SQLite probe."""

import os
import time
from pathlib import Path


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
