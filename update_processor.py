"""Keep each user's conversation ordered while other users continue working."""

import asyncio
import inspect

from telegram.ext import BaseUpdateProcessor


class UserUpdateProcessor(BaseUpdateProcessor):
    def __init__(self, allowed_users, max_concurrent_updates=256):
        super().__init__(max_concurrent_updates)
        self.user_locks = {user_id: asyncio.Lock() for user_id in allowed_users}
        self.unknown_user_lock = asyncio.Lock()

    async def initialize(self):
        pass

    async def shutdown(self):
        pass

    async def do_process_update(self, update, coroutine):
        user = getattr(update, "effective_user", None)
        chat = getattr(update, "effective_chat", None)
        if (
            user is None
            or user.id not in self.user_locks
            or chat is None
            or chat.type != "private"
        ):
            # Reject before Application creates per-user context or makes Telegram replies.
            if inspect.iscoroutine(coroutine):
                coroutine.close()
            return
        lock = self.user_locks[user.id]
        try:
            async with lock:
                await coroutine
        except BaseException:
            # A cancelled update may still be waiting for its user's previous update.
            if inspect.iscoroutine(coroutine):
                coroutine.close()
            raise
