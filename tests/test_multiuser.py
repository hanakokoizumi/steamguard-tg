import asyncio
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from sqlalchemy import select
from test_bot import FIELDS, VALUES, add, click, last_buttons, update
from test_bot import bot as bot

from database import SteamAccount
from update_processor import UserUpdateProcessor


def user_context(bot, user):
    return SimpleNamespace(user_data=bot.application.user_data[user])


async def process(bot, event, coroutine):
    await bot.application.update_processor.process_update(event, coroutine)


async def test_users_only_see_their_own_accounts(bot):
    ids = {
        user: add(bot, user=user, steamid=str(76561198000000000 + user))
        for user in (42, 43)
    }
    for user in ids:
        ctx = user_context(bot, user)
        event = update(user=user)
        await bot.list_accounts(event, ctx)
        buttons = last_buttons(event)
        assert len(buttons) == 1
        assert (
            ctx.user_data["pending"][buttons[0][0].callback_data]["account_id"]
            == ids[user]
        )
    assert bot.application.user_data[42] is not bot.application.user_data[43]


async def test_valid_foreign_button_is_unusable_for_other_user(bot):
    account_id = add(bot, user=43)
    a, b = user_context(bot, 42), user_context(bot, 43)
    button = bot.button(b, "private", "code", account_id)
    event = await click(bot, a, button, user=42)
    event.callback_query.edit_message_text.assert_not_awaited()
    assert event.callback_query.answer.await_args.kwargs["show_alert"]
    bot.steam.server_time.assert_not_awaited()
    assert button.callback_data in b.user_data["pending"]


@pytest.mark.parametrize(
    "action",
    [
        "code",
        "confirm",
        "detail",
        "act",
        "delete",
        "delete_yes",
        "login",
        "login_auto",
        "token",
        "qr",
        "qr_yes",
    ],
)
async def test_every_account_action_rechecks_owner(bot, action):
    other = add(bot, user=43)
    ctx = user_context(bot, 42)
    # Even a tampered server-side button entry must pass the database ownership check.
    button = bot.button(ctx, "forged", action, other)
    event = await click(bot, ctx, button, user=42)
    assert "不属于当前用户" in event.callback_query.edit_message_text.await_args.args[0]
    assert "flow" not in ctx.user_data
    bot.steam.server_time.assert_not_awaited()
    bot.steam.refresh_access_token.assert_not_awaited()
    bot.steam.confirmation_request.assert_not_awaited()
    bot.steam.qr_login.assert_not_awaited()
    with bot.sessions() as s:
        assert s.get(SteamAccount, other)


async def test_cancel_and_rate_limits_are_independent(bot):
    a, b = user_context(bot, 42), user_context(bot, 43)
    for user, ctx in ((42, a), (43, b)):
        await bot.add_account(update(user=user), ctx)
        bot.button(ctx, "button", "code", 1)
    b_before = {**b.user_data}
    await bot.cancel_command(update(user=42), a)
    assert not a.user_data
    assert b.user_data == b_before
    bot.request_limits[42] = (60, time.monotonic())
    event = update(user=43)
    await bot.help_command(event, b)
    assert "Steam Guard" in event.effective_message.reply_text.await_args.args[0]
    for _ in range(5):
        assert bot.allow_login_attempt(42)
    assert not bot.allow_login_attempt(42)
    assert bot.allow_login_attempt(43)


async def test_deleting_own_account_does_not_clear_other_users_state(bot):
    a_id, b_id = add(bot, user=42), add(bot, user=43)
    a, b = user_context(bot, 42), user_context(bot, 43)
    await bot.add_account(update(user=43), b)
    b_flow = b.user_data["flow"]
    await click(bot, a, bot.button(a, "delete", "delete_yes", a_id), user=42)
    with bot.sessions() as s:
        assert s.get(SteamAccount, a_id) is None
        assert s.get(SteamAccount, b_id) is not None
    assert b.user_data["flow"] is b_flow


async def test_interleaved_account_entry_keeps_secrets_and_ownership_separate(bot):
    contexts = {user: user_context(bot, user) for user in (42, 43)}
    for user, ctx in contexts.items():
        await bot.add_account(update(user=user), ctx)
    for field in FIELDS:
        for user, ctx in contexts.items():
            value = VALUES[field]
            if field == "steam_name":
                value = f"account-{user}"
            if field == "refresh_token":
                value = f"refresh-token-for-user-{user}"
            await bot.handle_account_input(update(user=user, text=value), ctx)
    with bot.sessions() as s:
        rows = s.scalars(select(SteamAccount).order_by(SteamAccount.user_id)).all()
        assert [(a.user_id, a.steam_name, a.refresh_token) for a in rows] == [
            (42, "account-42", "refresh-token-for-user-42"),
            (43, "account-43", "refresh-token-for-user-43"),
        ]
    assert all("flow" not in ctx.user_data for ctx in contexts.values())


async def test_slow_login_does_not_block_another_users_full_login(bot):
    assert isinstance(bot.application.update_processor, UserUpdateProcessor)
    assert bot.application.concurrent_updates > 1
    ids = {
        user: add(bot, user=user, steamid=str(76561198000000000 + user))
        for user in (42, 43)
    }
    contexts = {user: user_context(bot, user) for user in ids}
    started, release = asyncio.Event(), asyncio.Event()

    async def begin(username, password):
        user = int(username.removeprefix("user"))
        if user == 42:
            started.set()
            await release.wait()
        return {
            "steamid": str(76561198000000000 + user),
            "client_id": user,
            "request_id": str(user).encode(),
            "interval": 5,
            "guards": [3],
        }

    async def poll(state):
        return f"refresh-{state['client_id']}", f"access-{state['client_id']}"

    bot.mobile_login = SimpleNamespace(
        begin=AsyncMock(side_effect=begin),
        submit_code=AsyncMock(),
        poll=AsyncMock(side_effect=poll),
    )
    for user, ctx in contexts.items():
        event = update(
            user=user,
            callback=bot.button(ctx, "login", "login", ids[user]).callback_data,
        )
        await process(bot, event, bot.callback_query_handler(event, ctx))
        event = update(user=user, text=f"user{user}")
        await process(bot, event, bot.handle_account_input(event, ctx))
    first = update(user=42, text="user42-password")
    task = asyncio.create_task(
        process(bot, first, bot.handle_account_input(first, contexts[42]))
    )
    try:
        await asyncio.wait_for(started.wait(), 1)
        # A's password request is still waiting on Steam while B finishes every step.
        for text in ("user43-password", "AB123"):
            event = update(user=43, text=text)
            await asyncio.wait_for(
                process(bot, event, bot.handle_account_input(event, contexts[43])), 1
            )
        assert not task.done()
        assert contexts[42].user_data["flow"]["stage"] == "busy"
        assert "flow" not in contexts[43].user_data
        with bot.sessions() as s:
            assert s.get(SteamAccount, ids[43]).refresh_token == "refresh-43"
            assert s.get(SteamAccount, ids[42]).refresh_token == VALUES["refresh_token"]
    finally:
        release.set()
        await task
    event = update(user=42, text="AB123")
    await process(bot, event, bot.handle_account_input(event, contexts[42]))
    with bot.sessions() as s:
        assert s.get(SteamAccount, ids[42]).refresh_token == "refresh-42"
        assert s.get(SteamAccount, ids[43]).refresh_token == "refresh-43"


async def test_same_user_updates_stay_in_order_while_other_user_runs():
    processor = UserUpdateProcessor({42, 43})
    started, release, second_started = asyncio.Event(), asyncio.Event(), asyncio.Event()
    order = []

    async def first():
        order.append("first-start")
        started.set()
        await release.wait()
        order.append("first-end")

    async def second():
        order.append("second")
        second_started.set()

    async def other():
        order.append("other")

    task = asyncio.create_task(processor.process_update(update(user=42), first()))
    await started.wait()
    queued = asyncio.create_task(processor.process_update(update(user=42), second()))
    await processor.process_update(update(user=43), other())
    assert not second_started.is_set()
    release.set()
    await asyncio.gather(task, queued)
    assert order == ["first-start", "other", "first-end", "second"]


async def test_cancelled_waiter_is_closed_and_does_not_break_its_user():
    processor = UserUpdateProcessor({42, 43})
    entered, release = asyncio.Event(), asyncio.Event()

    async def first():
        entered.set()
        await release.wait()

    async def queued():
        raise AssertionError("cancelled callback ran")

    running = asyncio.create_task(processor.process_update(update(user=42), first()))
    await entered.wait()
    coroutine = queued()
    task = asyncio.create_task(processor.process_update(update(user=42), coroutine))
    await asyncio.sleep(0)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert coroutine.cr_frame is None
    release.set()
    await running
    callback = AsyncMock()
    await processor.process_update(update(user=42), callback())
    callback.assert_awaited_once()


def test_untrusted_user_ids_do_not_create_unbounded_locks():
    processor = UserUpdateProcessor({42, 43})
    assert set(processor.user_locks) == {42, 43}
