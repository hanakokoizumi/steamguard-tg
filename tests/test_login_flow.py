import asyncio
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from test_bot import VALUES, add, click, context, last_buttons, update
from test_bot import bot as bot

from database import SteamAccount
from login_flow import CANCELLED
from steam_login import LoginError
from utils import SteamError, get_2fa_code


@pytest.fixture
def backend(bot):
    bot.mobile_login = SimpleNamespace(
        begin=AsyncMock(
            return_value={
                "client_id": 123,
                "request_id": b"id",
                "steamid": VALUES["steamid"],
                "interval": 5,
                "guards": [3, 4],
            }
        ),
        submit_code=AsyncMock(),
        poll=AsyncMock(return_value=None),
    )
    return bot.mobile_login


async def start(bot):
    account_id = add(bot)
    ctx = context()
    event = await click(bot, ctx, bot.button(ctx, "login", "login", account_id))
    assert "登录用户名" in event.callback_query.edit_message_text.await_args.args[0]
    return account_id, ctx


async def username_and_password(bot, ctx, password="  Password to preserve  "):
    await bot.handle_account_input(update(text="login_name"), ctx)
    event = update(text=password)
    await bot.handle_account_input(event, ctx)
    event.effective_message.delete.assert_awaited_once()
    return event


async def test_username_password_code_login_updates_only_tokens(bot, backend):
    account_id, ctx = await start(bot)

    async def begin(username, password):
        assert username == "login_name" and password == "  Password to preserve  "
        assert "Password" not in repr(ctx.user_data)
        assert "username" not in ctx.user_data["flow"]
        return {
            "client_id": 123,
            "request_id": b"id",
            "steamid": VALUES["steamid"],
            "interval": 5,
            "guards": [3, 4],
        }

    backend.begin.side_effect = begin
    await username_and_password(bot, ctx)
    assert ctx.user_data["flow"]["stage"] == "code"
    backend.poll.return_value = ("fresh-refresh", "fresh-access")
    event = update(text="ab123")
    await bot.handle_account_input(event, ctx)
    event.effective_message.delete.assert_awaited_once()
    backend.submit_code.assert_awaited_once()
    assert backend.submit_code.await_args.args[1] == "AB123"
    assert "flow" not in ctx.user_data
    with bot.sessions() as session:
        account = session.get(SteamAccount, account_id)
        assert (
            account.refresh_token == "fresh-refresh"
            and account.access_token == "fresh-access"
        )
        assert account.shared_secret == VALUES["shared_secret"]
        assert account.device_id == VALUES["device_id"]
        assert (
            b"Password to preserve" not in Path(session.bind.url.database).read_bytes()
        )


async def test_password_is_deleted_before_network_request(bot, backend):
    _, ctx = await start(bot)
    await bot.handle_account_input(update(text="login_name"), ctx)
    event = update(text="Password!")

    async def begin(*args):
        event.effective_message.delete.assert_awaited_once()
        raise LoginError("5")

    backend.begin.side_effect = begin
    await bot.handle_account_input(event, ctx)
    assert "flow" not in ctx.user_data
    assert "用户名或密码错误" in event.effective_message.reply_text.await_args.args[0]
    assert "Password!" not in repr(ctx.user_data)


async def test_wrong_username_cannot_replace_selected_account(bot, backend):
    account_id, ctx = await start(bot)
    backend.begin.return_value["steamid"] = "76561198000000002"
    event = await username_and_password(bot, ctx)
    assert "不一致" in event.effective_message.reply_text.await_args.args[0]
    assert "flow" not in ctx.user_data
    backend.submit_code.assert_not_awaited()
    with bot.sessions() as session:
        assert (
            session.get(SteamAccount, account_id).refresh_token
            == VALUES["refresh_token"]
        )


async def test_wrong_code_can_be_retried_without_password(bot, backend):
    _, ctx = await start(bot)
    await username_and_password(bot, ctx)
    backend.submit_code.side_effect = [LoginError("88"), None]
    await bot.handle_account_input(update(text="WRONG"), ctx)
    assert ctx.user_data["flow"]["stage"] == "code"
    backend.poll.return_value = ("refresh", "access")
    await bot.handle_account_input(update(text="AB123"), ctx)
    assert "flow" not in ctx.user_data
    backend.begin.assert_awaited_once()


async def test_code_attempt_limit_keeps_original_tokens(bot, backend):
    account_id, ctx = await start(bot)
    await username_and_password(bot, ctx)
    backend.submit_code.side_effect = LoginError("88")
    for _ in range(5):
        await bot.handle_account_input(update(text="WRONG"), ctx)
    assert "flow" not in ctx.user_data
    with bot.sessions() as session:
        assert (
            session.get(SteamAccount, account_id).refresh_token
            == VALUES["refresh_token"]
        )


async def test_automatic_code_uses_existing_secret_without_phone(bot, backend):
    _, ctx = await start(bot)
    event = await username_and_password(bot, ctx)
    button = last_buttons(event)[0][0]
    backend.poll.return_value = ("refresh", "access")
    await click(bot, ctx, button)
    assert backend.submit_code.await_args.args[1] == get_2fa_code(
        VALUES["shared_secret"], 1700000000
    )
    assert "flow" not in ctx.user_data


async def test_old_auto_code_button_cannot_submit_into_new_login(bot, backend):
    account_id, ctx = await start(bot)
    event = await username_and_password(bot, ctx)
    old_button = last_buttons(event)[0][0]
    await click(bot, ctx, bot.button(ctx, "login", "login", account_id))
    await username_and_password(bot, ctx)
    await click(bot, ctx, old_button)
    backend.submit_code.assert_not_awaited()
    assert ctx.user_data["flow"]["stage"] == "code"


async def test_email_code_prompt_has_no_automatic_device_code_button(bot, backend):
    _, ctx = await start(bot)
    backend.begin.return_value["guards"] = [2]
    event = await username_and_password(bot, ctx)
    assert "邮箱" in event.effective_message.reply_text.await_args.args[0]
    assert len(last_buttons(event)) == 1
    assert ctx.user_data["flow"]["session"]["code_type"] == 2


async def test_device_only_guard_is_reported_without_silently_waiting_for_phone(
    bot, backend
):
    _, ctx = await start(bot)
    backend.begin.return_value["guards"] = [4]
    event = await username_and_password(bot, ctx)
    assert "仅提供设备确认" in event.effective_message.reply_text.await_args.args[0]
    assert "flow" not in ctx.user_data


async def test_no_guard_can_finish_immediately(bot, backend):
    _, ctx = await start(bot)
    backend.begin.return_value["guards"] = [1]
    backend.poll.return_value = ("refresh", "access")
    await username_and_password(bot, ctx)
    assert "flow" not in ctx.user_data
    backend.submit_code.assert_not_awaited()


async def pending(bot, backend):
    account_id, ctx = await start(bot)
    await username_and_password(bot, ctx)
    await bot.handle_account_input(update(text="AB123"), ctx)
    flow = ctx.user_data["flow"]
    assert flow["stage"] == "pending"
    job = SimpleNamespace(
        data={"flow_id": flow["id"]}, user_id=42, chat_id=42, name="login-test"
    )
    job_context = SimpleNamespace(
        user_data=ctx.user_data, job=job, bot=SimpleNamespace(send_message=AsyncMock())
    )
    return account_id, ctx, flow, job_context


async def test_pending_login_finishes_in_background(bot, backend):
    account_id, ctx, _, job_context = await pending(bot, backend)
    backend.poll.return_value = ("new-refresh", "new-access")
    await bot.login_poll_job(job_context)
    assert "flow" not in ctx.user_data
    job_context.bot.send_message.assert_awaited_once()
    assert "登录成功" in job_context.bot.send_message.await_args.args[1]
    with bot.sessions() as session:
        assert session.get(SteamAccount, account_id).refresh_token == "new-refresh"


async def test_cancel_while_polling_does_not_save_or_notify(bot, backend):
    account_id, ctx, _, job_context = await pending(bot, backend)
    started = asyncio.Event()
    release = asyncio.Event()

    async def delayed(state):
        started.set()
        await release.wait()
        return ("cancelled-refresh", "cancelled-access")

    backend.poll.side_effect = delayed
    task = asyncio.create_task(bot.login_poll_job(job_context))
    await started.wait()
    await bot.cancel_command(update(), ctx)
    release.set()
    await task
    job_context.bot.send_message.assert_not_awaited()
    with bot.sessions() as session:
        assert (
            session.get(SteamAccount, account_id).refresh_token
            == VALUES["refresh_token"]
        )


async def test_new_flow_while_polling_is_not_overwritten(bot, backend):
    account_id, ctx, flow, job_context = await pending(bot, backend)

    async def replace(state):
        ctx.user_data["flow"] = {
            "kind": "add",
            "values": {},
            "expires": time.monotonic() + 600,
        }
        return ("cancelled-refresh", "cancelled-access")

    backend.poll.side_effect = replace
    assert await bot.poll_login_once(ctx.user_data, flow, 42) is CANCELLED
    assert ctx.user_data["flow"]["kind"] == "add"
    with bot.sessions() as session:
        assert (
            session.get(SteamAccount, account_id).refresh_token
            == VALUES["refresh_token"]
        )


async def test_background_timeout_preserves_old_tokens(bot, backend):
    account_id, ctx, flow, job_context = await pending(bot, backend)
    flow["expires"] = time.monotonic() - 1
    await bot.login_poll_job(job_context)
    assert "flow" not in ctx.user_data
    assert "超时" in job_context.bot.send_message.await_args.args[1]
    with bot.sessions() as session:
        assert (
            session.get(SteamAccount, account_id).refresh_token
            == VALUES["refresh_token"]
        )


async def test_network_poll_retries_are_bounded(bot, backend):
    _, ctx, flow, job_context = await pending(bot, backend)
    backend.poll.side_effect = SteamError("network unavailable")
    for _ in range(3):
        await bot.login_poll_job(job_context)
    assert flow["poll_errors"] == 3
    assert "flow" not in ctx.user_data
    job_context.bot.send_message.assert_awaited_once()


async def test_late_password_after_expiry_is_deleted(bot, backend):
    _, ctx = await start(bot)
    await bot.handle_account_input(update(text="login_name"), ctx)
    ctx.user_data["flow"]["expires"] = time.monotonic() - 1
    event = update(text="late secret password")
    await bot.handle_account_input(event, ctx)
    event.effective_message.delete.assert_awaited_once()
    backend.begin.assert_not_awaited()
    assert "已过期" in event.effective_message.reply_text.await_args.args[0]


async def test_login_attempt_rate_limit(bot, backend):
    account_id = add(bot)
    ctx = context()
    backend.begin.side_effect = LoginError("5")
    for _ in range(6):
        await click(bot, ctx, bot.button(ctx, "login", "login", account_id))
        event = await username_and_password(bot, ctx)
    assert backend.begin.await_count == 5
    assert "10 分钟" in event.effective_message.reply_text.await_args.args[0]


async def test_deleted_account_does_not_receive_new_tokens(bot, backend):
    account_id, ctx, _, job_context = await pending(bot, backend)
    with bot.sessions() as session:
        session.delete(session.get(SteamAccount, account_id))
        session.commit()
    backend.poll.return_value = ("refresh", "access")
    await bot.login_poll_job(job_context)
    assert "已删除" in job_context.bot.send_message.await_args.args[1]
    assert "flow" not in ctx.user_data


async def test_rate_limited_password_is_still_deleted(bot, backend):
    _, ctx = await start(bot)
    await bot.handle_account_input(update(text="login_name"), ctx)
    bot.request_limits[42] = (60, time.monotonic())
    event = update(text="rate-limited password")
    await bot.handle_account_input(event, ctx)
    event.effective_message.delete.assert_awaited_once()
    backend.begin.assert_not_awaited()


async def test_expired_login_is_cleared_and_notified_by_maintenance(
    bot, backend, monkeypatch, tmp_path
):
    _, ctx = await start(bot)
    flow = ctx.user_data["flow"]
    flow["expires"] = time.monotonic() - 1
    bot.application.user_data[42].update(ctx.user_data)
    context = SimpleNamespace(
        bot=SimpleNamespace(send_message=AsyncMock(), get_me=AsyncMock())
    )
    monkeypatch.setenv("HEALTHCHECK_PATH", str(tmp_path / "health"))
    await bot.maintenance(context)
    context.bot.send_message.assert_awaited_once()
    assert "flow" not in bot.application.user_data[42]
    assert bot.application.user_data[42]["expired_login"] > time.monotonic()
