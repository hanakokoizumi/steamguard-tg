import inspect
import json
import sqlite3
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest
from cryptography.fernet import Fernet
from sqlalchemy import select
from telegram import Update, User
from telegram.ext import ApplicationHandlerStop
from test_bot import VALUES, add, click, context, last_buttons, update
from test_bot import bot as bot
from test_login_api import STEAMID, token
from test_login_flow import backend as backend
from test_login_flow import pending, start

from database import PREFIX, CredentialError, SteamAccount, initialize_database
from main import SteamAccountBot
from update_processor import UserUpdateProcessor
from utils import AccessTokenExpired, SteamClient, SteamError


async def test_slash_password_is_deleted_and_sent_unchanged(bot, backend):
    _, ctx = await start(bot)
    await bot.handle_account_input(update(text="steam_name"), ctx)
    event = update(text="/Password with spaces  ")
    with pytest.raises(ApplicationHandlerStop):
        await bot.handle_command_input(event, ctx)
    event.effective_message.delete.assert_awaited_once()
    backend.begin.assert_awaited_once_with("steam_name", "/Password with spaces  ")
    assert bot.application.handlers[-1][0].callback == bot.handle_command_input


async def test_cancel_command_is_not_submitted_as_password(bot, backend):
    _, ctx = await start(bot)
    await bot.handle_account_input(update(text="steam_name"), ctx)
    event = update(text="/cancel")
    await bot.handle_command_input(event, ctx)
    await bot.cancel_command(event, ctx)
    backend.begin.assert_not_awaited()
    assert not ctx.user_data


async def test_real_telegram_command_entity_routes_through_password_flow(bot, backend):
    _, ctx = await start(bot)
    await bot.handle_account_input(update(text="steam_name"), ctx)
    bot.application.user_data[42].update(ctx.user_data)
    bot.application._initialized = True
    bot.application.bot._bot_user = User(123, "Test", True, username="test_bot")
    bot.respond = AsyncMock()
    bot.remove_sensitive_message = AsyncMock()
    password = "/a_real_password"
    event = Update.de_json(
        {
            "update_id": 1,
            "message": {
                "message_id": 1,
                "date": int(time.time()),
                "from": {"id": 42, "first_name": "Tester", "is_bot": False},
                "chat": {"id": 42, "type": "private"},
                "text": password,
                "entities": [
                    {"type": "bot_command", "offset": 0, "length": len(password)}
                ],
            },
        },
        bot.application.bot,
    )
    await bot.application.process_update(event)
    backend.begin.assert_awaited_once_with("steam_name", password)
    bot.remove_sensitive_message.assert_awaited_once()
    assert bot.application.user_data[42]["flow"]["stage"] == "code"


@pytest.mark.parametrize(
    "kind,step", [("token", None), ("add", 1), ("add", 2), ("add", 4)]
)
@pytest.mark.parametrize("limited,expired", [(True, False), (False, True)])
async def test_secrets_are_deleted_even_when_limited_or_expired(
    bot, kind, step, limited, expired
):
    ctx = context()
    ctx.user_data["flow"] = {
        "kind": kind,
        "step": step,
        "values": {},
        "account_id": 999,
        "expires": time.monotonic() + (-1 if expired else 600),
    }
    if limited:
        bot.request_limits[42] = (60, time.monotonic())
    event = update(text="secret")
    await bot.handle_account_input(event, ctx)
    event.effective_message.delete.assert_awaited_once()
    bot.steam.refresh_access_token.assert_not_awaited()


async def test_maintenance_expiry_remembers_late_token_is_sensitive(bot):
    ctx = context()
    ctx.user_data["flow"] = {"kind": "token", "expires": time.monotonic() - 1}
    SteamAccountBot.prune(ctx.user_data)
    event = update(text="late-token")
    await bot.handle_account_input(event, ctx)
    event.effective_message.delete.assert_awaited_once()
    assert "已过期" in event.effective_message.reply_text.await_args.args[0]


async def test_expired_slash_password_is_not_an_unknown_command(bot, backend):
    _, ctx = await start(bot)
    ctx.user_data["flow"]["stage"] = "password"
    ctx.user_data["flow"]["expires"] = time.monotonic() - 1
    bot.prune(ctx.user_data)
    event = update(text="/a_late_password")
    with pytest.raises(ApplicationHandlerStop):
        await bot.handle_command_input(event, ctx)
    event.effective_message.delete.assert_awaited_once()
    backend.begin.assert_not_awaited()


async def test_rate_limited_account_file_is_deleted_without_download(bot):
    event = update()
    event.effective_message.document = SimpleNamespace(
        file_name="account.maFile", get_file=AsyncMock()
    )
    bot.request_limits[42] = (60, time.monotonic())
    await bot.handle_file(event, context())
    event.effective_message.delete.assert_awaited_once()
    event.effective_message.document.get_file.assert_not_awaited()


async def test_manual_token_is_deleted_before_network_request(bot):
    account_id = add(bot)
    ctx = context()
    await click(bot, ctx, bot.button(ctx, "token", "token", account_id))
    event = update(text=VALUES["refresh_token"])

    async def refresh(*args):
        event.effective_message.delete.assert_awaited_once()
        return "new-access"

    bot.steam.refresh_access_token.side_effect = refresh
    await bot.handle_account_input(event, ctx)
    assert "已更新" in event.effective_message.reply_text.await_args.args[0]


async def test_token_response_after_expiry_cannot_commit(bot):
    account_id = add(bot)
    ctx = context()
    await click(bot, ctx, bot.button(ctx, "token", "token", account_id))

    async def expire(*args):
        ctx.user_data["flow"]["expires"] = time.monotonic() - 1
        bot.prune(ctx.user_data)
        return "late-access"

    bot.steam.refresh_access_token.side_effect = expire
    event = update(text="a-new-refresh-token-long-enough")
    await bot.handle_account_input(event, ctx)
    with bot.sessions() as session:
        assert (
            session.get(SteamAccount, account_id).refresh_token
            == VALUES["refresh_token"]
        )
    assert "凭据未更新" in event.effective_message.reply_text.await_args.args[0]


async def test_add_response_after_expiry_cannot_create_account(bot):
    with pytest.raises(ValueError, match="未保存"):
        await bot.save_account(42, VALUES, active=lambda: False)
    with bot.sessions() as session:
        assert session.scalar(select(SteamAccount)) is None


async def test_refresh_cannot_overwrite_background_login(bot):
    account_id = add(bot)

    async def refresh(*args):
        with bot.sessions() as newer:
            account = newer.get(SteamAccount, account_id)
            account.refresh_token = "fresh-login-refresh"
            account.access_token = "fresh-login-access"
            newer.commit()
        return "old-session-refreshed-access"

    bot.steam.refresh_access_token.side_effect = refresh
    operation = AsyncMock(side_effect=[AccessTokenExpired("expired"), "ok"])
    with bot.sessions() as session:
        account = session.get(SteamAccount, account_id)
        assert await bot.with_access_token(session, account, operation) == "ok"
    assert operation.await_args.args == ("fresh-login-access",)
    with bot.sessions() as session:
        account = session.get(SteamAccount, account_id)
        assert account.refresh_token == "fresh-login-refresh"
        assert account.access_token == "fresh-login-access"


async def test_navigation_stops_background_login(bot, backend):
    account_id, ctx, _, job_context = await pending(bot, backend)
    await bot.list_accounts(update(), ctx)
    backend.poll.return_value = ("late-refresh", "late-access")
    await bot.login_poll_job(job_context)
    job_context.bot.send_message.assert_not_awaited()
    with bot.sessions() as session:
        assert (
            session.get(SteamAccount, account_id).refresh_token
            == VALUES["refresh_token"]
        )


@pytest.mark.parametrize(
    "user,chat_type", [(999, "private"), (42, "group"), (42, "channel")]
)
async def test_untrusted_updates_do_not_build_context_or_reply(user, chat_type):
    processor = UserUpdateProcessor({42})
    callback = AsyncMock()
    coroutine = callback()
    await processor.process_update(update(user=user, chat_type=chat_type), coroutine)
    callback.assert_not_awaited()
    assert inspect.getcoroutinestate(coroutine) == inspect.CORO_CLOSED


@pytest.mark.parametrize(
    "bad",
    [
        token(steamid="76561198000000002"),
        token(audience=["web", "derive"]),
        token(refresh=False),
        token(expiry=1),
        token() + "\r\nCookie: bad",
    ],
)
async def test_manual_refresh_rejects_wrong_account_type_or_expiry_before_http(bad):
    handler = AsyncMock(return_value=httpx.Response(200))
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        steam = SteamClient(http)
        with pytest.raises(SteamError):
            await steam.refresh_access_token(STEAMID, bad)
        handler.assert_not_awaited()


@pytest.mark.parametrize(
    "bad",
    [
        token(steamid="76561198000000002", refresh=False),
        token(audience=["web"], refresh=False),
        token(),
    ],
)
async def test_refresh_rejects_invalid_access_token_from_steam(bad):
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda _: httpx.Response(
                200,
                headers={"X-eresult": "1"},
                json={"response": {"access_token": bad}},
            )
        )
    ) as http:
        with pytest.raises(SteamError):
            await SteamClient(http).refresh_access_token(STEAMID, token())


async def test_qr_preview_exposes_steam_risk_flags(bot):
    account_id = add(bot)
    bot.steam.qr_info.return_value.update(
        requestor_location_mismatch=True, high_usage_login=True
    )
    ctx = context()
    event = await click(
        bot,
        ctx,
        bot.button(ctx, "qr", "qr", account_id, qr_url="https://s.team/q/1/123"),
    )
    text = event.callback_query.edit_message_text.await_args.args[0]
    assert "位置不一致" in text and "高频" in text
    bot.steam.qr_login.assert_not_awaited()


async def test_confirmation_failure_offers_fresh_list_and_prevents_replay(bot):
    account_id = add(bot)
    ctx = context()
    conf = {"id": "123", "nonce": "test"}
    button = bot.button(ctx, "allow", "act", account_id, confirmation=conf, allow=True)
    bot.steam.confirmation_request.side_effect = SteamError("network")
    event = await click(bot, ctx, button)
    next_button = last_buttons(event)[0][0]
    assert ctx.user_data["pending"][next_button.callback_data]["action"] == "confirm"
    await click(bot, ctx, button)
    bot.steam.confirmation_request.assert_awaited_once()


def test_database_keys_are_isolated_and_failed_init_does_not_break_existing_engine(
    tmp_path,
):
    keys = [Fernet.generate_key(), Fernet.generate_key()]
    paths = [tmp_path / "one.db", tmp_path / "two.db"]
    factories = [initialize_database(path, key) for path, key in zip(paths, keys)]
    for factory in factories:
        with factory() as session:
            session.add(SteamAccount(user_id=42, **VALUES))
            session.commit()
    for path, key, factory in zip(paths, keys, factories):
        with sqlite3.connect(path) as raw:
            stored = raw.execute("SELECT refresh_token FROM steam_accounts").fetchone()[
                0
            ]
        assert (
            Fernet(key).decrypt(stored.removeprefix(PREFIX).encode()).decode()
            == VALUES["refresh_token"]
        )
        with pytest.raises(CredentialError):
            initialize_database(path, Fernet.generate_key())
        with factory() as session:
            assert (
                session.scalar(select(SteamAccount)).refresh_token
                == VALUES["refresh_token"]
            )


async def test_new_account_without_token_can_generate_code_then_start_login(
    bot, backend
):
    from main import FIELDS

    ctx = context()
    await bot.add_account(update(), ctx)
    for field in FIELDS:
        event = update(text="跳过" if field == "refresh_token" else VALUES[field])
        await bot.handle_account_input(event, ctx)
    bot.steam.refresh_access_token.assert_not_awaited()
    assert "尚未登录" in event.effective_message.reply_text.await_args.args[0]
    with bot.sessions() as session:
        account = session.scalar(select(SteamAccount))
        account_id = account.id
        assert account.refresh_token == "" and account.access_token is None
    code = await click(bot, ctx, bot.button(ctx, "code", "code", account_id))
    assert "<code>" in code.callback_query.edit_message_text.await_args.args[0]
    confirmation = await click(
        bot, ctx, bot.button(ctx, "confirm", "confirm", account_id)
    )
    assert "重新登录" in last_buttons(confirmation)[0][0].text
    await click(bot, ctx, last_buttons(confirmation)[0][0])
    assert ctx.user_data["flow"]["stage"] == "username"


@pytest.mark.parametrize("expired", [False, True])
async def test_mafile_without_usable_refresh_token_imports_and_prompts_login(
    bot, expired
):
    event = update()
    document = {
        "Session": {"SteamID": VALUES["steamid"]},
        "shared_secret": VALUES["shared_secret"],
        "identity_secret": VALUES["identity_secret"],
        "device_id": VALUES["device_id"],
        "account_name": "new account",
    }
    if expired:
        document["Session"]["RefreshToken"] = VALUES["refresh_token"]
        bot.steam.refresh_access_token.side_effect = AccessTokenExpired("expired")
    file = AsyncMock()
    file.download_as_bytearray.return_value = bytearray(json.dumps(document).encode())
    event.effective_message.document = SimpleNamespace(
        file_name="new.maFile", file_size=1000, get_file=AsyncMock(return_value=file)
    )
    await bot.handle_file(event, context())
    event.effective_message.delete.assert_awaited_once()
    assert bot.steam.refresh_access_token.await_count == (1 if expired else 0)
    assert "/login" in event.effective_message.reply_text.await_args.args[0]
    with bot.sessions() as session:
        account = session.scalar(select(SteamAccount))
        assert account.refresh_token == "" and account.access_token is None
