import io
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
import qrcode
from cryptography.fernet import Fernet
from sqlalchemy import func, select

from database import SteamAccount, initialize_database
from main import FIELDS, SteamAccountBot, decode_qr, validate_field
from utils import AccessTokenExpired

SECRET = "MDEyMzQ1Njc4OTAxMjM0NTY3ODk="
VALUES = dict(
    zip(
        FIELDS,
        [
            "76561198000000001",
            SECRET,
            SECRET,
            "android:12345678-1234-1234-1234-123456789abc",
            "a-refresh-token-long-enough",
            "测试账号",
        ],
    )
)


@pytest.fixture
async def bot(tmp_path):
    sessions = initialize_database(tmp_path / "test.db", Fernet.generate_key())
    steam = SimpleNamespace(
        refresh_access_token=AsyncMock(return_value="new-access-token"),
        server_time=AsyncMock(return_value=1700000000),
        confirmation_request=AsyncMock(return_value=[]),
        qr_info=AsyncMock(
            return_value={"device_friendly_name": "test device", "ip": "127.0.0.1"}
        ),
        qr_login=AsyncMock(return_value=True),
        close=AsyncMock(),
    )
    bot = SteamAccountBot("123456789:fake_test_token", {42, 43}, sessions, steam)
    yield bot
    await bot.application.bot.request.shutdown()
    await bot.application.bot.shutdown()


def update(user=42, text="", callback=None, chat_type="private"):
    message = SimpleNamespace(
        text=text, reply_text=AsyncMock(), delete=AsyncMock(), document=None
    )
    query = (
        SimpleNamespace(
            data=callback,
            answer=AsyncMock(),
            edit_message_text=AsyncMock(),
            from_user=SimpleNamespace(id=user),
        )
        if callback
        else None
    )
    return SimpleNamespace(
        effective_user=SimpleNamespace(id=user),
        effective_chat=SimpleNamespace(type=chat_type),
        effective_message=message,
        callback_query=query,
    )


def context():
    return SimpleNamespace(user_data={})


def last_buttons(event):
    call = (
        event.callback_query.edit_message_text.await_args
        if event.callback_query
        else event.effective_message.reply_text.await_args
    )
    return call.kwargs["reply_markup"].inline_keyboard


def add(bot, user=42, steamid=None):
    with bot.sessions() as session:
        values = {**VALUES, **({"steamid": steamid} if steamid else {})}
        account = SteamAccount(user_id=user, access_token="old-access", **values)
        session.add(account)
        session.commit()
        return account.id


async def click(bot, ctx, button, user=42):
    event = update(user=user, callback=button.callback_data)
    await bot.callback_query_handler(event, ctx)
    return event


async def test_add_input_is_registered(bot):
    from telegram.ext import MessageHandler

    assert any(
        isinstance(h, MessageHandler) and h.callback == bot.handle_account_input
        for h in bot.application.handlers[0]
    )


async def test_six_step_add_commits_once_and_clears_secrets(bot):
    ctx = context()
    await bot.add_account(update(), ctx)
    for field in FIELDS:
        event = update(text=VALUES[field])
        await bot.handle_account_input(event, ctx)
        if field in ("shared_secret", "identity_secret", "refresh_token"):
            event.effective_message.delete.assert_awaited_once()
    assert "flow" not in ctx.user_data
    with bot.sessions() as session:
        account = session.scalar(select(SteamAccount))
        assert account.refresh_token == VALUES["refresh_token"]
        assert account.access_token == "new-access-token"
        assert session.scalar(select(func.count()).select_from(SteamAccount)) == 1


async def test_invalid_refresh_does_not_save_partial_account(bot):
    ctx = context()
    bot.steam.refresh_access_token.side_effect = AccessTokenExpired("invalid")
    await bot.add_account(update(), ctx)
    for field in FIELDS:
        await bot.handle_account_input(update(text=VALUES[field]), ctx)
    with bot.sessions() as session:
        assert session.scalar(select(func.count()).select_from(SteamAccount)) == 0
    assert ctx.user_data["flow"]["step"] == 4
    assert "refresh_token" not in ctx.user_data["flow"]["values"]


async def test_duplicate_account_not_added(bot):
    add(bot)
    with pytest.raises(ValueError, match="已经添加"):
        await bot.save_account(42, VALUES)
    bot.steam.refresh_access_token.assert_not_awaited()


@pytest.mark.parametrize(
    "method",
    [
        "help_command",
        "cancel_command",
        "add_account",
        "request_2fa_code",
        "handle_account_input",
        "confirm_request",
        "list_accounts",
        "update_token",
        "delete_account",
        "login_command",
    ],
)
async def test_all_commands_require_whitelist(bot, method):
    ctx = context()
    ctx.user_data["sentinel"] = 1
    event = update(user=999)
    await getattr(bot, method)(event, ctx)
    assert ctx.user_data == {"sentinel": 1}
    event.effective_message.reply_text.assert_awaited_once_with("没有访问权限。")


async def test_group_chat_cannot_get_codes(bot):
    event = update(chat_type="group")
    await bot.request_2fa_code(event, context())
    event.effective_message.reply_text.assert_awaited_once_with(
        "请在与机器人的私聊中操作。"
    )


async def test_callback_cannot_access_other_users_account(bot):
    account_id = add(bot, user=43)
    ctx = context()
    button = bot.button(ctx, "forged", "code", account_id)
    event = await click(bot, ctx, button)
    assert "不属于当前用户" in event.callback_query.edit_message_text.await_args.args[0]
    bot.steam.server_time.assert_not_awaited()


async def test_cancel_clears_inputs_and_old_buttons(bot):
    ctx = context()
    button = bot.button(ctx, "old", "code", 1)
    ctx.user_data["flow"] = {"values": {"shared_secret": SECRET}}
    await bot.cancel_command(update(), ctx)
    assert not ctx.user_data
    event = await click(bot, ctx, button)
    event.callback_query.answer.assert_awaited_once()
    event.callback_query.edit_message_text.assert_not_awaited()


async def test_expired_state_and_short_opaque_buttons(bot):
    ctx = context()
    ctx.user_data["flow"] = {
        "expires": time.monotonic() - 1,
        "values": {"refresh_token": "secret"},
    }
    button = bot.button(
        ctx, "login", "qr", 1, qr_url="https://s.team/q/1/18446744073709551615"
    )
    assert len(button.callback_data.encode()) <= 64
    assert "s.team" not in button.callback_data
    assert "flow" not in ctx.user_data
    ctx.user_data["pending"][button.callback_data]["expires"] = time.monotonic() - 1
    event = await click(bot, ctx, button)
    event.callback_query.edit_message_text.assert_not_awaited()


async def test_delete_requires_confirmation(bot):
    account_id = add(bot)
    ctx = context()
    event = await click(bot, ctx, bot.button(ctx, "delete", "delete", account_id))
    with bot.sessions() as session:
        assert session.get(SteamAccount, account_id)
    confirm = last_buttons(event)[0][0]
    await click(bot, ctx, confirm)
    with bot.sessions() as session:
        assert session.get(SteamAccount, account_id) is None


async def test_update_token_validates_before_replacing(bot):
    account_id = add(bot)
    ctx = context()
    await click(bot, ctx, bot.button(ctx, "token", "token", account_id))
    bot.steam.refresh_access_token.side_effect = AccessTokenExpired("expired")
    await bot.handle_account_input(
        update(text="another-refresh-token-long-enough"), ctx
    )
    with bot.sessions() as session:
        assert (
            session.get(SteamAccount, account_id).refresh_token
            == VALUES["refresh_token"]
        )
    bot.steam.refresh_access_token.side_effect = None
    await bot.handle_account_input(
        update(text="another-refresh-token-long-enough"), ctx
    )
    with bot.sessions() as session:
        assert (
            session.get(SteamAccount, account_id).refresh_token
            == "another-refresh-token-long-enough"
        )
    assert "flow" not in ctx.user_data


async def test_access_token_retries_once(bot):
    account_id = add(bot)
    operation = AsyncMock(side_effect=[AccessTokenExpired("expired"), "ok"])
    with bot.sessions() as session:
        account = session.get(SteamAccount, account_id)
        assert await bot.with_access_token(session, account, operation) == "ok"
        assert account.access_token == "new-access-token"
    assert operation.await_count == 2
    bot.steam.refresh_access_token.assert_awaited_once()


async def test_confirm_actions_are_consumed_once(bot):
    account_id = add(bot)
    ctx = context()
    conf = {"id": "123", "nonce": "private-nonce", "headline": "trade"}
    approve = bot.button(
        ctx, "approve", "act", account_id, confirmation=conf, allow=True
    )
    reject = bot.button(
        ctx, "reject", "act", account_id, confirmation=conf, allow=False
    )
    event = await click(bot, ctx, approve)
    assert "已同意" in event.callback_query.edit_message_text.await_args.args[0]
    await click(bot, ctx, reject)
    await click(bot, ctx, approve)
    assert bot.steam.confirmation_request.await_count == 1


async def test_qr_preview_before_approval_and_replay_prevention(bot):
    account_id = add(bot)
    ctx = context()
    select = bot.button(ctx, "qr", "qr", account_id, qr_url="https://s.team/q/1/123")
    event = await click(bot, ctx, select)
    bot.steam.qr_login.assert_not_awaited()
    assert "test device" in event.callback_query.edit_message_text.await_args.args[0]
    confirm = last_buttons(event)[0][0]
    await click(bot, ctx, confirm)
    await click(bot, ctx, confirm)
    bot.steam.qr_login.assert_awaited_once()


async def test_pagination_and_copyable_code(bot):
    for i in range(10):
        add(bot, steamid=str(76561198000000000 + i))
    ctx = context()
    event = update()
    await bot.request_2fa_code(event, ctx)
    keyboard = last_buttons(event)
    assert len(keyboard) == 9
    next_event = await click(bot, ctx, keyboard[-1][0])
    assert len(last_buttons(next_event)) == 3
    code_event = await click(bot, ctx, keyboard[0][0])
    assert "<code>" in code_event.callback_query.edit_message_text.await_args.args[0]
    assert last_buttons(code_event)[0][0].copy_text.text


def test_qr_decodes_real_image():
    output = io.BytesIO()
    qrcode.make("https://s.team/q/1/123").save(output, format="PNG")
    assert decode_qr(output.getvalue()) == "https://s.team/q/1/123"


def test_image_errors_are_readable():
    with pytest.raises(ValueError, match="无法读取"):
        decode_qr(b"not an image")


@pytest.mark.parametrize(
    "field,value",
    [
        ("steamid", "123"),
        ("device_id", "android:bad"),
        ("steam_name", "line\nbreak"),
        ("steam_name", "x" * 65),
        ("refresh_token", "token with spaces"),
    ],
)
def test_input_validation(field, value):
    with pytest.raises(ValueError):
        validate_field(field, value)


async def test_codes_work_if_steam_time_is_unavailable(bot):
    from utils import SteamError

    account_id = add(bot)
    ctx = context()
    bot.steam.server_time.side_effect = SteamError("network unavailable")
    event = await click(bot, ctx, bot.button(ctx, "code", "code", account_id))
    assert "<code>" in event.callback_query.edit_message_text.await_args.args[0]
    assert "服务器时间" in event.callback_query.edit_message_text.await_args.args[0]


async def test_inline_cancel_invalidates_delete_approval(bot):
    account_id = add(bot)
    ctx = context()
    event = await click(bot, ctx, bot.button(ctx, "delete", "delete", account_id))
    confirm, cancel = last_buttons(event)[0]
    await click(bot, ctx, cancel)
    await click(bot, ctx, confirm)
    with bot.sessions() as session:
        assert session.get(SteamAccount, account_id)


def test_log_filter_redacts_tokens_and_tracebacks():
    import logging

    from main import RedactCredentials

    record = logging.LogRecord(
        "test",
        logging.ERROR,
        "",
        1,
        "https://api.telegram.org/bot%s?access_token=secret",
        ("123:secret",),
        (ValueError, ValueError("private"), None),
    )
    RedactCredentials("123:secret").filter(record)
    assert "secret" not in record.getMessage()
    assert record.exc_info is None


async def test_mafile_import_and_sensitive_file_deletion(bot):
    import json

    ctx = context()
    event = update()
    file = AsyncMock()
    file.download_as_bytearray.return_value = bytearray(
        json.dumps(
            {
                "Session": {
                    "SteamID": VALUES["steamid"],
                    "RefreshToken": VALUES["refresh_token"],
                },
                "shared_secret": SECRET,
                "identity_secret": SECRET,
                "device_id": VALUES["device_id"],
                "account_name": "imported",
            }
        ).encode()
    )
    event.effective_message.document = SimpleNamespace(
        file_name="account.maFile", file_size=400, get_file=AsyncMock(return_value=file)
    )
    await bot.handle_file(event, ctx)
    event.effective_message.delete.assert_awaited_once()
    with bot.sessions() as session:
        assert session.scalar(select(SteamAccount)).steam_name == "imported"


async def test_photo_uses_short_opaque_callback(bot):
    ctx = context()
    add(bot)
    output = io.BytesIO()
    qrcode.make("https://s.team/q/1/18446744073709551615").save(output, format="PNG")
    file = AsyncMock()
    file.download_as_bytearray.return_value = bytearray(output.getvalue())
    event = update()
    event.effective_message.photo = [
        SimpleNamespace(
            file_size=len(output.getvalue()), get_file=AsyncMock(return_value=file)
        )
    ]
    await bot.handle_file(event, ctx)
    button = last_buttons(event)[0][0]
    assert len(button.callback_data.encode()) <= 64
    assert ctx.user_data["pending"][button.callback_data]["payload"]["qr_url"].endswith(
        "18446744073709551615"
    )
