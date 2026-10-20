import asyncio
import io
import json
import logging
import os
import re
import secrets
import time
import warnings
from functools import wraps
from html import escape
from pathlib import Path

from dotenv import load_dotenv
from PIL import Image, UnidentifiedImageError
from sqlalchemy import select
from telegram import (
    BotCommand,
    CopyTextButton,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    MenuButtonCommands,
)
from telegram.error import BadRequest, TelegramError
from telegram.ext import (
    ApplicationBuilder,
    CallbackQueryHandler,
    CommandHandler,
    MessageHandler,
    filters,
)

from database import CredentialError, SteamAccount, initialize_database
from utils import (
    AccessTokenExpired,
    SteamClient,
    SteamError,
    decode_secret,
    get_2fa_code,
    parse_qr_url,
)

logger = logging.getLogger(__name__)
TTL = 600
PAGE_SIZE = 8
MAX_FILE_SIZE = 8 * 1024 * 1024
Image.MAX_IMAGE_PIXELS = 12_000_000
FIELDS = (
    "steamid",
    "shared_secret",
    "identity_secret",
    "device_id",
    "refresh_token",
    "steam_name",
)
PROMPTS = {
    "steamid": "1/6 · 请输入 17 位 SteamID64：",
    "shared_secret": "2/6 · 请输入 Shared Secret：",
    "identity_secret": "3/6 · 请输入 Identity Secret：",
    "device_id": "4/6 · 请输入 Device ID（android: 开头）：",
    "refresh_token": "5/6 · 请输入 Steam 移动端 Refresh Token：",
    "steam_name": "6/6 · 给这个账号起个名字（最多 64 字）：",
}
COMMANDS = [
    ("start", "打开菜单"),
    ("code", "获取 Steam Guard 验证码"),
    ("confirm", "处理交易和市场确认"),
    ("list", "查看账号"),
    ("addaccount", "添加账号"),
    ("updatetoken", "更新登录凭据"),
    ("deleteaccount", "删除账号"),
    ("cancel", "取消当前操作"),
    ("help", "使用帮助"),
]


class RedactCredentials(logging.Filter):
    def __init__(self, token):
        super().__init__()
        self.token = token

    def filter(self, record):
        message = record.getMessage().replace(self.token, "[redacted]")
        message = re.sub(r"(access_token=)[^&\s]+", r"\1[redacted]", message)
        record.msg, record.args = message, ()
        record.exc_info = record.exc_text = record.stack_info = None
        return True


def authorized(handler):
    @wraps(handler)
    async def wrapper(self, update, context):
        if await self.check_user(update):
            self.prune(context.user_data)
            return await handler(self, update, context)

    return wrapper


def validate_field(field, value):
    if not isinstance(value, str):
        raise ValueError("输入格式不正确。")
    value = value.strip()
    if not value:
        raise ValueError("输入不能为空，请重新输入。")
    if field == "steamid" and not re.fullmatch(r"7656119[0-9]{10}", value):
        raise ValueError("请输入 17 位 SteamID64，通常以 7656119 开头。")
    if field in ("shared_secret", "identity_secret"):
        decode_secret(value)
    if field == "device_id" and not re.fullmatch(
        r"android:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
        value,
    ):
        raise ValueError(
            "Device ID 格式应为 android:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx。"
        )
    if field == "refresh_token" and (
        not 20 <= len(value) <= 8192 or any(c.isspace() for c in value)
    ):
        raise ValueError("Refresh Token 格式不正确，请完整复制移动端令牌。")
    if field == "steam_name" and (len(value) > 64 or any(ord(c) < 32 for c in value)):
        raise ValueError("账号名称应为 1–64 字，且不能包含换行。")
    return value


def decode_qr(data):
    from pyzbar.pyzbar import ZBarSymbol, decode

    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(io.BytesIO(data)) as image:
                image.load()
                codes = decode(image, symbols=[ZBarSymbol.QRCODE])
        urls = set()
        for code in codes:
            try:
                url = code.data.decode("utf-8")
                parse_qr_url(url)
                urls.add(url)
            except (UnicodeError, ValueError):
                continue
        if len(urls) != 1:
            raise ValueError("请发送只包含一个 Steam 登录二维码的清晰图片。")
        return urls.pop()
    except (
        UnidentifiedImageError,
        OSError,
        Image.DecompressionBombError,
        Image.DecompressionBombWarning,
    ):
        raise ValueError("图片无法读取或尺寸过大，请裁剪到二维码后重新发送。") from None


class SteamAccountBot:
    def __init__(self, token, allowed_users, session_factory, steam=None):
        self.allowed_users = {int(user) for user in allowed_users}
        if not self.allowed_users:
            raise ValueError("ALLOWED_USERS 不能为空。")
        self.sessions = session_factory
        self.steam = steam or SteamClient()
        self.request_limits = {}
        self.application = (
            ApplicationBuilder()
            .token(token)
            .concurrent_updates(False)
            .post_init(self.post_init)
            .post_shutdown(self.post_shutdown)
            .build()
        )
        routes = {
            "start": self.help_command,
            "help": self.help_command,
            "addaccount": self.add_account,
            "deleteaccount": self.delete_account,
            "code": self.request_2fa_code,
            "2fa": self.request_2fa_code,
            "confirm": self.confirm_request,
            "list": self.list_accounts,
            "cancel": self.cancel_command,
            "updatetoken": self.update_token,
        }
        for command, handler in routes.items():
            self.application.add_handler(CommandHandler(command, handler))
        self.application.add_handler(CallbackQueryHandler(self.callback_query_handler))
        self.application.add_handler(
            MessageHandler(filters.PHOTO | filters.Document.ALL, self.handle_file)
        )
        self.application.add_handler(
            MessageHandler(filters.TEXT & ~filters.COMMAND, self.handle_account_input)
        )
        self.application.add_handler(
            MessageHandler(filters.COMMAND, self.unknown_command)
        )
        self.application.add_error_handler(self.error_handler)

    async def post_init(self, application):
        await application.bot.set_my_commands(
            [BotCommand(*command) for command in COMMANDS]
        )
        await application.bot.set_chat_menu_button(menu_button=MenuButtonCommands())
        application.job_queue.run_repeating(self.maintenance, interval=30, first=1)
        logger.info(
            "Bot initialized; private-chat access enabled for %d users",
            len(self.allowed_users),
        )

    async def post_shutdown(self, application):
        await self.steam.close()
        Path(os.environ.get("HEALTHCHECK_PATH", "/tmp/steamguard-tg.health")).unlink(
            missing_ok=True
        )

    async def maintenance(self, context):
        for data in self.application.user_data.values():
            self.prune(data)
        try:
            await context.bot.get_me()
            with self.sessions() as session:
                session.execute(select(1))
            if self.application.updater.running:
                Path(
                    os.environ.get("HEALTHCHECK_PATH", "/tmp/steamguard-tg.health")
                ).touch()
        except Exception as error:
            logger.warning("Health probe failed (%s)", type(error).__name__)

    @staticmethod
    def prune(data):
        now = time.monotonic()
        if data.get("flow", {}).get("expires", now + 1) <= now:
            data.pop("flow", None)
        pending = data.setdefault("pending", {})
        for key in list(pending):
            if pending[key]["expires"] <= now:
                del pending[key]

    def button(self, context, label, action, account_id=None, **payload):
        self.prune(context.user_data)
        pending = context.user_data["pending"]
        while len(pending) >= 200:
            del pending[next(iter(pending))]
        key = "sg:" + secrets.token_urlsafe(12)
        pending[key] = {
            "action": action,
            "account_id": account_id,
            "payload": payload,
            "expires": time.monotonic() + TTL,
        }
        return InlineKeyboardButton(label[:100], callback_data=key)

    async def check_user(self, update):
        user, chat, query = (
            update.effective_user,
            update.effective_chat,
            update.callback_query,
        )
        reason = None
        if user is None or user.id not in self.allowed_users:
            reason = "没有访问权限。"
        elif chat is None or chat.type != "private":
            reason = "请在与机器人的私聊中操作。"
        else:
            now = time.monotonic()
            count, reset = self.request_limits.get(user.id, (0, now))
            if now - reset >= 60:
                count, reset = 0, now
            self.request_limits[user.id] = (count + 1, reset)
            if count >= 60:
                reason = "操作过于频繁，请稍后再试。"
        if reason:
            if query:
                await query.answer(reason, show_alert=True)
            elif update.effective_message:
                await update.effective_message.reply_text(reason)
            return False
        return True

    @staticmethod
    async def respond(update, text, keyboard=None, html=False):
        kwargs = {
            "reply_markup": InlineKeyboardMarkup(keyboard) if keyboard else None,
            "parse_mode": "HTML" if html else None,
        }
        if update.callback_query:
            try:
                await update.callback_query.edit_message_text(text, **kwargs)
            except BadRequest as error:
                if "message is not modified" not in str(error).lower():
                    raise
        else:
            await update.effective_message.reply_text(
                text, protect_content=True, **kwargs
            )

    @staticmethod
    async def remove_sensitive_message(message):
        try:
            await message.delete()
        except TelegramError:
            await message.reply_text("这条消息未能自动删除，请手动删除包含凭据的消息。")

    @authorized
    async def help_command(self, update, context):
        await self.respond(
            update,
            "Steam Guard\n\n/code（或 /2fa）· 获取验证码\n/confirm · 交易和市场确认\n/list · 查看账号\n"
            "/addaccount · 添加账号\n/updatetoken · 更新 Refresh Token\n/deleteaccount · 删除账号\n/cancel · 取消操作\n\n"
            "发送 Steam 登录二维码图片，选择账号并确认后登录。\n也可以直接发送含完整凭据的 .maFile 文件导入账号。",
            [
                [
                    self.button(context, "获取验证码", "choose", kind="code"),
                    self.button(context, "待确认请求", "choose", kind="confirm"),
                ],
                [self.button(context, "我的账号", "choose", kind="list")],
            ],
        )

    async def choose_accounts(self, update, context, kind, page=0, qr_url=None):
        with self.sessions() as session:
            accounts = session.scalars(
                select(SteamAccount)
                .where(SteamAccount.user_id == update.effective_user.id)
                .order_by(SteamAccount.id)
            ).all()
        if not accounts:
            await self.respond(
                update, "还没有账号，使用 /addaccount 添加，或发送 .maFile 导入。"
            )
            return
        page = min(max(0, page), (len(accounts) - 1) // PAGE_SIZE)
        keyboard = []
        for account in accounts[page * PAGE_SIZE : (page + 1) * PAGE_SIZE]:
            keyboard.append(
                [
                    self.button(
                        context,
                        f"{account.steam_name or account.steamid} · {account.steamid}",
                        kind,
                        account.id,
                        qr_url=qr_url,
                    )
                    if kind == "qr"
                    else self.button(
                        context,
                        f"{account.steam_name or account.steamid} · {account.steamid}",
                        kind,
                        account.id,
                    )
                ]
            )
        pages = []
        for target, label in ((page - 1, "上一页"), (page + 1, "下一页")):
            if 0 <= target <= (len(accounts) - 1) // PAGE_SIZE:
                pages.append(
                    self.button(
                        context, label, "choose", kind=kind, page=target, qr_url=qr_url
                    )
                )
        if pages:
            keyboard.append(pages)
        titles = {
            "code": "选择账号获取验证码",
            "confirm": "选择账号查看待确认请求",
            "delete": "选择要删除的账号",
            "token": "选择要更新登录凭据的账号",
            "qr": "选择登录账号；下一步需要确认",
            "list": f"我的账号 · 共 {len(accounts)} 个（点击获取验证码）",
        }
        if kind == "list":
            # List entries have the same behavior as the code picker.
            for row in keyboard:
                for button in row:
                    entry = context.user_data["pending"][button.callback_data]
                    if entry["action"] == "list":
                        entry["action"] = "code"
        await self.respond(update, f"{titles[kind]} · 第 {page + 1} 页", keyboard)

    @authorized
    async def request_2fa_code(self, update, context):
        await self.choose_accounts(update, context, "code")

    @authorized
    async def confirm_request(self, update, context):
        await self.choose_accounts(update, context, "confirm")

    @authorized
    async def delete_account(self, update, context):
        await self.choose_accounts(update, context, "delete")

    @authorized
    async def update_token(self, update, context):
        context.user_data.pop("flow", None)
        await self.choose_accounts(update, context, "token")

    @authorized
    async def list_accounts(self, update, context):
        await self.choose_accounts(update, context, "list")

    @authorized
    async def cancel_command(self, update, context):
        context.user_data.clear()
        await self.respond(
            update, "已取消操作，之前的操作按钮已失效。使用 /start 返回菜单。"
        )

    @authorized
    async def unknown_command(self, update, context):
        await self.respond(update, "无法识别这个命令，使用 /help 查看用法。")

    @authorized
    async def add_account(self, update, context):
        context.user_data["flow"] = {
            "kind": "add",
            "step": 0,
            "values": {},
            "expires": time.monotonic() + TTL,
        }
        await self.respond(
            update,
            "按提示输入账号凭据，或发送 .maFile 文件。10 分钟未操作会取消，可随时使用 /cancel。\n\n"
            + PROMPTS["steamid"],
        )

    async def save_account(self, user_id, values):
        with self.sessions() as session:
            duplicate = session.scalar(
                select(SteamAccount.id).where(
                    SteamAccount.user_id == user_id,
                    SteamAccount.steamid == values["steamid"],
                )
            )
            if duplicate:
                raise ValueError(
                    "这个 Steam 账号已经添加。更新登录凭据请用 /updatetoken。"
                )
            access_token = await self.steam.refresh_access_token(
                values["steamid"], values["refresh_token"]
            )
            session.add(
                SteamAccount(user_id=user_id, access_token=access_token, **values)
            )
            session.commit()

    @authorized
    async def handle_account_input(self, update, context):
        flow = context.user_data.get("flow")
        if not flow:
            await self.respond(
                update, "使用 /addaccount 添加账号，或 /start 打开菜单。"
            )
            return
        field = "refresh_token" if flow["kind"] == "token" else FIELDS[flow["step"]]
        try:
            value = validate_field(field, update.effective_message.text)
            flow["expires"] = time.monotonic() + TTL
            if flow["kind"] == "token":
                with self.sessions() as session:
                    account = session.scalar(
                        select(SteamAccount).where(
                            SteamAccount.id == flow["account_id"],
                            SteamAccount.user_id == update.effective_user.id,
                        )
                    )
                    if not account:
                        context.user_data.pop("flow", None)
                        raise ValueError("账号不存在，请重新选择。")
                    token = await self.steam.refresh_access_token(
                        account.steamid, value
                    )
                    account.refresh_token, account.access_token = value, token
                    session.commit()
                context.user_data.pop("flow", None)
                await self.respond(update, "登录凭据已更新。")
            else:
                flow["values"][field] = value
                if flow["step"] == len(FIELDS) - 1:
                    try:
                        await self.save_account(
                            update.effective_user.id, flow["values"]
                        )
                    except AccessTokenExpired:
                        flow["step"] = 4
                        flow["values"].pop("refresh_token", None)
                        raise ValueError(
                            "Refresh Token 无效或已过期，请重新输入移动端 Refresh Token。"
                        ) from None
                    context.user_data.pop("flow", None)
                    await self.respond(
                        update, f"已添加账号 {value}。使用 /code 获取验证码。"
                    )
                else:
                    flow["step"] += 1
                    await self.respond(update, PROMPTS[FIELDS[flow["step"]]])
        except (ValueError, SteamError) as error:
            await self.respond(update, str(error))
        finally:
            if field in ("shared_secret", "identity_secret", "refresh_token"):
                await self.remove_sensitive_message(update.effective_message)

    @authorized
    async def handle_file(self, update, context):
        message = update.effective_message
        document = message.document
        is_account = document and (document.file_name or "").lower().endswith(
            (".mafile", ".json")
        )
        try:
            media = document or message.photo[-1]
            limit = 64 * 1024 if is_account else MAX_FILE_SIZE
            if media.file_size and media.file_size > limit:
                raise ValueError("文件过大：账号文件最多 64 KB，二维码图片最多 8 MB。")
            if (
                document
                and not is_account
                and not (document.mime_type or "").startswith("image/")
            ):
                raise ValueError("请发送二维码图片或 .maFile 账号文件。")
            data = await (await media.get_file()).download_as_bytearray()
            if len(data) > limit:
                raise ValueError("文件过大，请缩小后重新发送。")
            if is_account:
                try:
                    account = json.loads(data)
                    session = account.get("Session") or {}
                    values = {
                        "steamid": str(
                            session.get("SteamID") or account.get("steamid") or ""
                        ),
                        "shared_secret": account.get("shared_secret", ""),
                        "identity_secret": account.get("identity_secret", ""),
                        "device_id": account.get("device_id", ""),
                        "refresh_token": session.get("RefreshToken")
                        or account.get("refresh_token", ""),
                        "steam_name": account.get("account_name") or "Steam",
                    }
                    values = {
                        field: validate_field(field, value)
                        for field, value in values.items()
                    }
                except (ValueError, AttributeError, TypeError):
                    raise ValueError(
                        "账号文件缺少有效凭据。需要 SteamID、两个 Secret、Device ID 和移动端 Refresh Token；也可用 /addaccount 手动输入。"
                    ) from None
                await self.save_account(update.effective_user.id, values)
                context.user_data.pop("flow", None)
                await self.respond(update, f"已导入账号 {values['steam_name']}。")
            else:
                if context.user_data.get("flow"):
                    raise ValueError("请先用 /cancel 结束当前输入，再发送登录二维码。")
                qr_url = await asyncio.to_thread(decode_qr, data)
                await self.choose_accounts(update, context, "qr", qr_url=qr_url)
        except (ValueError, SteamError) as error:
            await self.respond(update, str(error))
        finally:
            if is_account:
                await self.remove_sensitive_message(message)

    async def with_access_token(self, session, account, operation):
        if not account.access_token:
            account.access_token = await self.steam.refresh_access_token(
                account.steamid, account.refresh_token
            )
            session.commit()
        try:
            return await operation(account.access_token)
        except AccessTokenExpired:
            account.access_token = await self.steam.refresh_access_token(
                account.steamid, account.refresh_token
            )
            session.commit()
            return await operation(account.access_token)

    async def show_confirmations(self, update, context, session, account, page=0):
        confirmations = await self.with_access_token(
            session,
            account,
            lambda token: self.steam.confirmation_request(
                account.steamid, account.identity_secret, token, account.device_id
            ),
        )
        keyboard = []
        page = min(max(0, page), max(0, (len(confirmations) - 1) // PAGE_SIZE))
        for confirmation in confirmations[page * PAGE_SIZE : (page + 1) * PAGE_SIZE]:
            label = f"{confirmation.get('type_name', '确认')} · {confirmation.get('headline', confirmation['id'])}"
            keyboard.append(
                [
                    self.button(
                        context, label, "detail", account.id, confirmation=confirmation
                    )
                ]
            )
        pages = [
            self.button(context, label, "confirm", account.id, page=target)
            for target, label in ((page - 1, "上一页"), (page + 1, "下一页"))
            if 0 <= target <= (len(confirmations) - 1) // PAGE_SIZE
        ]
        if pages:
            keyboard.append(pages)
        keyboard.append(
            [
                self.button(context, "刷新列表", "confirm", account.id),
                self.button(context, "切换账号", "choose", kind="confirm"),
            ]
        )
        await self.respond(
            update,
            f"{account.steam_name} · {len(confirmations)} 个待确认请求"
            if confirmations
            else f"{account.steam_name} · 没有待确认请求。",
            keyboard,
        )

    @authorized
    async def callback_query_handler(self, update, context):
        query = update.callback_query
        entry = context.user_data["pending"].get(query.data)
        if not entry:
            await query.answer(
                "按钮已过期或操作已完成，请重新发送命令。", show_alert=True
            )
            return
        await query.answer()
        action, payload = entry["action"], entry["payload"]
        if action == "cancel":
            context.user_data.clear()
            await self.choose_accounts(update, context, "list")
            return
        if action == "choose":
            await self.choose_accounts(update, context, **payload)
            return
        with self.sessions() as session:
            account = session.scalar(
                select(SteamAccount).where(
                    SteamAccount.id == entry["account_id"],
                    SteamAccount.user_id == update.effective_user.id,
                )
            )
            if not account:
                await self.respond(update, "账号已删除或不属于当前用户。")
                return
            try:
                if action == "code":
                    clock_note = ""
                    try:
                        timestamp = await self.steam.server_time()
                    except SteamError:
                        timestamp = int(time.time())
                        clock_note = "\nSteam 时间同步失败，已使用服务器时间。"
                    code = get_2fa_code(account.shared_secret, timestamp)
                    keyboard = [
                        [
                            InlineKeyboardButton(
                                "复制验证码", copy_text=CopyTextButton(code)
                            ),
                            self.button(context, "刷新", "code", account.id),
                        ]
                    ]
                    await self.respond(
                        update,
                        f"{escape(account.steam_name or account.steamid)}\n\n<code>{code}</code>\n\n生成时剩余 {30 - timestamp % 30} 秒，到期后点击刷新。{clock_note}",
                        keyboard,
                        html=True,
                    )
                elif action == "confirm":
                    await self.show_confirmations(
                        update, context, session, account, payload.get("page", 0)
                    )
                elif action == "detail":
                    confirmation = payload["confirmation"]
                    summary = confirmation.get("summary") or []
                    if isinstance(summary, list):
                        summary = "\n".join(map(str, summary))
                    text = (
                        f"{account.steam_name}\n类型：{confirmation.get('type_name', '确认')}\n"
                        f"标题：{confirmation.get('headline', '')}\n{summary}\n"
                        f"{confirmation.get('warn') or ''}"
                    )[:3500]
                    await self.respond(
                        update,
                        text,
                        [
                            [
                                self.button(
                                    context,
                                    "同意",
                                    "act",
                                    account.id,
                                    confirmation=confirmation,
                                    allow=True,
                                ),
                                self.button(
                                    context,
                                    "拒绝",
                                    "act",
                                    account.id,
                                    confirmation=confirmation,
                                    allow=False,
                                ),
                            ],
                            [self.button(context, "返回列表", "confirm", account.id)],
                        ],
                    )
                elif action == "act":
                    # Invalidate every button for this request before contacting Steam.
                    conf_id = str(payload["confirmation"]["id"])
                    for key, item in list(context.user_data["pending"].items()):
                        if (
                            item["account_id"] == account.id
                            and str(item["payload"].get("confirmation", {}).get("id"))
                            == conf_id
                        ):
                            del context.user_data["pending"][key]
                    await self.with_access_token(
                        session,
                        account,
                        lambda token: self.steam.confirmation_request(
                            account.steamid,
                            account.identity_secret,
                            token,
                            account.device_id,
                            payload["allow"],
                            payload["confirmation"],
                        ),
                    )
                    await self.respond(
                        update,
                        "请求已同意。" if payload["allow"] else "请求已拒绝。",
                        [[self.button(context, "返回列表", "confirm", account.id)]],
                    )
                elif action == "delete":
                    await self.respond(
                        update,
                        f"删除账号 {account.steam_name}？\n只删除机器人保存的凭据。",
                        [
                            [
                                self.button(
                                    context, "确认删除", "delete_yes", account.id
                                ),
                                self.button(context, "取消", "cancel"),
                            ]
                        ],
                    )
                elif action == "delete_yes":
                    session.delete(account)
                    session.commit()
                    context.user_data.clear()
                    await self.respond(update, "账号已删除。")
                elif action == "token":
                    context.user_data["flow"] = {
                        "kind": "token",
                        "account_id": account.id,
                        "expires": time.monotonic() + TTL,
                    }
                    await self.respond(
                        update,
                        f"请发送 {account.steam_name} 的新移动端 Refresh Token。可用 /cancel 取消。",
                    )
                elif action == "qr":
                    # Fetch request metadata before the user approves this login.
                    info = await self.with_access_token(
                        session,
                        account,
                        lambda token: self.steam.qr_info(token, payload["qr_url"]),
                    )
                    details = "\n".join(
                        f"{label}：{str(info.get(key) or '未知')[:200]}"
                        for key, label in (
                            ("device_friendly_name", "设备"),
                            ("ip", "IP"),
                            ("city", "城市"),
                            ("country", "国家/地区"),
                        )
                    )
                    await self.respond(
                        update,
                        f"使用 {account.steam_name} 批准这次登录？\n\n{details}\n\n仅在这是你发起的登录时确认。",
                        [
                            [
                                self.button(
                                    context,
                                    "确认登录",
                                    "qr_yes",
                                    account.id,
                                    qr_url=payload["qr_url"],
                                ),
                                self.button(context, "取消", "cancel"),
                            ]
                        ],
                    )
                elif action == "qr_yes":
                    # Consume all approvals for this QR, including duplicate previews.
                    for key, item in list(context.user_data["pending"].items()):
                        if item["payload"].get("qr_url") == payload["qr_url"]:
                            del context.user_data["pending"][key]
                    await self.with_access_token(
                        session,
                        account,
                        lambda token: self.steam.qr_login(
                            account.steamid,
                            account.shared_secret,
                            token,
                            payload["qr_url"],
                        ),
                    )
                    await self.respond(
                        update,
                        f"已批准 {account.steam_name} 的登录，请查看 Steam 登录页面。",
                    )
            except AccessTokenExpired:
                await self.respond(
                    update,
                    "Steam 登录凭据已失效，请用 /updatetoken 更新移动端 Refresh Token。",
                )
            except (SteamError, ValueError) as error:
                await self.respond(
                    update,
                    str(error),
                    [[self.button(context, "返回账号", "choose", kind="list")]],
                )

    async def error_handler(self, update, context):
        # Exception strings and tracebacks can contain bot tokens, cookies or SQL values.
        logger.error("Request failed (%s)", type(context.error).__name__)
        if update and update.effective_message:
            try:
                await self.respond(
                    update,
                    "处理失败，请稍后重试。若正在输入账号，可用 /cancel 重新开始。",
                )
            except TelegramError:
                pass

    def run(self):
        self.application.run_polling(
            allowed_updates=["message", "callback_query"], bootstrap_retries=3
        )


def main():
    os.umask(0o077)
    load_dotenv()
    logging.basicConfig(
        format="%(asctime)s %(levelname)s %(name)s: %(message)s", level=logging.INFO
    )
    for name in ("httpx", "httpcore", "apscheduler", "telegram", "sqlalchemy"):
        logging.getLogger(name).setLevel(logging.WARNING)
    try:
        token = os.environ["BOT_TOKEN"].strip()
        if token:
            for handler in logging.getLogger().handlers:
                handler.addFilter(RedactCredentials(token))
        users = {
            int(value.strip())
            for value in os.environ["ALLOWED_USERS"].split(",")
            if value.strip()
        }
        if (
            not re.fullmatch(r"[0-9]+:[A-Za-z0-9_-]+", token)
            or not users
            or any(user <= 0 for user in users)
        ):
            raise ValueError
        sessions = initialize_database()
        SteamAccountBot(token, users, sessions).run()
    except (KeyError, ValueError):
        raise SystemExit(
            "请检查 BOT_TOKEN、ALLOWED_USERS 和 ENCRYPTION_KEY 配置。"
        ) from None
    except CredentialError as error:
        raise SystemExit(str(error)) from None


if __name__ == "__main__":
    main()
