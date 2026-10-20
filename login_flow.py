"""Telegram conversation for reconnecting an existing Steam account."""

import asyncio
import re
import secrets
import time

from sqlalchemy import select

from database import SteamAccount
from steam_login import LoginError
from utils import SteamError, get_2fa_code

LOGIN_TTL = 180
MAX_CODE_ATTEMPTS = 5
CANCELLED = object()


class LoginStateError(SteamError):
    pass


class LoginFlow:
    def login_buttons(self, context, flow):
        buttons = []
        if flow.get("stage") == "code" and flow["session"]["code_type"] == 3:
            buttons.append(
                [
                    self.button(
                        context,
                        "使用已保存密钥验证",
                        "login_auto",
                        flow["account_id"],
                        flow_id=flow["id"],
                    )
                ]
            )
        buttons.append([self.button(context, "取消登录", "cancel")])
        return buttons

    @staticmethod
    def login_active(data, flow):
        return data.get("flow") is flow and flow["expires"] > time.monotonic()

    async def begin_account_login(self, update, context, account):
        context.user_data.pop("expired_login", None)
        context.user_data.pop("expired_input", None)
        flow = {
            "kind": "login",
            "stage": "username",
            "id": secrets.token_urlsafe(12),
            "account_id": account.id,
            "steamid": account.steamid,
            "label": account.steam_name or account.steamid,
            "expires": time.monotonic() + 600,
        }
        context.user_data["flow"] = flow
        await self.respond(
            update,
            f"为 {flow['label']} 登录 Steam。\n请输入 Steam 登录用户名（不是昵称或邮箱）。可用 /cancel 取消。",
            self.login_buttons(context, flow),
        )

    def allow_login_attempt(self, user_id):
        now = time.monotonic()
        count, start = self.login_attempts.get(user_id, (0, now))
        if now - start >= 600:
            count, start = 0, now
        if count >= 5:
            return False
        self.login_attempts[user_id] = count + 1, start
        return True

    async def handle_login_input(self, update, context, flow):
        text = update.effective_message.text
        stage = flow["stage"]
        if stage == "username":
            username = text.strip()
            if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", username):
                await self.respond(update, "请输入 Steam 登录用户名，不能包含空格。")
                return
            flow.update(
                username=username, stage="password", expires=time.monotonic() + 600
            )
            await self.respond(
                update,
                "请发送 Steam 密码（包括开头的 / 和空格）。收到后会立即尝试删除消息，密码只用于这次登录，不写入数据库。\n退出请点“取消登录”或发送 /cancel。\nTelegram 机器人私聊不是端到端加密。",
                self.login_buttons(context, flow),
            )
            return
        # The authorized input wrapper deletes passwords/codes before rate limiting.
        if stage == "password":
            if not text or len(text.encode("utf-8")) > 256:
                await self.respond(update, "密码不能为空或超过 256 字节，请重新输入。")
                return
            if not self.allow_login_attempt(update.effective_user.id):
                context.user_data.pop("flow", None)
                await self.respond(
                    update, "本用户 10 分钟内已尝试登录 5 次，请稍后再试。"
                )
                return
            username = flow.pop("username")
            flow["stage"] = "busy"
            try:
                state = await self.mobile_login.begin(username, text)
                if not self.login_active(context.user_data, flow):
                    return
                if state["steamid"] != flow["steamid"]:
                    raise SteamError(
                        "该用户名的 SteamID 与所选账号不一致，原有凭据未更新。请用 /login 重新选择。"
                    )
                flow.update(
                    session=state,
                    expires=time.monotonic() + LOGIN_TTL,
                    attempts=0,
                    poll_errors=0,
                )
                if 3 in state["guards"] or 2 in state["guards"]:
                    state["code_type"] = 3 if 3 in state["guards"] else 2
                    flow["stage"] = "code"
                    prompt = (
                        "请输入 5 位 Steam Guard 验证码，或点击下面的按钮使用已保存密钥验证。"
                        if state["code_type"] == 3
                        else "请输入 Steam 发往账号邮箱的 5 位验证码。"
                    )
                    await self.respond(
                        update,
                        prompt + "\n本次登录会话 3 分钟后过期，可用 /cancel 取消。",
                        self.login_buttons(context, flow),
                    )
                elif 1 in state["guards"] or 5 in state["guards"]:
                    flow["stage"] = "pending"
                    text = await self.poll_login_once(
                        context.user_data, flow, update.effective_user.id
                    )
                    if text is CANCELLED:
                        return
                    if text is None:
                        self.schedule_login_poll(update.effective_user.id, flow)
                        text = (
                            "Steam 要求邮件确认，请在邮箱中批准这次登录，机器人会自动检查结果。"
                            if 5 in state["guards"]
                            else "Steam 已接受登录，正在等待令牌。"
                        )
                    await self.respond(update, text)
                else:
                    raise SteamError(
                        "Steam 这次仅提供设备确认，未提供验证码登录。请稍后用 /login 重试；机器人无法替代 Steam 要求的额外验证。"
                    )
            except SteamError as error:
                if context.user_data.get("flow") is flow:
                    context.user_data.pop("flow", None)
                    await self.respond(update, str(error))
        elif stage == "code":
            code = text.strip().upper()
            if not re.fullmatch(r"[A-Z0-9]{5}", code):
                await self.respond(
                    update,
                    "验证码应为 5 位英文字母或数字，请重新输入。",
                    self.login_buttons(context, flow),
                )
                return
            await self.submit_login_code(update, context, flow, code)
        else:
            await self.respond(
                update, "正在等待 Steam 登录结果，无需重复输入。可用 /cancel 取消。"
            )

    async def automatic_login_code(self, update, context, account, flow_id):
        flow = context.user_data.get("flow")
        if (
            not flow
            or flow.get("kind") != "login"
            or flow.get("id") != flow_id
            or flow.get("account_id") != account.id
            or flow.get("stage") != "code"
            or flow["session"]["code_type"] != 3
        ):
            await self.respond(
                update, "这次登录已结束或步骤已变更，请用 /login 重新开始。"
            )
            return
        try:
            timestamp = await self.steam.server_time()
            code = get_2fa_code(account.shared_secret, timestamp)
        except (SteamError, ValueError):
            await self.respond(
                update,
                "未能生成验证码，请稍后重试或手动输入 5 位验证码。",
                self.login_buttons(context, flow),
            )
            return
        if self.login_active(context.user_data, flow):
            await self.submit_login_code(update, context, flow, code)

    async def submit_login_code(self, update, context, flow, code):
        if not self.login_active(context.user_data, flow):
            return
        flow["attempts"] += 1
        flow["stage"] = "busy"
        try:
            await self.mobile_login.submit_code(flow["session"], code)
            if not self.login_active(context.user_data, flow):
                return
            flow["stage"] = "pending"
            text = await self.poll_login_once(
                context.user_data, flow, update.effective_user.id
            )
            if text is CANCELLED:
                return
            if text is None:
                self.schedule_login_poll(update.effective_user.id, flow)
                text = "验证码已提交，正在等待 Steam 完成登录；结果会自动发送，可用 /cancel 取消。"
            await self.respond(update, text)
        except SteamError as error:
            if context.user_data.get("flow") is not flow:
                return
            if (
                flow["attempts"] >= MAX_CODE_ATTEMPTS
                or isinstance(error, LoginStateError)
                or (isinstance(error, LoginError) and not error.code_retryable)
            ):
                context.user_data.pop("flow", None)
                await self.respond(
                    update,
                    "验证码尝试已达 5 次，请用 /login 重新开始。"
                    if flow["attempts"] >= MAX_CODE_ATTEMPTS
                    else str(error),
                )
            else:
                flow["stage"] = "code"
                await self.respond(
                    update, str(error), self.login_buttons(context, flow)
                )

    async def poll_login_once(self, data, flow, user_id):
        lock = self.login_locks.setdefault(user_id, asyncio.Lock())
        async with lock:
            if not self.login_active(data, flow):
                return CANCELLED
            tokens = await self.mobile_login.poll(flow["session"])
            # /cancel or a new command may have arrived while Steam was responding.
            if not self.login_active(data, flow):
                return CANCELLED
            if tokens is None:
                return None
            with self.sessions() as session:
                account = session.scalar(
                    select(SteamAccount).where(
                        SteamAccount.id == flow["account_id"],
                        SteamAccount.user_id == user_id,
                        SteamAccount.steamid == flow["steamid"],
                    )
                )
                if account is None:
                    raise LoginStateError("账号已删除，登录结果未保存。")
                account.refresh_token, account.access_token = tokens
                session.commit()
            data.pop("flow", None)
            return f"{flow['label']} 登录成功，凭据已更新。\n可用 /confirm 处理确认请求，或发送 Steam 登录二维码。"

    def schedule_login_poll(self, user_id, flow):
        name = f"login:{user_id}:{flow['id']}"
        if not self.application.job_queue.get_jobs_by_name(name):
            self.application.job_queue.run_once(
                self.login_poll_job,
                when=min(
                    flow["session"]["interval"],
                    max(0.1, flow["expires"] - time.monotonic()),
                ),
                user_id=user_id,
                chat_id=user_id,
                name=name,
                data={"flow_id": flow["id"]},
            )

    async def login_poll_job(self, context):
        data = context.user_data
        flow = data.get("flow") if data else None
        if (
            not flow
            or flow.get("id") != context.job.data["flow_id"]
            or flow.get("stage") != "pending"
        ):
            return
        if not self.login_active(data, flow):
            data["expired_login"] = time.monotonic() + 600
            data.pop("flow", None)
            await context.bot.send_message(
                context.job.chat_id,
                "Steam 登录已超时，请用 /login 重新开始。",
                protect_content=True,
            )
            return
        try:
            text = await self.poll_login_once(data, flow, context.job.user_id)
        except SteamError as error:
            if data.get("flow") is not flow:
                return
            flow["poll_errors"] += 1
            if (
                isinstance(error, (LoginError, LoginStateError))
                or flow["poll_errors"] >= 3
            ):
                data.pop("flow", None)
                text = str(error)
            else:
                text = None
        if text is not None:
            if text is CANCELLED:
                return
            # A cancelled or replaced session must not send a late completion notice.
            if data.get("flow") not in (None, flow):
                return
            await context.bot.send_message(
                context.job.chat_id, text, protect_content=True
            )
        elif self.login_active(data, flow):
            # The running one-shot job still exists in APScheduler until it returns.
            self.application.job_queue.run_once(
                self.login_poll_job,
                when=min(
                    flow["session"]["interval"],
                    max(0.1, flow["expires"] - time.monotonic()),
                ),
                user_id=context.job.user_id,
                chat_id=context.job.chat_id,
                name=context.job.name,
                data=context.job.data,
            )
