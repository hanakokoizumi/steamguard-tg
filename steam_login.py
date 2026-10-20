"""Password login through Steam's MobileApp authentication endpoints."""

import base64
import binascii
import math
import re

from cryptography.hazmat.primitives.asymmetric import padding, rsa

from protobufs.steam_auth_pb2 import (
    CAuthentication_BeginAuthSessionViaCredentials_Request,
    CAuthentication_DeviceDetails,
    CAuthentication_GetPasswordRSAPublicKey_Request,
    CAuthentication_PollAuthSessionStatus_Request,
    CAuthentication_UpdateAuthSessionWithSteamGuardCode_Request,
)
from utils import API, MOBILE_HEADERS, AccessTokenExpired, SteamError
from utils import validate_login_token as validate_login_token


class LoginError(SteamError):
    def __init__(self, result):
        self.result = str(result)
        messages = {
            "5": "用户名或密码错误，请用 /login 重新登录。",
            "9": "登录会话已失效，请用 /login 重新开始。",
            "15": "Steam 拒绝了这次登录，请检查账号状态后重试。",
            "27": "登录会话已过期，请用 /login 重新开始。",
            "29": "登录会话已过期，请用 /login 重新开始。",
            "65": "验证码不正确，请重新输入。",
            "71": "验证码已过期，请输入新的验证码。",
            "84": "Steam 请求过于频繁，请稍后再用 /login 重试。",
            "87": "Steam 暂时限制了登录，请稍后再试。",
            "88": "Steam Guard 验证码不正确，请输入新的验证码。",
            "101": "Steam 要求额外的人机验证，请先在 Steam 官方网站完成验证后重试。",
        }
        super().__init__(
            messages.get(self.result, "Steam 未完成登录，请稍后用 /login 重试。")
        )

    @property
    def code_retryable(self):
        return self.result in ("65", "71", "88")


class MobileLogin:
    def __init__(self, steam):
        self.steam = steam

    async def call(self, method, message, get=False):
        params = {"format": "json"}
        encoded = base64.b64encode(message.SerializeToString()).decode()
        kwargs = {"params": params, "headers": MOBILE_HEADERS}
        if get:
            params["input_protobuf_encoded"] = encoded
            params["origin"] = "SteamMobile"
        else:
            kwargs["files"] = {"input_protobuf_encoded": (None, encoded)}
        try:
            response = await self.steam.request(
                "GET" if get else "POST",
                f"{API}/IAuthenticationService/{method}/v1/",
                **kwargs,
            )
        except AccessTokenExpired:
            raise LoginError("15") from None
        if response.headers.get("X-eresult") != "1":
            raise LoginError(response.headers.get("X-eresult"))
        payload = self.steam.json(response).get("response")
        if not isinstance(payload, dict):
            raise SteamError("Steam 登录响应格式异常，请用 /login 重试。")
        if payload.get("agreement_session_url"):
            raise SteamError(
                "Steam 要求确认新的协议，请先在 Steam 官方网站完成确认后重新登录。"
            )
        return payload

    async def begin(self, username, password):
        key = await self.call(
            "GetPasswordRSAPublicKey",
            CAuthentication_GetPasswordRSAPublicKey_Request(account_name=username),
            get=True,
        )
        try:
            modulus, exponent = (
                int(key["publickey_mod"], 16),
                int(key["publickey_exp"], 16),
            )
            if not 1024 <= modulus.bit_length() <= 8192:
                raise ValueError
            public_key = rsa.RSAPublicNumbers(exponent, modulus).public_key()
            encrypted = base64.b64encode(
                public_key.encrypt(password.encode("utf-8"), padding.PKCS1v15())
            ).decode()
            timestamp = int(key["timestamp"])
        except (KeyError, TypeError, ValueError, OverflowError):
            raise SteamError(
                "无法使用 Steam 提供的公钥加密密码，请检查密码长度或稍后重试。"
            ) from None
        # Only the RSA ciphertext goes into this request; no password enters the login state.
        del password
        payload = await self.call(
            "BeginAuthSessionViaCredentials",
            CAuthentication_BeginAuthSessionViaCredentials_Request(
                device_friendly_name="steamguard-tg",
                account_name=username,
                encrypted_password=encrypted,
                encryption_timestamp=timestamp,
                remember_login=True,
                platform_type=3,
                persistence=1,
                website_id="Mobile",
                device_details=CAuthentication_DeviceDetails(
                    device_friendly_name="steamguard-tg",
                    platform_type=3,
                    os_type=-500,
                    gaming_device_type=528,
                    app_type=1,
                ),
            ),
        )
        try:
            client_id = int(payload["client_id"])
            steamid = str(payload["steamid"])
            request_id = base64.b64decode(payload["request_id"], validate=True)
            interval = float(payload.get("interval", 5))
            guards = [
                int(item["confirmation_type"])
                for item in payload["allowed_confirmations"]
            ]
            if (
                not 0 < client_id < 2**64
                or not re.fullmatch(r"\d{17}", steamid)
                or not request_id
                or len(request_id) > 4096
                or not math.isfinite(interval)
            ):
                raise ValueError
        except (KeyError, TypeError, ValueError, binascii.Error):
            raise SteamError("Steam 登录会话数据异常，请用 /login 重试。") from None
        return {
            "client_id": client_id,
            "steamid": steamid,
            "request_id": request_id,
            "interval": max(2, min(30, interval)),
            "guards": guards,
        }

    async def submit_code(self, state, code):
        await self.call(
            "UpdateAuthSessionWithSteamGuardCode",
            CAuthentication_UpdateAuthSessionWithSteamGuardCode_Request(
                client_id=state["client_id"],
                steamid=int(state["steamid"]),
                code=code,
                code_type=state["code_type"],
            ),
        )

    async def poll(self, state):
        payload = await self.call(
            "PollAuthSessionStatus",
            CAuthentication_PollAuthSessionStatus_Request(
                client_id=state["client_id"], request_id=state["request_id"]
            ),
        )
        if payload.get("new_client_id"):
            try:
                client_id = int(payload["new_client_id"])
                if not 0 < client_id < 2**64:
                    raise ValueError
                state["client_id"] = client_id
            except (ValueError, TypeError):
                raise SteamError("Steam 登录会话发生异常，请用 /login 重试。") from None
        if not payload.get("refresh_token"):
            return None
        refresh = validate_login_token(payload["refresh_token"], state["steamid"], True)
        access = payload.get("access_token") or await self.steam.refresh_access_token(
            state["steamid"], refresh
        )
        return refresh, validate_login_token(access, state["steamid"], False)
