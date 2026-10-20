"""Steam requests and signing. Errors must never include response bodies or URLs."""

import base64
import binascii
import hashlib
import hmac
import json
import math
import re
import struct
import time

import httpx

from protobufs.steam_auth_pb2 import (
    CAuthentication_AccessToken_GenerateForApp_Request,
    CAuthentication_GetAuthSessionInfo_Request,
    CAuthentication_UpdateAuthSessionWithMobileConfirmation_Request,
)

API = "https://api.steampowered.com"
COMMUNITY = "https://steamcommunity.com/mobileconf"
MOBILE_HEADERS = {
    "User-Agent": "okhttp/4.9.2",
    "Cookie": "mobileClient=android; mobileClientVersion=777777 3.10.3",
}


class SteamError(RuntimeError):
    pass


class AccessTokenExpired(SteamError):
    pass


class InvalidMobileToken(SteamError):
    pass


def validate_login_token(token, steamid, refresh):
    """Check claims, then rely on Steam over TLS for authentication, not this decode."""
    try:
        if (
            not isinstance(token, str)
            or len(token) > 16384
            or not re.fullmatch(
                r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", token
            )
        ):
            raise ValueError
        payload = json.loads(base64.urlsafe_b64decode(token.split(".")[1] + "==="))
        audience = payload.get("aud", [])
        expiry = payload.get("exp")
        if (
            payload.get("sub") != str(steamid)
            or not isinstance(audience, list)
            or "mobile" not in audience
            or ("derive" in audience) != refresh
            or type(expiry) not in (int, float)
            or not math.isfinite(expiry)
        ):
            raise ValueError
        if expiry <= time.time():
            raise AccessTokenExpired(
                "Steam 登录凭据已过期，原有凭据未更新，请用 /login 重新登录。"
            )
        return token
    except (
        ValueError,
        TypeError,
        KeyError,
        binascii.Error,
        UnicodeError,
        AttributeError,
        RecursionError,
    ):
        raise InvalidMobileToken(
            "令牌与当前账号或移动端类型不匹配，原有凭据未更新。请用 /login 重新登录，或提供该账号的移动端 Refresh Token。"
        ) from None


def decode_secret(value):
    try:
        secret = base64.b64decode(value, validate=True)
        if len(secret) != 20:
            raise ValueError
        return secret
    except (ValueError, binascii.Error):
        raise ValueError(
            "Secret 应为 Base64 编码的 20 字节密钥，请检查复制内容。"
        ) from None


def parse_qr_url(url):
    match = re.fullmatch(r"https://s\.team/q/([0-9]{1,5})/([0-9]{1,20})/?", url)
    if not match:
        raise ValueError("未找到有效的 Steam 登录二维码。")
    version, client_id = map(int, match.groups())
    if not 0 < version < 2**16 or not 0 < client_id < 2**64:
        raise ValueError("Steam 登录二维码格式无效。")
    return version, client_id


def get_2fa_code(shared_secret, timestamp=None):
    timestamp = int(time.time() if timestamp is None else timestamp)
    digest = hmac.new(
        decode_secret(shared_secret), struct.pack(">Q", timestamp // 30), hashlib.sha1
    ).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    alphabet = "23456789BCDFGHJKMNPQRTVWXY"
    code = ""
    for _ in range(5):
        code += alphabet[value % len(alphabet)]
        value //= len(alphabet)
    return code


def generate_confirmation_hash_for_time(timestamp, tag, identity_secret):
    digest = hmac.new(
        decode_secret(identity_secret),
        struct.pack(">Q", timestamp) + tag.encode()[:32],
        hashlib.sha1,
    ).digest()
    return base64.b64encode(digest).decode()


class SteamClient:
    def __init__(self, client=None):
        self.http = client or httpx.AsyncClient(
            timeout=httpx.Timeout(20, connect=10), follow_redirects=False
        )
        self.time_offset = 0
        self.last_sync = None

    async def close(self):
        await self.http.aclose()

    async def request(self, method, url, **kwargs):
        try:
            response = await self.http.request(method, url, **kwargs)
        except httpx.RequestError:
            raise SteamError("连接 Steam 超时或网络异常，请稍后重试。") from None
        if response.status_code in (401, 403):
            raise AccessTokenExpired("Steam 登录凭据已失效。")
        if response.status_code != 200:
            raise SteamError(
                f"Steam 服务暂时不可用（HTTP {response.status_code}），请稍后重试。"
            )
        return response

    @staticmethod
    def json(response):
        try:
            data = response.json()
            if not isinstance(data, dict):
                raise ValueError
            return data
        except ValueError:
            raise SteamError("Steam 返回了无法识别的数据，请稍后重试。") from None

    async def server_time(self):
        if self.last_sync is None or time.monotonic() - self.last_sync > 300:
            response = await self.request(
                "POST", f"{API}/ITwoFactorService/QueryTime/v1/"
            )
            try:
                server_time = int(self.json(response)["response"]["server_time"])
            except (KeyError, TypeError, ValueError):
                raise SteamError("无法获取 Steam 时间，请稍后重试。") from None
            self.time_offset = server_time - time.time()
            self.last_sync = time.monotonic()
        return int(time.time() + self.time_offset)

    async def auth_request(self, method, message, access_token=None):
        params = {"format": "json"}
        if access_token:
            params["access_token"] = access_token
        response = await self.request(
            "POST",
            f"{API}/IAuthenticationService/{method}/v1/",
            params=params,
            headers=MOBILE_HEADERS,
            files={
                "input_protobuf_encoded": (
                    None,
                    base64.b64encode(message.SerializeToString()).decode(),
                )
            },
        )
        result = response.headers.get("X-eresult")
        if result in ("5", "15", "27"):
            raise AccessTokenExpired("Steam 登录凭据已失效。")
        if result in ("8", "29"):
            raise SteamError("二维码已过期或会话无效，请重新扫码。")
        if result == "84":
            raise SteamError("Steam 请求过于频繁，请稍后重试。")
        if result != "1":
            raise SteamError("Steam 未完成请求，请检查账号凭据或稍后重试。")
        payload = self.json(response).get("response")
        if not isinstance(payload, dict):
            raise SteamError("Steam 返回了无法识别的数据，请稍后重试。")
        return payload

    async def refresh_access_token(self, steamid, refresh_token):
        validate_login_token(refresh_token, steamid, True)
        message = CAuthentication_AccessToken_GenerateForApp_Request(
            steamid=int(steamid),
            refresh_token=refresh_token,
            renewal_type=0,
        )
        payload = await self.auth_request("GenerateAccessTokenForApp", message)
        token = payload.get("access_token")
        if not isinstance(token, str) or not token:
            raise AccessTokenExpired(
                "Refresh Token 无效或已过期，请用 /login 重新登录。"
            )
        return validate_login_token(token, steamid, False)

    async def qr_info(self, access_token, qr_url):
        _, client_id = parse_qr_url(qr_url)
        return await self.auth_request(
            "GetAuthSessionInfo",
            CAuthentication_GetAuthSessionInfo_Request(client_id=client_id),
            access_token,
        )

    async def qr_login(self, steamid, shared_secret, access_token, qr_url):
        version, client_id = parse_qr_url(qr_url)
        signature = hmac.new(
            decode_secret(shared_secret),
            struct.pack("<HQQ", version, client_id, int(steamid)),
            hashlib.sha256,
        ).digest()
        message = CAuthentication_UpdateAuthSessionWithMobileConfirmation_Request(
            version=version,
            client_id=client_id,
            steamid=int(steamid),
            signature=signature,
            confirm=True,
            persistence=1,
        )
        await self.auth_request(
            "UpdateAuthSessionWithMobileConfirmation", message, access_token
        )
        return True

    async def confirmation_request(
        self,
        steamid,
        identity_secret,
        access_token,
        device_id,
        operation=None,
        confirmation=None,
    ):
        timestamp = await self.server_time()
        tag = "list" if operation is None else ("accept" if operation else "reject")
        params = {
            "p": device_id,
            "a": steamid,
            "k": generate_confirmation_hash_for_time(timestamp, tag, identity_secret),
            "t": timestamp,
            "m": "react",
            "tag": tag,
        }
        headers = {
            "Cookie": f"steamLoginSecure={steamid}%7C%7C{access_token}",
            "User-Agent": "okhttp/4.9.2",
        }
        if operation is None:
            response = await self.request(
                "GET", f"{COMMUNITY}/getlist", params=params, headers=headers
            )
        else:
            params.update(
                {
                    "op": "allow" if operation else "cancel",
                    "cid[]": str(confirmation["id"]),
                    "ck[]": str(confirmation["nonce"]),
                }
            )
            response = await self.request(
                "POST", f"{COMMUNITY}/multiajaxop", data=params, headers=headers
            )
        data = self.json(response)
        if data.get("needauth") or data.get("needsauth"):
            raise AccessTokenExpired("Steam 登录凭据已失效。")
        if data.get("success") is not True:
            raise SteamError("Steam 未完成确认操作，请刷新列表检查请求状态。")
        if operation is not None:
            return True
        confirmations = data.get("conf", [])
        if not isinstance(confirmations, list) or any(
            not isinstance(c, dict) or not c.get("id") or not c.get("nonce")
            for c in confirmations
        ):
            raise SteamError("Steam 确认列表格式异常，请稍后重试。")
        return confirmations
