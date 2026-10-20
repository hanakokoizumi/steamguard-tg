import base64
import json
import time

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from protobufs.steam_auth_pb2 import (
    CAuthentication_BeginAuthSessionViaCredentials_Request,
    CAuthentication_GetPasswordRSAPublicKey_Request,
    CAuthentication_PollAuthSessionStatus_Request,
    CAuthentication_UpdateAuthSessionWithSteamGuardCode_Request,
)
from steam_login import LoginError, MobileLogin, validate_login_token
from utils import SteamClient, SteamError

STEAMID = "76561198000000001"
FUTURE = int(time.time()) + 3600


def token(steamid=STEAMID, refresh=True, audience=None, expiry=None):
    payload = {
        "sub": steamid,
        "aud": audience
        if audience is not None
        else (["web", "mobile", "derive", "renew"] if refresh else ["web", "mobile"]),
        "exp": expiry if expiry is not None else FUTURE,
    }
    return (
        "header."
        + base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        + ".signature"
    )


def encoded(request):
    if request.method == "GET":
        return base64.b64decode(request.url.params["input_protobuf_encoded"])
    return base64.b64decode(
        request.content.split(b"\r\n\r\n", 1)[1].split(b"\r\n", 1)[0]
    )


def response(body, result="1"):
    return httpx.Response(200, headers={"x-eresult": result}, json={"response": body})


@pytest.fixture(scope="module")
def key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


async def test_full_password_code_poll_protocol(key):
    calls = []
    password = "  Complex密码 with spaces  "

    def handler(request):
        method = request.url.path.split("/")[-3]
        calls.append(method)
        assert request.headers["cookie"].startswith("mobileClient=android;")
        assert password.encode() not in request.content
        if method == "GetPasswordRSAPublicKey":
            assert request.method == "GET"
            msg = CAuthentication_GetPasswordRSAPublicKey_Request.FromString(
                encoded(request)
            )
            assert msg.account_name == "login_name"
            assert request.url.params["origin"] == "SteamMobile"
            numbers = key.public_key().public_numbers()
            return response(
                {
                    "publickey_mod": format(numbers.n, "x"),
                    "publickey_exp": format(numbers.e, "x"),
                    "timestamp": "123456789",
                }
            )
        if method == "BeginAuthSessionViaCredentials":
            msg = CAuthentication_BeginAuthSessionViaCredentials_Request.FromString(
                encoded(request)
            )
            assert msg.account_name == "login_name"
            assert (
                key.decrypt(
                    base64.b64decode(msg.encrypted_password), padding.PKCS1v15()
                ).decode()
                == password
            )
            assert msg.encryption_timestamp == 123456789
            assert msg.platform_type == msg.device_details.platform_type == 3
            assert msg.persistence == 1 and msg.remember_login
            assert msg.website_id == "Mobile"
            assert msg.device_details.device_friendly_name == "steamguard-tg"
            return response(
                {
                    "client_id": "123",
                    "request_id": base64.b64encode(b"request-id").decode(),
                    "steamid": STEAMID,
                    "interval": 4,
                    "allowed_confirmations": [
                        {"confirmation_type": 3},
                        {"confirmation_type": 4},
                    ],
                }
            )
        if method == "UpdateAuthSessionWithSteamGuardCode":
            msg = (
                CAuthentication_UpdateAuthSessionWithSteamGuardCode_Request.FromString(
                    encoded(request)
                )
            )
            assert msg.client_id == 123 and msg.steamid == int(STEAMID)
            assert msg.code == "2AB3C" and msg.code_type == 3
            return response({})
        assert method == "PollAuthSessionStatus"
        msg = CAuthentication_PollAuthSessionStatus_Request.FromString(encoded(request))
        assert msg.request_id == b"request-id"
        if calls.count(method) == 1:
            assert msg.client_id == 123
            return response({"new_client_id": "456"})
        assert msg.client_id == 456
        return response(
            {"refresh_token": token(), "access_token": token(refresh=False)}
        )

    steam = SteamClient(httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    mobile = MobileLogin(steam)
    state = await mobile.begin("login_name", password)
    assert "password" not in state and password not in repr(state)
    state["code_type"] = 3
    await mobile.submit_code(state, "2AB3C")
    assert await mobile.poll(state) is None
    refresh, access = await mobile.poll(state)
    assert refresh == token() and access == token(refresh=False)
    await steam.close()


@pytest.mark.parametrize(
    "code,retryable",
    [
        ("5", False),
        ("65", True),
        ("71", True),
        ("88", True),
        ("84", False),
        ("101", False),
        ("999", False),
    ],
)
async def test_login_errors_are_specific_and_safe(code, retryable):
    steam = SteamClient(
        httpx.AsyncClient(
            transport=httpx.MockTransport(
                lambda r: response({"secret": "raw-private-body"}, code)
            )
        )
    )
    with pytest.raises(LoginError) as error:
        await MobileLogin(steam).call(
            "GetPasswordRSAPublicKey",
            CAuthentication_GetPasswordRSAPublicKey_Request(account_name="test"),
            get=True,
        )
    assert error.value.code_retryable == retryable
    assert "raw-private-body" not in str(error.value)
    if code == "5":
        assert "用户名或密码" in str(error.value)
    await steam.close()


@pytest.mark.parametrize(
    "bad",
    [
        "not-a-token",
        token(steamid="76561198000000002"),
        token(audience=["web", "client", "derive"]),
        token(refresh=False),
        token(expiry=1),
        "header." + base64.urlsafe_b64encode(b"[]").decode() + ".signature",
    ],
)
def test_unusable_refresh_tokens_are_rejected(bad):
    with pytest.raises(SteamError, match="未更新"):
        validate_login_token(bad, STEAMID, True)


async def test_missing_access_token_is_refreshed():
    calls = []

    def handler(request):
        calls.append(request.url.path)
        if "PollAuthSessionStatus" in request.url.path:
            return response({"refresh_token": token()})
        assert "GenerateAccessTokenForApp" in request.url.path
        return response({"access_token": token(refresh=False)})

    steam = SteamClient(httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    result = await MobileLogin(steam).poll(
        {"client_id": 123, "request_id": b"id", "steamid": STEAMID}
    )
    assert result == (token(), token(refresh=False))
    assert len(calls) == 2
    await steam.close()


@pytest.mark.parametrize("code_type", [2, 3])
async def test_email_and_device_codes_have_correct_type(code_type):
    def handler(request):
        msg = CAuthentication_UpdateAuthSessionWithSteamGuardCode_Request.FromString(
            encoded(request)
        )
        assert msg.code_type == code_type and msg.code == "AB123"
        return response({})

    steam = SteamClient(httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    await MobileLogin(steam).submit_code(
        {"client_id": 123, "steamid": STEAMID, "code_type": code_type}, "AB123"
    )
    await steam.close()


async def test_http_denial_is_a_login_error():
    steam = SteamClient(
        httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(403)))
    )
    with pytest.raises(LoginError, match="拒绝"):
        await MobileLogin(steam).call(
            "GetPasswordRSAPublicKey",
            CAuthentication_GetPasswordRSAPublicKey_Request(account_name="test"),
            get=True,
        )
    await steam.close()
