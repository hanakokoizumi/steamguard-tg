import base64
import hashlib
import hmac
import struct
from urllib.parse import parse_qs

import httpx
import pytest
from pyotp.contrib.steam import Steam

from protobufs.steam_auth_pb2 import (
    CAuthentication_AccessToken_GenerateForApp_Request,
    CAuthentication_GetAuthSessionInfo_Request,
    CAuthentication_UpdateAuthSessionWithMobileConfirmation_Request,
)
from utils import (
    AccessTokenExpired,
    SteamClient,
    SteamError,
    decode_secret,
    generate_confirmation_hash_for_time,
    get_2fa_code,
    parse_qr_url,
)

SECRET = base64.b64encode(b"01234567890123456789").decode()
STEAMID = "76561198000000001"


@pytest.mark.parametrize("timestamp", [0, 29, 30, 59, 60, 1234567890, 1792480000])
def test_codes_match_independent_implementation(timestamp):
    oracle = Steam(base64.b32encode(base64.b64decode(SECRET)).decode())
    assert get_2fa_code(SECRET, timestamp) == oracle.at(timestamp)


@pytest.mark.parametrize(
    "url", ["https://s.team/q/1/123", "https://s.team/q/2/18446744073709551615/"]
)
def test_valid_qr(url):
    assert parse_qr_url(url)[0] > 0


@pytest.mark.parametrize(
    "url",
    [
        "https://s.team.evil/q/1/123",
        "https://s.team/q/1/123?x=1",
        "https://s.team/q/1/1#fake",
        "http://s.team/q/1/123",
        "https://s.team/q/65536/123",
        "https://s.team/q/1/18446744073709551616",
        "https://s.team/q/1/0",
        "https://s.team/q/0/1",
    ],
)
def test_rejects_untrusted_qr(url):
    with pytest.raises(ValueError):
        parse_qr_url(url)


@pytest.mark.parametrize(
    "secret", ["bad", "", base64.b64encode(b"wrong-length").decode(), SECRET + "!"]
)
def test_validates_secret(secret):
    with pytest.raises(ValueError):
        decode_secret(secret)


def client(handler):
    return SteamClient(httpx.AsyncClient(transport=httpx.MockTransport(handler)))


def multipart_payload(request):
    # Decode the single protocol field without depending on multipart boundary randomness.
    return base64.b64decode(
        request.content.split(b"\r\n\r\n", 1)[1].split(b"\r\n", 1)[0]
    )


async def test_refresh_uses_current_proto_and_no_renewal():
    def handler(request):
        assert request.url.path.endswith("/GenerateAccessTokenForApp/v1/")
        msg = CAuthentication_AccessToken_GenerateForApp_Request.FromString(
            multipart_payload(request)
        )
        assert msg.steamid == int(STEAMID)
        assert msg.refresh_token == "refresh-secret"
        assert msg.renewal_type == 0
        return httpx.Response(
            200,
            headers={"x-eresult": "1"},
            json={"response": {"access_token": "new-token"}},
        )

    steam = client(handler)
    assert await steam.refresh_access_token(STEAMID, "refresh-secret") == "new-token"
    await steam.close()


async def test_qr_signature_and_metadata():
    def handler(request):
        assert request.url.params["access_token"] == "access-secret"
        if "GetAuthSessionInfo" in request.url.path:
            msg = CAuthentication_GetAuthSessionInfo_Request.FromString(
                multipart_payload(request)
            )
            assert msg.client_id == 123
            body = {"device_friendly_name": "Firefox", "ip": "127.0.0.1"}
        else:
            msg = CAuthentication_UpdateAuthSessionWithMobileConfirmation_Request.FromString(
                multipart_payload(request)
            )
            expected = hmac.new(
                base64.b64decode(SECRET),
                struct.pack("<HQQ", 1, 123, int(STEAMID)),
                hashlib.sha256,
            ).digest()
            assert msg.signature == expected
            assert msg.confirm is True
            assert msg.persistence == 1
            body = {}
        return httpx.Response(200, headers={"x-eresult": "1"}, json={"response": body})

    steam = client(handler)
    assert (await steam.qr_info("access-secret", "https://s.team/q/1/123"))[
        "ip"
    ] == "127.0.0.1"
    assert await steam.qr_login(
        STEAMID, SECRET, "access-secret", "https://s.team/q/1/123"
    )
    await steam.close()


@pytest.mark.parametrize(
    "operation,tag", [(None, "list"), (True, "accept"), (False, "reject")]
)
async def test_confirmation_signatures(operation, tag):
    def handler(request):
        if "QueryTime" in request.url.path:
            return httpx.Response(200, json={"response": {"server_time": 1700000000}})
        params = (
            dict(request.url.params)
            if operation is None
            else {k: v[0] for k, v in parse_qs(request.content.decode()).items()}
        )
        assert params["tag"] == tag
        assert params["k"] == generate_confirmation_hash_for_time(
            int(params["t"]), tag, SECRET
        )
        assert (
            request.headers["cookie"]
            == f"steamLoginSecure={STEAMID}%7C%7Caccess-secret"
        )
        if operation is None:
            assert request.method == "GET"
            return httpx.Response(200, json={"success": True, "conf": []})
        assert request.method == "POST"
        assert params["op"] == ("allow" if operation else "cancel")
        assert params["cid[]"] == "123"
        assert params["ck[]"] == "secret-nonce"
        return httpx.Response(200, json={"success": True, "needauth": False})

    steam = client(handler)
    result = await steam.confirmation_request(
        STEAMID,
        SECRET,
        "access-secret",
        "android:test",
        operation,
        {"id": "123", "nonce": "secret-nonce"},
    )
    assert result == ([] if operation is None else True)
    await steam.close()


@pytest.mark.parametrize(
    "result,exception",
    [
        ("15", AccessTokenExpired),
        ("27", AccessTokenExpired),
        ("29", SteamError),
        ("84", SteamError),
        ("2", SteamError),
    ],
)
async def test_api_errors_do_not_leak_credentials(result, exception):
    steam = client(
        lambda r: httpx.Response(
            200,
            headers={"x-eresult": result},
            json={"response": {"secret": "sensitive"}},
        )
    )
    with pytest.raises(exception) as error:
        await steam.refresh_access_token(STEAMID, "sensitive")
    assert "sensitive" not in str(error.value)
    await steam.close()


async def test_confirmation_needauth_true_expires():
    steam = client(
        lambda r: httpx.Response(200, json={"needauth": True, "success": False})
    )
    steam.last_sync = __import__("time").monotonic()
    with pytest.raises(AccessTokenExpired):
        await steam.confirmation_request(STEAMID, SECRET, "access", "device")
    await steam.close()


async def test_network_failure_has_safe_error():
    def handler(request):
        raise httpx.ConnectError("sensitive-token", request=request)

    steam = client(handler)
    with pytest.raises(SteamError) as error:
        await steam.refresh_access_token(STEAMID, "sensitive-token")
    assert "sensitive-token" not in str(error.value)
    await steam.close()
