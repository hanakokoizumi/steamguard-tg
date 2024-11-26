import struct
from protobufs.steammessages_auth.steamclient_pb2 import *
import requests
import hmac
import base64
import hashlib
from steam_totp import generate_twofactor_code_for_time

def get_2fa_code(shared_secret):
    return generate_twofactor_code_for_time(shared_secret=shared_secret)

def qr_login(steamid, shared_secret, access_token, qr_url):
    if not qr_url.startswith('https://s.team/q/'):
        raise Exception('Invalid QR code url')
    if qr_url[-1] == '/':
        qr_url = qr_url[:-1]
    parts = qr_url.split('/')
    if len(parts) != 6:
        raise Exception('Invalid QR code url')
    version = parts[4]
    client_id = parts[5]
    signature_data = bytearray(2 + 8 + 8)
    struct.pack_into("<H", signature_data, 0, int(version))
    struct.pack_into("<Q", signature_data, 2, int(client_id))
    struct.pack_into("<Q", signature_data, 10, int(steamid))
    signature = hmac.new(base64.b64decode(shared_secret), signature_data, hashlib.sha256).digest()
    message = CAuthentication_UpdateAuthSessionWithMobileConfirmation_Request(
        version=int(version),
        client_id=int(client_id),
        steamid=int(steamid),
        signature=signature,
        confirm=1,
        persistence=1
    )

    resp = requests.post(
        'https://api.steampowered.com/IAuthenticationService/UpdateAuthSessionWithMobileConfirmation/v1/',
        params={'access_token': access_token},
        data={'input_protobuf_encoded': str(base64.b64encode(message.SerializeToString()), 'utf8')}, files={})
    if resp.status_code != 200:
        raise AccessTokenExpired()
    if 'X-eresult' in resp.headers and resp.headers['X-eresult'] == '1':
        return True
    elif 'X-eresult' in resp.headers and resp.headers['X-eresult'] == '29':
        return False
    elif 'X-eresult' in resp.headers:
        raise Exception(f'Error code: {resp.headers["X-eresult"]}')
    raise Exception(resp.json())

def refresh_access_token(steamid, refresh_token):
    resp = requests.post('https://api.steampowered.com/IAuthenticationService/GenerateAccessTokenForApp/v1', data={
        'steamid': steamid,
        'refresh_token': refresh_token
    }).json()
    if 'response' in resp and 'access_token' in resp['response']:
        return resp['response']['access_token']

class AccessTokenExpired(Exception):
    pass
