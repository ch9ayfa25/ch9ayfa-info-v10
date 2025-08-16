import asyncio
import time
import json
import base64
from collections import defaultdict
from functools import wraps
from typing import Tuple

import httpx
from flask import Flask, request, jsonify
from flask_cors import CORS
from cachetools import TTLCache
from google.protobuf import json_format, message
from google.protobuf.message import Message
from Crypto.Cipher import AES

from proto import FreeFire_pb2, main_pb2, AccountPersonalShow_pb2


# =======================
# CONFIGURATION
# =======================

# AES Keys
MAIN_KEY = base64.b64decode('WWcmdGMlREV1aDYlWmNeOA==')
MAIN_IV = base64.b64decode('Nm95WkRyMjJFM3ljaGpNJQ==')

# Game/API Settings
RELEASEVERSION = "OB50"
USERAGENT = "Dalvik/2.1.0 (Linux; U; Android 13; CPH2095 Build/RKQ1.211119.001)"

# Account
GUEST_ACCOUNT = "uid=3998786367&password=7577A5E2F529AFE6DB59FDB613A673BE65E05A0CD01E11304F7CC10065BC8FBD"
SUPPORTED_REGIONS = {"ME"}

# Flask & Cache
app = Flask(__name__)
CORS(app)
cache = TTLCache(maxsize=100, ttl=300)
cached_tokens = defaultdict(dict)


# =======================
# HELPER FUNCTIONS
# =======================

def pad(text: bytes) -> bytes:
    """PKCS#7 padding for AES."""
    padding_length = AES.block_size - (len(text) % AES.block_size)
    return text + bytes([padding_length] * padding_length)


def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    """Encrypt with AES-CBC."""
    aes = AES.new(key, AES.MODE_CBC, iv)
    return aes.encrypt(pad(plaintext))


def decode_protobuf(encoded_data: bytes, message_type: message.Message) -> message.Message:
    """Decode protobuf bytes into a message instance."""
    instance = message_type()
    instance.ParseFromString(encoded_data)
    return instance


async def json_to_proto(json_data: str, proto_message: Message) -> bytes:
    """Convert JSON to protobuf bytes."""
    json_format.ParseDict(json.loads(json_data), proto_message)
    return proto_message.SerializeToString()


def get_account_credentials(region: str) -> str:
    """Return ME account credentials."""
    return GUEST_ACCOUNT


# =======================
# TOKEN GENERATION
# =======================

async def get_access_token(account: str):
    """Get OAuth access token for guest account."""
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    payload = account + (
        "&response_type=token&client_type=2&client_secret=2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3"
        "&client_id=100067"
    )
    headers = {
        'User-Agent': USERAGENT,
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Content-Type': "application/x-www-form-urlencoded"
    }
    async with httpx.AsyncClient() as client:
        resp = await client.post(url, data=payload, headers=headers)
        data = resp.json()
        return data.get("access_token", "0"), data.get("open_id", "0")


async def create_jwt(region: str):
    """Generate JWT for ME region."""
    account = get_account_credentials(region)
    token_val, open_id = await get_access_token(account)

    # Build protobuf login request
    body = json.dumps({
        "open_id": open_id,
        "open_id_type": "4",
        "login_token": token_val,
        "orign_platform_type": "4"
    })
    proto_bytes = await json_to_proto(body, FreeFire_pb2.LoginReq())

    # Encrypt request
    payload = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, proto_bytes)

    # Send login request
    url = "https://loginbp.ggblueshark.com/MajorLogin"
    headers = {
        'User-Agent': USERAGENT,
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Content-Type': "application/octet-stream",
        'Expect': "100-continue",
        'X-Unity-Version': "2018.4.11f1",
        'X-GA': "v1 1",
        'ReleaseVersion': RELEASEVERSION
    }
    async with httpx.AsyncClient() as client:
        resp = await client.post(url, data=payload, headers=headers)
        msg = json.loads(json_format.MessageToJson(decode_protobuf(resp.content, FreeFire_pb2.LoginRes)))

    # Store token
    cached_tokens[region] = {
        'token': f"Bearer {msg.get('token','0')}",
        'region': msg.get('lockRegion','0'),
        'server_url': msg.get('serverUrl','0'),
        'expires_at': time.time() + 25200
    }


async def initialize_tokens():
    """Initialize tokens for supported regions."""
    tasks = [create_jwt(r) for r in SUPPORTED_REGIONS]
    await asyncio.gather(*tasks)


async def refresh_tokens_periodically():
    """Refresh tokens every 7 hours."""
    while True:
        await asyncio.sleep(25200)
        await initialize_tokens()


async def get_token_info(region: str) -> Tuple[str, str, str]:
    """Get token info, refreshing if expired."""
    info = cached_tokens.get(region)
    if info and time.time() < info['expires_at']:
        return info['token'], info['region'], info['server_url']
    await create_jwt(region)
    info = cached_tokens[region]
    return info['token'], info['region'], info['server_url']


# =======================
# ACCOUNT INFORMATION
# =======================

async def GetAccountInformation(uid, unk, region, endpoint):
    """Fetch player account information."""
    if region not in SUPPORTED_REGIONS:
        raise ValueError(f"Unsupported region: {region}")

    # Prepare protobuf request
    payload = await json_to_proto(json.dumps({'a': uid, 'b': unk}), main_pb2.GetPlayerPersonalShow())
    data_enc = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, payload)

    # Get token and send request
    token, lock, server = await get_token_info(region)
    headers = {
        'User-Agent': USERAGENT,
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Content-Type': "application/octet-stream",
        'Expect': "100-continue",
        'Authorization': token,
        'X-Unity-Version': "2018.4.11f1",
        'X-GA': "v1 1",
        'ReleaseVersion': RELEASEVERSION
    }
    async with httpx.AsyncClient() as client:
        resp = await client.post(server + endpoint, data=data_enc, headers=headers)
        return json.loads(json_format.MessageToJson(
            decode_protobuf(resp.content, AccountPersonalShow_pb2.AccountPersonalShowInfo)
        ))


# =======================
# CACHING DECORATOR
# =======================

def cached_endpoint(ttl=300):
    """Simple TTL cache for routes."""
    def decorator(fn):
        @wraps(fn)
        def wrapper(*a, **k):
            key = (request.path, tuple(sorted(request.args.items())))
            if key in cache:
                return cache[key]
            res = fn(*a, **k)
            cache[key] = res
            return res
        return wrapper
    return decorator


# =======================
# ROUTES
# =======================

@app.route('/get')
@cached_endpoint()
def get_account_info():
    uid = request.args.get('uid')
    if not uid:
        return jsonify({"error": "Please provide UID."}), 400

    try:
        data = asyncio.run(GetAccountInformation(uid, "7", "ME", "/GetPlayerPersonalShow"))
        formatted_json = json.dumps(data, indent=2, ensure_ascii=False)
        return formatted_json, 200, {'Content-Type': 'application/json; charset=utf-8'}
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/refresh', methods=['GET', 'POST'])
def refresh_tokens_endpoint():
    try:
        asyncio.run(initialize_tokens())
        return jsonify({'message': 'Tokens refreshed for ME region.'}), 200
    except Exception as e:
        return jsonify({'error': f'Refresh failed: {e}'}), 500


# =======================
# STARTUP
# =======================

async def startup():
    await initialize_tokens()
    asyncio.create_task(refresh_tokens_periodically())

if __name__ == '__main__':
    asyncio.run(startup())
    app.run(host='0.0.0.0', port=5000, debug=True)
