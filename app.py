import os
import asyncio
import time
import json
import base64
from collections import defaultdict
from functools import wraps
from typing import Tuple

import httpx
from quart import Quart, request, jsonify
from quart_cors import cors
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
GUEST_ACCOUNT = "uid=4000576816&password=05789ABA8AC3F6163E532EB58873DAF1FE2FA77541312BA9F6B99A47DE62775D"
SUPPORTED_REGIONS = {"ME"}

# Quart & Cache
app = Quart(__name__)
app = cors(app)
cache = TTLCache(maxsize=100, ttl=300)
cached_tokens = defaultdict(dict)

# =======================
# HELPER FUNCTIONS
# =======================

def pad(text: bytes) -> bytes:
    padding_length = AES.block_size - (len(text) % AES.block_size)
    return text + bytes([padding_length] * padding_length)

def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    aes = AES.new(key, AES.MODE_CBC, iv)
    return aes.encrypt(pad(plaintext))

def decode_protobuf(encoded_data: bytes, message_type: message.Message) -> message.Message:
    instance = message_type()
    instance.ParseFromString(encoded_data)
    return instance

async def json_to_proto(json_data: str, proto_message: Message) -> bytes:
    json_format.ParseDict(json.loads(json_data), proto_message)
    return proto_message.SerializeToString()

def get_account_credentials(region: str) -> str:
    return GUEST_ACCOUNT

# =======================
# TOKEN GENERATION
# =======================

async def get_access_token(account: str):
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
    account = get_account_credentials(region)
    token_val, open_id = await get_access_token(account)

    body = json.dumps({
        "open_id": open_id,
        "open_id_type": "4",
        "login_token": token_val,
        "orign_platform_type": "4"
    })
    proto_bytes = await json_to_proto(body, FreeFire_pb2.LoginReq())
    payload = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, proto_bytes)

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

    cached_tokens[region] = {
        'token': f"Bearer {msg.get('token','0')}",
        'region': msg.get('lockRegion','0'),
        'server_url': msg.get('serverUrl','0'),
        'expires_at': time.time() + 25200
    }

async def get_token_info(region: str) -> Tuple[str, str, str]:
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
    if region not in SUPPORTED_REGIONS:
        raise ValueError(f"Unsupported region: {region}")

    payload = await json_to_proto(json.dumps({'a': uid, 'b': unk}), main_pb2.GetPlayerPersonalShow())
    data_enc = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, payload)

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
    def decorator(fn):
        @wraps(fn)
        async def wrapper(*a, **k):
            key = (request.path, tuple(sorted(request.args.items())))
            if key in cache:
                return cache[key]
            res = await fn(*a, **k)
            cache[key] = res
            return res
        return wrapper
    return decorator

# =======================
# ROUTES
# =======================

@app.route('/get')
@cached_endpoint()
async def get_account_info():
    uid = request.args.get('uid')
    if not uid:
        return jsonify({"error": "Please provide UID."}), 400

    try:
        data = await GetAccountInformation(uid, "7", "ME", "/GetPlayerPersonalShow")
        formatted_json = json.dumps(data, indent=2, ensure_ascii=False)
        return formatted_json, 200, {'Content-Type': 'application/json; charset=utf-8'}
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/refresh', methods=['GET', 'POST'])
async def refresh_tokens_endpoint():
    try:
        await create_jwt("ME")
        return jsonify({'message': 'Tokens refreshed for ME region.'}), 200
    except Exception as e:
        return jsonify({'error': f'Refresh failed: {e}'}), 500

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)
