import asyncio
import time
import httpx
import json
import os
from collections import defaultdict
from quart import Quart, request, jsonify
from quart_cors import cors
from cachetools import TTLCache
from typing import Tuple
from proto import FreeFire_pb2, main_pb2, AccountPersonalShow_pb2
from google.protobuf import json_format, message
from google.protobuf.message import Message
from Crypto.Cipher import AES
import base64
import logging

# === Logging ===
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# === Settings ===
MAIN_KEY = base64.b64decode('WWcmdGMlREV1aDYlWmNeOA==')
MAIN_IV = base64.b64decode('Nm95WkRyMjJFM3ljaGpNJQ==')
RELEASEVERSION = "OB50"
USERAGENT = "Dalvik/2.1.0 (Linux; U; Android 13; CPH2095 Build/RKQ1.211119.001)"
SUPPORTED_REGIONS = {"IND", "BR", "US", "SAC", "NA", "SG", "RU", "ID", "TW", "VN", "TH", "ME", "PK", "CIS", "BD", "EU"}

# === App setup ===
app = Quart(__name__)
app = cors(app, allow_origin="*")
cache = TTLCache(maxsize=100, ttl=300)
cached_tokens = defaultdict(dict)

# === Helper Functions ===
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
    # Default account for all regions
    return "uid=3998786367&password=7577A5E2F529AFE6DB59FDB613A673BE65E05A0CD01E11304F7CC10065BC8FBD"

# === Token Generation with Retry ===
async def get_access_token(account: str, retries=3):
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    payload = account + "&response_type=token&client_type=2&client_secret=2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3&client_id=100067"
    headers = {
        'User-Agent': USERAGENT,
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Content-Type': "application/x-www-form-urlencoded"
    }

    for attempt in range(retries):
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.post(url, data=payload, headers=headers)
                resp.raise_for_status()
                data = resp.json()
                return data.get("access_token", "0"), data.get("open_id", "0")
        except httpx.ConnectTimeout:
            logger.warning(f"Connection timed out, retry {attempt + 1}/{retries}...")
        except httpx.HTTPStatusError as e:
            logger.warning(f"HTTP error: {e}")
        except Exception as e:
            logger.error(f"Unexpected error during access token request: {e}")
        await asyncio.sleep(2)

    logger.error("Failed to get access token after retries.")
    return "0", "0"

async def create_jwt(region: str):
    account = get_account_credentials(region)
    token_val, open_id = await get_access_token(account)
    if token_val == "0":
        logger.error(f"[{region}] Access token fetch failed.")
        return

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

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(url, data=payload, headers=headers)
            msg = json.loads(json_format.MessageToJson(
                decode_protobuf(resp.content, FreeFire_pb2.LoginRes)
            ))
            cached_tokens[region] = {
                'token': f"Bearer {msg.get('token', '0')}",
                'region': msg.get('lockRegion', '0'),
                'server_url': msg.get('serverUrl', '0'),
                'expires_at': time.time() + 25200  # 7 hours
            }
            logger.info(f"[{region}] JWT created successfully.")
    except Exception as e:
        logger.error(f"[{region}] JWT creation failed: {e}")

async def initialize_tokens():
    tasks = [create_jwt(r) for r in SUPPORTED_REGIONS]
    await asyncio.gather(*tasks)

async def refresh_tokens_periodically():
    while True:
        await asyncio.sleep(25200)  # 7 hours
        logger.info("Refreshing tokens...")
        await initialize_tokens()

async def get_token_info(region: str) -> Tuple[str, str, str]:
    info = cached_tokens.get(region)
    if not info or time.time() >= info.get('expires_at', 0):
        await create_jwt(region)
        info = cached_tokens.get(region, {})
    return info.get('token', '0'), info.get('region', region), info.get('server_url', '0')

async def GetAccountInformation(uid, unk, region, endpoint):
    payload = await json_to_proto(json.dumps({'a': uid, 'b': unk}), main_pb2.GetPlayerPersonalShow())
    data_enc = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, payload)
    token, lock, server = await get_token_info(region)

    if token == "0" or server == "0":
        raise Exception("Token or server unavailable.")

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
    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.post(server + endpoint, data=data_enc, headers=headers)
        return json.loads(json_format.MessageToJson(
            decode_protobuf(resp.content, AccountPersonalShow_pb2.AccountPersonalShowInfo)
        ))

# === API Routes ===
@app.route('/get')
async def get_account_info():
    uid = request.args.get('uid')
    if not uid:
        return jsonify({"error": "Please provide UID."}), 400
    try:
        region = "ME"  # Default region
        return_data = await GetAccountInformation(uid, "7", region, "/GetPlayerPersonalShow")
        return jsonify(return_data), 200
    except Exception as e:
        logger.error(f"Error fetching account info: {e}")
        return jsonify({"error": "Invalid UID or server error."}), 500

@app.route('/refresh', methods=['GET', 'POST'])
async def refresh_tokens_endpoint():
    try:
        await initialize_tokens()
        return jsonify({'message': 'Tokens refreshed for all regions.'}), 200
    except Exception as e:
        logger.error(f"Error refreshing tokens: {e}")
        return jsonify({'error': f'Refresh failed: {e}'}), 500

# === Startup Tasks ===
@app.before_serving
async def startup_tasks():
    logger.info("Initializing tokens for all regions...")
    await initialize_tokens()
    asyncio.create_task(refresh_tokens_periodically())

# === Run app for development ===
if __name__ == "__main__":
    import hypercorn.asyncio
    import hypercorn.config

    config = hypercorn.config.Config()
    config.bind = [f"0.0.0.0:{os.environ.get('PORT', 5000)}"]
    asyncio.run(hypercorn.asyncio.serve(app, config))
