import asyncio
import time
import httpx
import json
import os
from flask import Flask, request, jsonify
from flask_cors import CORS
from cachetools import TTLCache
from proto import FreeFire_pb2, main_pb2, AccountPersonalShow_pb2
from google.protobuf import json_format, message
from google.protobuf.message import Message
from Crypto.Cipher import AES
import base64
from collections import defaultdict

# ===================== CONFIG =====================
MAIN_KEY = base64.b64decode('WWcmdGMlREV1aDYlWmNeOA==')
MAIN_IV = base64.b64decode('Nm95WkRyMjJFM3ljaGpNJQ==')
RELEASEVERSION = "OB50"
USERAGENT = "Dalvik/2.1.0 (Linux; U; Android 13; CPH2095 Build/RKQ1.211119.001)"
SUPPORTED_REGIONS = ["IND", "ME", "BD"]

app = Flask(__name__)
CORS(app)

cached_tokens = defaultdict(dict)

# ===================== AES HELPERS =====================
def pad(text: bytes) -> bytes:
    padding_length = AES.block_size - (len(text) % AES.block_size)
    return text + bytes([padding_length] * padding_length)

def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    from Crypto.Cipher import AES
    aes = AES.new(key, AES.MODE_CBC, iv)
    return aes.encrypt(pad(plaintext))

def decode_protobuf(encoded_data: bytes, proto_type: Message) -> Message:
    instance = proto_type()
    instance.ParseFromString(encoded_data)
    return instance

async def json_to_proto(json_data: str, proto_message: Message) -> bytes:
    json_format.ParseDict(json.loads(json_data), proto_message)
    return proto_message.SerializeToString()

# ===================== TOKEN LOGIC =====================
def get_account_credentials(region: str) -> str:
    accounts = {
        "IND": "uid=4107024119&password=8641DEF96973E839FB294C0E2A57239407FCCB15505FAEB71F24C0FB397A49C0",
        "BD": "uid=3957595605&password=7203510AB3D87E06CE54FC93ABE40D48AA6AEA55E2DEA2D2AA3487CBB20650D7",
        "ME": "uid=4000576816&password=05789ABA8AC3F6163E532EB58873DAF1FE2FA77541312BA9F6B99A47DE62775D"
    }
    return accounts.get(region.upper(), "")

async def get_access_token(account: str):
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    payload = account + "&response_type=token&client_type=2&client_secret=2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3&client_id=100067"
    headers = {'User-Agent': USERAGENT, 'Connection': "Keep-Alive", 'Accept-Encoding': "gzip", 'Content-Type': "application/x-www-form-urlencoded"}
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(url, data=payload, headers=headers)
            data = resp.json()
            return data.get("access_token", "0"), data.get("open_id", "0")
    except:
        return "0", "0"

async def create_jwt(region: str):
    account = get_account_credentials(region)
    token_val, open_id = await get_access_token(account)
    if token_val == "0":
        return
    body = json.dumps({"open_id": open_id, "open_id_type": "4", "login_token": token_val, "orign_platform_type": "4"})
    proto_bytes = await json_to_proto(body, FreeFire_pb2.LoginReq())
    payload = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, proto_bytes)
    url = "https://loginbp.ggblueshark.com/MajorLogin"
    headers = {
        'User-Agent': USERAGENT,
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Content-Type': "application/octet-stream",
        'X-Unity-Version': "2018.4.11f1",
        'X-GA': "v1 1",
        'ReleaseVersion': RELEASEVERSION
    }
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(url, data=payload, headers=headers)
            msg = json.loads(json_format.MessageToJson(decode_protobuf(resp.content, FreeFire_pb2.LoginRes)))
            cached_tokens[region] = {
                'token': f"Bearer {msg.get('token', '0')}",
                'region': msg.get('lockRegion', '0'),
                'server_url': msg.get('serverUrl', '0'),
                'expires_at': time.time() + 25200
            }
    except Exception as e:
        print(f"⚠️ Failed JWT for {region}: {e}")

async def get_token_info(region: str):
    info = cached_tokens.get(region)
    if info and time.time() < info['expires_at']:
        return info['token'], info['region'], info['server_url']
    await create_jwt(region)
    info = cached_tokens.get(region, {})
    return info.get('token', ''), info.get('region', ''), info.get('server_url', '')

# ===================== PLAYER INFO =====================
async def GetAccountInformation(uid, unk, region, endpoint):
    payload = await json_to_proto(json.dumps({'a': uid, 'b': unk}), main_pb2.GetPlayerPersonalShow())
    data_enc = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, payload)
    token, _, server = await get_token_info(region)
    if not server:
        return {}
    headers = {
        'User-Agent': USERAGENT,
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Content-Type': "application/octet-stream",
        'Authorization': token,
        'X-Unity-Version': "2018.4.11f1",
        'X-GA': "v1 1",
        'ReleaseVersion': RELEASEVERSION
    }
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(server + endpoint, data=data_enc, headers=headers)
            return json.loads(json_format.MessageToJson(decode_protobuf(resp.content, AccountPersonalShow_pb2.AccountPersonalShowInfo)))
    except:
        return {}

# ===================== FLASK ROUTES =====================
@app.route('/')
def home():
    return jsonify({"status": "✅ FF API Fast Mode Running."})

@app.route('/get', methods=['GET'])
def get_account_info():
    uid = request.args.get('uid')
    if not uid:
        return jsonify({"error": "Please provide uid."}), 400

    try_regions = ["IND", "ME", "BD"]

    async def try_regions_func():
        for reg in try_regions:
            result = await GetAccountInformation(uid, "7", reg, "/GetPlayerPersonalShow")
            if result and result.get("basicInfo"):
                return reg, result
        return None, None

    region, result = asyncio.run(try_regions_func())
    if not result:
        return jsonify({"error": f"UID not found in {try_regions}."}), 404

    # ===== Build exact same response structure =====
    response = {
        "DetectedRegion": region,
        "AccountInfo": result.get("basicInfo", {}),
        "CaptainInfo": result.get("captainBasicInfo", {}),
        "CreditScore": result.get("creditScoreInfo", {}),
        "GuildInfo": result.get("clanBasicInfo", {}),
        "PetInfo": result.get("petInfo", {}),
        "ProfileInfo": result.get("profileInfo", {}),
        "SocialInfo": result.get("socialInfo", {})
    }

    return jsonify(response), 200

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)
