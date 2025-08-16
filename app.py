import time
import httpx
import json
import os
import base64
from collections import defaultdict
from flask import Flask, request, jsonify
from flask_cors import CORS
from proto import FreeFire_pb2, main_pb2, AccountPersonalShow_pb2
from google.protobuf import json_format, message
from Crypto.Cipher import AES

# === Settings ===
MAIN_KEY = base64.b64decode('WWcmdGMlREV1aDYlWmNeOA==')
MAIN_IV = base64.b64decode('Nm95WkRyMjJFM3ljaGpNJQ==')
RELEASEVERSION = "OB50"
USERAGENT = "Dalvik/2.1.0 (Linux; U; Android 13; CPH2095 Build/RKQ1.211119.001)"
REGION = "ME"  # Force ME region

# === Flask Setup ===
app = Flask(__name__)
CORS(app)
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

def json_to_proto(json_data: str, proto_message: message.Message) -> bytes:
    json_format.ParseDict(json.loads(json_data), proto_message)
    return proto_message.SerializeToString()

def get_account_credentials(region: str) -> str:
    if region == "ME":
        return "uid=3979453236&password=790276AD097765884A1E9E743D796B540C1C435661B1D898FACBE8CC25AC457F"

def post_request(url, data, headers, timeout=15):
    try:
        resp = httpx.post(url, data=data, headers=headers, timeout=timeout)
        resp.raise_for_status()
        return resp
    except Exception as e:
        raise RuntimeError(f"HTTP Request failed: {str(e)}")

# === Token Generation ===
def get_access_token(account: str):
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    payload = account + "&response_type=token&client_type=2&client_secret=2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3&client_id=100067"
    headers = {'User-Agent': USERAGENT, 'Connection': "Keep-Alive", 'Accept-Encoding': "gzip", 'Content-Type': "application/x-www-form-urlencoded"}
    resp = post_request(url, payload, headers)
    data = resp.json()
    return data.get("access_token","0"), data.get("open_id","0")

def create_jwt(region: str):
    account = get_account_credentials(region)
    token_val, open_id = get_access_token(account)
    body = json.dumps({"open_id": open_id,"open_id_type":"4","login_token":token_val,"orign_platform_type":"4"})
    proto_bytes = json_to_proto(body, FreeFire_pb2.LoginReq())
    payload = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, proto_bytes)
    url = "https://loginbp.ggblueshark.com/MajorLogin"
    headers = {
        'User-Agent': USERAGENT,'Connection': "Keep-Alive",'Accept-Encoding': "gzip",
        'Content-Type': "application/octet-stream",'Expect': "100-continue",
        'X-Unity-Version': "2018.4.11f1",'X-GA': "v1 1",'ReleaseVersion': RELEASEVERSION
    }
    resp = post_request(url, payload, headers)
    msg = json.loads(json_format.MessageToJson(decode_protobuf(resp.content, FreeFire_pb2.LoginRes)))
    cached_tokens[region] = {
        'token': f"Bearer {msg.get('token','0')}",
        'region': msg.get('lockRegion','0'),
        'server_url': msg.get('serverUrl','0'),
        'expires_at': time.time() + 25200
    }

def get_token_info(region: str):
    info = cached_tokens.get(region)
    if info and time.time() < info['expires_at']:
        return info['token'], info['region'], info['server_url']
    create_jwt(region)
    info = cached_tokens[region]
    return info['token'], info['region'], info['server_url']

# === Account Info ===
def GetAccountInformation(uid, unk, region, endpoint):
    payload = json_to_proto(json.dumps({'a':uid,'b':unk}), main_pb2.GetPlayerPersonalShow())
    data_enc = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, payload)
    token, lock, server = get_token_info(region)
    headers = {
        'User-Agent': USERAGENT,'Connection': "Keep-Alive",'Accept-Encoding': "gzip",
        'Content-Type': "application/octet-stream",'Expect': "100-continue",
        'Authorization': token,'X-Unity-Version': "2018.4.11f1",'X-GA': "v1 1",
        'ReleaseVersion': RELEASEVERSION
    }
    resp = post_request(server+endpoint, data_enc, headers)
    return json.loads(json_format.MessageToJson(decode_protobuf(resp.content, AccountPersonalShow_pb2.AccountPersonalShowInfo)))

def format_response(data):
    return {"AccountInfo": data.get("basicInfo",{}), "Profile": data.get("profileInfo",{}), "Guild": data.get("clanBasicInfo",{})}

# === Flask Routes ===
@app.route("/get")
def get_account_info():
    uid = request.args.get("uid")
    if not uid:
        return jsonify({"error":"Provide UID"}), 400

    try:
        data = GetAccountInformation(uid, "7", REGION, "/GetPlayerPersonalShow")
        results = {REGION: format_response(data)}
        return jsonify(results), 200
    except Exception as e:
        return jsonify({"error": "Server error", "details": str(e)}), 500

@app.route("/refresh")
def refresh_tokens():
    try:
        create_jwt(REGION)  # refresh only ME token
        return jsonify({"message":"Token refreshed for ME"}), 200
    except Exception as e:
        return jsonify({"error": "Server error", "details": str(e)}), 500

# === Startup ===
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT",5000)))
