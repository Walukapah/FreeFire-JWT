from flask import Flask, jsonify, request
from flask_caching import Cache
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import binascii
import my_pb2
import output_pb2
import json
from colorama import init
import warnings
from urllib3.exceptions import InsecureRequestWarning

# Disable SSL warning
warnings.filterwarnings("ignore", category=InsecureRequestWarning)

# Constants
AES_KEY = b'Yg&tc%DEuh6%Zc^8'
AES_IV = b'6oyZDr22E3ychjM%'

# Init colorama
init(autoreset=True)

# Flask setup with JSON pretty print
app = Flask(__name__)
app.config['JSONIFY_PRETTYPRINT_REGULAR'] = True  # Enable pretty print
cache = Cache(app, config={'CACHE_TYPE': 'SimpleCache', 'CACHE_DEFAULT_TIMEOUT': 25200})


def get_token(password, uid):
    try:
        url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
        headers = {
            "Host": "100067.connect.garena.com",
            "User-Agent": "GarenaMSDK/4.0.19P4(G011A ;Android 9;en;US;)",
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "close"
        }
        data = {
            "uid": uid,
            "password": password,
            "response_type": "token",
            "client_type": "2",
            "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
            "client_id": "100067"
        }
        res = requests.post(url, headers=headers, data=data, timeout=10)
        if res.status_code != 200:
            return None
        token_json = res.json()
        if "access_token" in token_json and "open_id" in token_json:
            return token_json
        else:
            return None
    except Exception:
        return None


def encrypt_message(key, iv, plaintext):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = pad(plaintext, AES.block_size)
    return cipher.encrypt(padded_message)


def parse_response(content):
    response_dict = {}
    lines = content.split("\n")
    for line in lines:
        if ":" in line:
            key, value = line.split(":", 1)
            response_dict[key.strip()] = value.strip().strip('"')
    return response_dict


@app.route('/token', methods=['GET'])
@cache.cached(timeout=25200, query_string=True)
def get_single_response():
    uid = request.args.get('uid')
    password = request.args.get('password')

    if not uid or not password:
        return jsonify({
            "error": "Both uid and password parameters are required",
            "example_request": "/token?uid=YOUR_UID&password=YOUR_PASSWORD"
        }), 400

    token_data = get_token(password, uid)
    if not token_data:
        return jsonify({
            "uid": uid,
            "status": "invalid",
            "message": "Wrong UID or Password. Please check and try again.",
            "credit": "@NR_CODEX",
            "note": "Make sure your credentials are correct"
        }), 400

    game_data = my_pb2.GameData()
    # ... (rest of your game_data setup remains the same)

    try:
        serialized_data = game_data.SerializeToString()
        encrypted_data = encrypt_message(AES_KEY, AES_IV, serialized_data)
        edata = binascii.hexlify(encrypted_data).decode()

        url = "https://loginbp.common.ggbluefox.com/MajorLogin"
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Content-Type': "application/octet-stream",
            'Expect': "100-continue",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB49"
        }

        response = requests.post(url, data=bytes.fromhex(edata), headers=headers, verify=False)

        if response.status_code == 200:
            example_msg = output_pb2.Garena_420()
            try:
                example_msg.ParseFromString(response.content)
                response_dict = parse_response(str(example_msg))
                
                # Pretty formatted response
                return jsonify({
                    "status": "success",
                    "data": {
                        "uid": uid,
                        "login_status": response_dict.get("status", "N/A"),
                        "auth_token": response_dict.get("token", "N/A"),
                        "token_details": {
                            "access_token": token_data['access_token'],
                            "open_id": token_data['open_id']
                        }
                    },
                    "metadata": {
                        "api_version": "1.0",
                        "credit": "@NR_CODEX",
                        "note": "Token is valid for 7 hours (25200 seconds)"
                    }
                })
            except Exception as e:
                return jsonify({
                    "status": "error",
                    "error_type": "parsing_error",
                    "message": f"Failed to deserialize the response: {str(e)}",
                    "uid": uid,
                    "raw_response": response.content.decode('latin-1')
                }), 400
        else:
            return jsonify({
                "status": "error",
                "error_type": "api_error",
                "message": f"Failed to get response from login server",
                "http_status": response.status_code,
                "response_reason": response.reason,
                "uid": uid
            }), 400
    except Exception as e:
        return jsonify({
            "status": "error",
            "error_type": "internal_error",
            "message": f"Internal server error occurred: {str(e)}",
            "uid": uid
        }), 500


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, debug=True)
