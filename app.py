from flask import Flask, request, jsonify, render_template_string
import requests, json, hmac, hashlib, time, random, urllib3, ipaddress
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from datetime import datetime
import string

app = Flask(__name__)

# Disable warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# AES keys
aes_key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
aes_iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])

HEX_KEY = "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3"
API_KEY = bytes.fromhex(HEX_KEY)

# ==================== IP ROTATOR ====================
class IPRotator:
    REGION_IP_CIDRS = {
        "BD": ["27.147.128.0/17", "37.111.192.0/19", "49.0.32.0/20", "59.152.96.0/20",
               "114.130.0.0/17", "115.127.0.0/17", "119.30.32.0/20", "123.49.0.0/18",
               "103.220.220.0/22", "103.108.140.0/22", "103.242.20.0/22"],
        "IND": ["1.6.0.0/15", "1.38.0.0/15", "14.96.0.0/15", "27.4.0.0/14", "27.56.0.0/13"],
        "ID": ["36.64.0.0/11", "101.255.0.0/16", "103.10.60.0/22", "114.120.0.0/13"],
        "TH": ["1.46.0.0/15", "27.55.0.0/16", "49.228.0.0/15", "101.108.0.0/15"],
        "VN": ["1.52.0.0/14", "14.160.0.0/11", "27.64.0.0/12", "113.160.0.0/12"],
        "PK": ["39.32.0.0/11", "111.68.96.0/19", "182.176.0.0/12"],
        "ME": ["2.88.0.0/13", "5.100.0.0/14", "31.166.0.0/15", "37.104.0.0/13"],
        "BR": ["177.0.0.0/13", "186.192.0.0/12", "189.0.0.0/11", "200.96.0.0/12"],
        "EU": ["2.16.0.0/12", "5.144.0.0/14", "31.40.0.0/14", "46.16.0.0/14"],
        "CIS": ["2.92.0.0/14", "5.136.0.0/13", "31.128.0.0/12", "46.0.0.0/12"],
        "NA": ["3.0.0.0/9", "8.0.0.0/12", "12.0.0.0/10", "24.0.0.0/10"],
        "SAC": ["186.0.0.0/10", "190.0.0.0/11", "200.0.0.0/11"],
        "TW": ["1.160.0.0/12", "36.224.0.0/12", "114.24.0.0/12", "118.160.0.0/12"]
    }
    _cache = {}
    
    @classmethod
    def get_random_ip(cls, region="BD"):
        region = region.upper()
        if region not in cls._cache:
            cidrs = cls.REGION_IP_CIDRS.get(region, ["27.0.0.0/8"])
            hosts = []
            for cidr in cidrs:
                try:
                    net = ipaddress.ip_network(cidr, strict=False)
                    for _ in range(3):
                        ip_int = int(net.network_address) + random.randint(1, 2**(32-net.prefixlen)-2)
                        hosts.append(str(ipaddress.IPv4Address(ip_int)))
                except:
                    continue
            cls._cache[region] = hosts if hosts else [f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}"]
        return random.choice(cls._cache[region])

# ==================== PROTOBUF FUNCTIONS ====================
def create_vr(N):
    if N < 0: return b''
    H = []
    while True:
        S = N & 0x7F
        N >>= 7
        if N:
            S |= 0x80
        H.append(S)
        if not N:
            break
    return bytes(H)

def create_variant(field_number, value):
    field_header = (field_number << 3) | 0
    return create_vr(field_header) + create_vr(value)

def create_length(field_number, value):
    field_header = (field_number << 3) | 2
    encoded_value = value.encode() if isinstance(value, str) else value
    return create_vr(field_header) + create_vr(len(encoded_value)) + encoded_value

def create_proto(fields):
    packet = bytearray()
    for field, value in fields.items():
        if isinstance(value, dict):
            nested_packet = create_proto(value)
            packet.extend(create_length(field, nested_packet))
        elif isinstance(value, int):
            packet.extend(create_variant(field, value))
        elif isinstance(value, str) or isinstance(value, bytes):
            packet.extend(create_length(field, value))
    return packet

def decode_varint(data, offset):
    result = 0
    shift = 0
    while offset < len(data):
        byte = data[offset]
        result |= (byte & 0x7F) << shift
        offset += 1
        if not (byte & 0x80):
            return result, offset
        shift += 7
    return None, offset

def decode_protobuf(data):
    result = {}
    offset = 0
    data_len = len(data)
    while offset < data_len:
        header, offset = decode_varint(data, offset)
        if header is None:
            break
        field_number = header >> 3
        wire_type = header & 0x7
        if wire_type == 0:
            value, offset = decode_varint(data, offset)
            if value is not None:
                result[field_number] = value
        elif wire_type == 2:
            length, offset = decode_varint(data, offset)
            if length is None:
                break
            value = data[offset:offset + length]
            offset += length
            try:
                result[field_number] = value.decode('utf-8')
            except:
                result[field_number] = value.hex()
        elif wire_type == 1:
            offset += 8
        elif wire_type == 3:
            offset += 4
        else:
            break
    return result

# ==================== ENCRYPTION ====================
def encrypt_aes(HeX):
    cipher = AES.new(aes_key, AES.MODE_CBC, aes_iv)
    return cipher.encrypt(pad(bytes.fromhex(HeX), AES.block_size)).hex()

# ==================== API FUNCTIONS ====================
def register_account(password, region="BD"):
    url = "https://100067.connect.garena.com/api/v2/oauth/guest:register"
    client_ip = IPRotator.get_random_ip(region)
    payload_json = {"app_id": 100067, "client_type": 2, "password": password, "source": 2}
    payload = json.dumps(payload_json, separators=(',', ':'))
    signature = hmac.new(API_KEY, payload.encode(), hashlib.sha256).hexdigest()
    timestamp = str(int(time.time() * 1000) + random.randint(-999, 999))
    headers = {
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; SM-G960F Build/PIE)",
        "Authorization": f"Signature {signature}",
        "Content-Type": "application/json; charset=utf-8",
        "Accept": "application/json",
        "Connection": "Keep-Alive",
        "Host": "100067.connect.garena.com",
        "X-Garena-Timestamp": timestamp,
        "X-Forwarded-For": client_ip,
        "X-Real-IP": client_ip,
    }
    response = requests.post(url, headers=headers, data=payload, verify=False)
    json_data = response.json()
    uid = json_data["data"]["uid"]
    return uid, password

def get_access_token(uid, password, region="BD"):
    url = "https://100067.connect.garena.com/oauth/guest/token/grant"
    client_ip = IPRotator.get_random_ip(region)
    headers = {
        "Host": "100067.connect.garena.com",
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; SM-G960F Build/PIE)",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "close",
        "X-Forwarded-For": client_ip,
        "X-Real-IP": client_ip,
    }
    data = {
        "uid": uid,
        "password": password,
        "response_type": "token",
        "client_type": "2",
        "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
        "client_id": "100067"
    }
    response = requests.post(url, headers=headers, data=data)
    if response.status_code != 200:
        return None, None, None
    json_data = response.json()
    access_token = json_data["access_token"]
    open_id = json_data["open_id"]
    platform = json_data["platform"]
    platform_type = int(platform)
    return access_token, open_id, platform_type

def major_register(access_token, open_id, name, LANG='en', region="BD"):
    url = "https://loginbp.ggpolarbear.com/MajorRegister"
    client_ip = IPRotator.get_random_ip(region)
    keystream = [0x30, 0x30, 0x30, 0x32, 0x30, 0x31, 0x37, 0x30, 0x30, 0x30, 0x30, 0x30, 0x32, 0x30, 0x31, 0x37,
                 0x30, 0x30, 0x30, 0x30, 0x30, 0x32, 0x30, 0x31, 0x37, 0x30, 0x30, 0x30, 0x30, 0x30, 0x32, 0x30]
    encoded_open_id = ""
    for i, ch in enumerate(open_id):
        encoded_open_id += chr(ord(ch) ^ keystream[i % len(keystream)])
    field14 = encoded_open_id.encode('latin1')
    payload_fields = {
        1: name,
        2: access_token,
        3: open_id,
        5: 102000007,
        6: 4,
        7: 1,
        13: 1,
        14: field14,
        15: LANG,
        16: 1,
        17: 1
    }
    proto_bytes = create_proto(payload_fields)
    proto_hex = proto_bytes.hex()
    payload = bytes.fromhex(encrypt_aes(proto_hex))
    headers = {
        "Accept-Encoding": "gzip",
        "Authorization": "Bearer",
        "Connection": "Keep-Alive",
        "Content-Type": "application/x-www-form-urlencoded",
        "Expect": "100-continue",
        "Host": "loginbp.ggpolarbear.com",
        "ReleaseVersion": "OB54",
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_I005DA Build/PI)",
        "X-GA": "v1 1",
        "X-Unity-Version": "2018.4.",
        "X-Forwarded-For": client_ip,
        "X-Real-IP": client_ip,
    }
    response = requests.post(url, headers=headers, data=payload)
    response_data = decode_protobuf(response.content)
    return response_data

def major_login_payload(access_token, open_id, platform_type):
    fields = {
        3: str(datetime.now())[:-7],
        4: "free fire",
        5: 1,
        7: "1.128.14",
        8: "Android OS 14 / API-34 (UKQ1.230917.001/V816.0.1.0.UMWJPSB)",
        9: "Handheld",
        11: "WIFI",
        12: 1708,
        13: 750,
        14: "440",
        15: "ARM64 FP ASIMD AES | 2208 | 8",
        16: 3479,
        17: "Adreno (TM) 613",
        18: "OpenGL ES 3.2 V@0615.74 (GIT@dad4038ba6, If56d4a5bb8, 1690544947) (Date:07/28/23)",
        19: "Google|27ed2fb9-7ace-4842-9ebf-0d42c7140201",
        20: "103.13.194.32",
        21: "en",
        22: open_id,
        23: platform_type,
        24: "Handheld",
        25: "google G011A",
        26: "BD",
        29: access_token,
        30: 1,
        42: "WIFI",
        57: "7428b253defc164018c604a1ebbfebdf",
        60: 110509,
        61: 29537,
        62: 697,
        64: 29665,
        65: 110509,
        66: 29665,
        67: 110509,
        73: 2,
        74: "/data/app/~~XPfhCrDak-UWHWhp3ymWJg==/com.dts.freefireth-am4qxn2SuG3LmR020vv1zQ==/lib/arm64",
        76: 1,
        77: "4c322aeb56444feaa151d1ea91a8f7f2|/data/app/~~XPfhCrDak-UWHWhp3ymWJg==/com.dts.freefireth-am4qxn2SuG3LmR020vv1zQ==/base.apk",
        78: 3,
        79: 2,
        81: "64",
        83: "2019120828",
        85: 3,
        86: "OpenGLES2",
        87: 4095,
        88: platform_type,
        90: "Pokhara",
        91: {10: 52},
        92: 21559,
        93: "android",
        94: "KqsHT8i1nPYybHwReglCq3THRFio2Q9U/EYoQzoAUmdpAf9+6ZixKBvdt1f8xFUBDN0+XKgZZfNC4rEtfHn3Vt/jEyg=",
        95: 111207,
        96: '{"cur_rate":[60,48,30,90],"support_etc2":false}',
        97: 1,
        99: f"{platform_type}",
        100: f"{platform_type}",
        102: "16544d12040f0f0263",
        103: 1
    }
    pyl = create_proto(fields).hex()
    payload = bytes.fromhex(encrypt_aes(pyl))
    return payload

def major_login(payload, region="BD"):
    url = "https://loginbp.ggpolarbear.com/MajorLogin"
    client_ip = IPRotator.get_random_ip(region)
    headers = {
        'X-Unity-Version': '2018.4.11f1',
        'ReleaseVersion': 'OB54',
        'Content-Type': 'application/x-www-form-urlencoded',
        'X-GA': 'v1 1',
        'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 7.1.2; ASUS_Z01QD Build/QKQ1.190825.002)',
        'Host': 'loginbp.ggpolarbear.com',
        'Connection': 'Keep-Alive',
        'Accept-Encoding': 'gzip',
        'X-Forwarded-For': client_ip,
        'X-Real-IP': client_ip,
    }
    response = requests.post(url, headers=headers, data=payload)
    response_content = response.content
    json_response = decode_protobuf(response_content)
    return json_response

def get_login_data(server_url, jwt_token, payload, region="BD"):
    url = f"{server_url}/GetLoginData"
    client_ip = IPRotator.get_random_ip(region)
    headers = {
        'X-Unity-Version': '2018.4.11f1',
        'ReleaseVersion': 'OB54',
        'Content-Type': 'application/x-www-form-urlencoded',
        'X-GA': 'v1 1',
        'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 7.1.2; ASUS_Z01QD Build/QKQ1.190825.002)',
        'Host': 'loginbp.ggpolarbear.com',
        'Connection': 'Keep-Alive',
        'Accept-Encoding': 'gzip',
        'Authorization': f'Bearer {jwt_token}',
        'X-Forwarded-For': client_ip,
        'X-Real-IP': client_ip,
    }
    response = requests.post(url, headers=headers, data=payload)
    response_content = response.content
    json_response = decode_protobuf(response_content)
    return json_response

# ==================== MAIN REGISTRATION FUNCTION ====================
def generate_random_password_suffix():
    chars = string.ascii_uppercase + string.digits
    return '_' + ''.join(random.choices(chars, k=4))

def generate_random_name_suffix():
    """Generate 5 random superscript digits for name suffix"""
    superscript_digits = '¹²³⁴⁵⁶⁷⁸⁹⁰'
    return ''.join(random.choices(superscript_digits, k=5))

def check_name_taken_error(response):
    """Check if the error indicates name is already taken"""
    if isinstance(response, dict):
        if 9 in response:
            error_msg = str(response[9]).lower()
            name_taken_patterns = [
                'already exists',
                'already taken',
                'duplicate',
                'exists',
                'taken',
                'muddle'
            ]
            for pattern in name_taken_patterns:
                if pattern in error_msg:
                    return True
        if 'error' in response:
            error_msg = str(response['error']).lower()
            for pattern in ['already exists', 'already taken', 'duplicate', 'exists', 'taken']:
                if pattern in error_msg:
                    return True
    return False

def register_single_account(name, password, region="BD"):
    """Generate a single account with retry logic"""
    max_retries = 10
    attempt = 0
    
    while attempt < max_retries:
        attempt += 1
        try:
            final_password = password + generate_random_password_suffix()
            
            uid, _ = register_account(final_password, region)
            
            access_token, open_id, platform_type = get_access_token(uid, final_password, region)
            if access_token is None:
                continue
            
            if attempt == 1:
                current_name = name
            else:
                current_name = name + generate_random_name_suffix()
            
            major_register_response = major_register(access_token, open_id, current_name, region=region)
            
            if check_name_taken_error(major_register_response):
                if attempt < max_retries:
                    continue
                else:
                    return {
                        "error": "Failed to generate unique name after 10 attempts",
                        "uid": uid,
                        "password": final_password
                    }
            
            if 3 in major_register_response:
                account_id = major_register_response[3]
                payload = major_login_payload(access_token, open_id, platform_type)
                major_login_response = major_login(payload, region)
                jwt_token = major_login_response.get(8)
                server_url = major_login_response.get(10)
                
                if jwt_token and server_url:
                    login_data_response = get_login_data(server_url, jwt_token, payload, region)
                    region_result = login_data_response.get(3, region)
                    
                    if region_result != region.upper():
                        if attempt < max_retries:
                            continue
                        else:
                            return {
                                "error": f"Region mismatch. Expected: {region.upper()}, Got: {region_result}",
                                "uid": uid,
                                "password": final_password,
                                "name": current_name,
                                "account_id": account_id,
                                "region_got": region_result
                            }
                    
                    return {
                        "success": True,
                        "uid": uid,
                        "password": final_password,
                        "name": current_name,
                        "account_id": account_id,
                        "access_token": access_token,
                        "open_id": open_id,
                        "platform_type": platform_type,
                        "jwt_token": jwt_token,
                        "server_url": server_url,
                        "region": region_result
                    }
                else:
                    if attempt < max_retries:
                        continue
                    else:
                        return {
                            "error": "Major login failed after 10 attempts",
                            "response": major_login_response,
                            "uid": uid,
                            "password": final_password
                        }
            else:
                if attempt < max_retries:
                    continue
                else:
                    return {
                        "error": "Registration failed after 10 attempts",
                        "response": major_register_response,
                        "uid": uid,
                        "password": final_password
                    }
                
        except Exception as e:
            if attempt < max_retries:
                continue
            else:
                return {"error": f"Error after 10 attempts: {str(e)}"}
    
    return {"error": "Max retries reached"}

def register_account_full(name, password, region="BD", count=1):
    """Generate multiple accounts"""
    count = min(max(count, 1), 10)  # Clamp between 1 and 10
    
    results = []
    successful = 0
    failed = 0
    
    for i in range(count):
        # Generate a unique name for each account
        if count > 1:
            # Add number suffix for multiple accounts
            account_name = f"{name}_{i+1}"
        else:
            account_name = name
        
        result = register_single_account(account_name, password, region)
        
        if result.get("success"):
            successful += 1
            results.append(result)
        else:
            failed += 1
            # Still include failed attempts but mark them
            result["attempt"] = i + 1
            results.append(result)
        
        # Small delay between accounts to avoid rate limiting
        if i < count - 1:
            time.sleep(0.5)
    
    return {
        "total": count,
        "successful": successful,
        "failed": failed,
        "accounts": results,
        "region": region.upper(),
        "password_base": password
    }

# ==================== HTML TEMPLATE ====================
HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>FF Account Generator</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: #0a0a0a;
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
        }
        .container {
            background: linear-gradient(145deg, #1a1a2e, #16213e);
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.8), 0 0 40px rgba(100, 100, 255, 0.1);
            padding: 40px;
            max-width: 560px;
            width: 100%;
            border: 1px solid rgba(255,255,255,0.05);
        }
        h1 {
            color: #fff;
            font-size: 28px;
            margin-bottom: 5px;
            text-align: center;
            background: linear-gradient(135deg, #667eea, #764ba2);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            font-weight: 800;
        }
        .subtitle {
            color: #888;
            text-align: center;
            margin-bottom: 30px;
            font-size: 13px;
        }
        .form-group {
            margin-bottom: 20px;
        }
        label {
            display: block;
            color: #aaa;
            font-weight: 600;
            margin-bottom: 5px;
            font-size: 13px;
            letter-spacing: 0.5px;
        }
        input, select {
            width: 100%;
            padding: 12px 15px;
            background: rgba(255,255,255,0.05);
            border: 2px solid rgba(255,255,255,0.1);
            border-radius: 10px;
            font-size: 15px;
            color: #fff;
            transition: all 0.3s;
        }
        input::placeholder {
            color: #555;
        }
        input:focus, select:focus {
            outline: none;
            border-color: #667eea;
            background: rgba(255,255,255,0.08);
            box-shadow: 0 0 20px rgba(102, 126, 234, 0.15);
        }
        select option {
            background: #1a1a2e;
            color: #fff;
        }
        .btn {
            width: 100%;
            padding: 14px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 10px;
            font-size: 16px;
            font-weight: 700;
            cursor: pointer;
            transition: all 0.3s;
            letter-spacing: 0.5px;
        }
        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 30px rgba(102, 126, 234, 0.3);
        }
        .btn:active {
            transform: translateY(0);
        }
        .btn:disabled {
            opacity: 0.6;
            cursor: not-allowed;
            transform: none;
        }
        #result {
            margin-top: 20px;
            padding: 15px;
            border-radius: 10px;
            display: none;
            word-wrap: break-word;
            max-height: 500px;
            overflow-y: auto;
        }
        #result::-webkit-scrollbar {
            width: 6px;
        }
        #result::-webkit-scrollbar-track {
            background: rgba(255,255,255,0.05);
            border-radius: 10px;
        }
        #result::-webkit-scrollbar-thumb {
            background: #667eea;
            border-radius: 10px;
        }
        #result.success {
            display: block;
            background: rgba(0, 255, 100, 0.08);
            border: 1px solid rgba(0, 255, 100, 0.2);
            color: #7dffb3;
        }
        #result.error {
            display: block;
            background: rgba(255, 0, 0, 0.08);
            border: 1px solid rgba(255, 0, 0, 0.2);
            color: #ff6b6b;
        }
        #result.loading {
            display: block;
            background: rgba(102, 126, 234, 0.08);
            border: 1px solid rgba(102, 126, 234, 0.2);
            color: #a8b4ff;
        }
        .result-item {
            margin: 8px 0;
            font-size: 13px;
            padding: 4px 0;
            border-bottom: 1px solid rgba(255,255,255,0.05);
        }
        .result-item strong {
            color: #a8b4ff;
            display: inline-block;
            min-width: 100px;
        }
        .result-item .value {
            color: #fff;
            word-break: break-all;
        }
        .result-item .highlight {
            color: #7dffb3;
            font-weight: 600;
        }
        .account-box {
            background: rgba(255,255,255,0.03);
            border: 1px solid rgba(255,255,255,0.08);
            border-radius: 10px;
            padding: 12px;
            margin: 10px 0;
        }
        .account-box .account-title {
            color: #667eea;
            font-weight: 700;
            font-size: 14px;
            margin-bottom: 8px;
        }
        .account-box .account-item {
            font-size: 12px;
            padding: 2px 0;
            color: #ccc;
        }
        .account-box .account-item strong {
            color: #888;
            min-width: 80px;
            display: inline-block;
        }
        .badge-success {
            display: inline-block;
            background: rgba(0, 255, 100, 0.15);
            color: #7dffb3;
            padding: 2px 10px;
            border-radius: 20px;
            font-size: 11px;
            font-weight: 600;
        }
        .badge-failed {
            display: inline-block;
            background: rgba(255, 0, 0, 0.15);
            color: #ff6b6b;
            padding: 2px 10px;
            border-radius: 20px;
            font-size: 11px;
            font-weight: 600;
        }
        .summary {
            background: rgba(255,255,255,0.03);
            border-radius: 10px;
            padding: 12px;
            margin-bottom: 15px;
            text-align: center;
        }
        .summary span {
            margin: 0 10px;
        }
        .endpoints {
            margin-top: 25px;
            padding-top: 20px;
            border-top: 1px solid rgba(255,255,255,0.05);
        }
        .endpoints h3 {
            color: #666;
            font-size: 12px;
            margin-bottom: 10px;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        .endpoint {
            background: rgba(255,255,255,0.03);
            padding: 8px 12px;
            border-radius: 6px;
            margin: 5px 0;
            font-family: 'Courier New', monospace;
            font-size: 12px;
            color: #888;
            border: 1px solid rgba(255,255,255,0.05);
        }
        .endpoint span {
            color: #667eea;
            font-weight: 600;
        }
        .dev-info {
            margin-top: 20px;
            padding-top: 15px;
            border-top: 1px solid rgba(255,255,255,0.05);
            text-align: center;
            color: #555;
            font-size: 12px;
        }
        .dev-info a {
            color: #667eea;
            text-decoration: none;
            font-weight: 600;
        }
        .dev-info a:hover {
            color: #764ba2;
        }
        .loading-spinner {
            display: inline-block;
            width: 20px;
            height: 20px;
            border: 3px solid rgba(102, 126, 234, 0.2);
            border-top: 3px solid #667eea;
            border-radius: 50%;
            animation: spin 1s linear infinite;
            margin-right: 10px;
            vertical-align: middle;
        }
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        .copy-btn {
            background: rgba(102, 126, 234, 0.2);
            color: #667eea;
            border: 1px solid rgba(102, 126, 234, 0.3);
            padding: 2px 10px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 11px;
            margin-left: 5px;
            transition: all 0.2s;
        }
        .copy-btn:hover {
            background: rgba(102, 126, 234, 0.3);
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🎮 FF Generator</h1>
        <p class="subtitle">⚡ Generate Free Fire accounts instantly</p>
        
        <form id="form">
            <div class="form-group">
                <label>👤 Nickname</label>
                <input type="text" id="name" placeholder="Enter your nickname" value="ALWAYS~MARUF" required>
            </div>
            
            <div class="form-group">
                <label>🔑 Password</label>
                <input type="text" id="password" placeholder="Enter password" value="MARUF" required>
            </div>
            
            <div class="form-group">
                <label>🌍 Region</label>
                <select id="region">
                    <option value="BD">🇧🇩 Bangladesh (BD)</option>
                    <option value="IND">🇮🇳 India (IND)</option>
                    <option value="ID">🇮🇩 Indonesia (ID)</option>
                    <option value="TH">🇹🇭 Thailand (TH)</option>
                    <option value="VN">🇻🇳 Vietnam (VN)</option>
                    <option value="PK">🇵🇰 Pakistan (PK)</option>
                    <option value="ME">🇸🇦 Middle East (ME)</option>
                    <option value="BR">🇧🇷 Brazil (BR)</option>
                    <option value="EU">🇪🇺 Europe (EU)</option>
                    <option value="NA">🇺🇸 North America (NA)</option>
                    <option value="TW">🇹🇼 Taiwan (TW)</option>
                </select>
            </div>
            
            <div class="form-group">
                <label>📊 Count (1-10)</label>
                <input type="number" id="count" min="1" max="10" value="1">
            </div>
            
            <button type="submit" class="btn" id="submitBtn">🚀 Generate Account(s)</button>
        </form>
        
        <div id="result"></div>
        
        <div class="endpoints">
            <h3>📡 API Endpoints</h3>
            <div class="endpoint"><span>GET</span> /gen?name=NAME&password=PASS&region=BD&count=1</div>
            <div class="endpoint"><span>GET</span> /health</div>
        </div>
        
        <div class="dev-info">
            💻 Developer: <a href="https://t.me/FF_CLIENT" target="_blank">@FF_CLIENT</a>
        </div>
    </div>

    <script>
        document.getElementById('form').addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const name = document.getElementById('name').value.trim();
            const password = document.getElementById('password').value.trim();
            const region = document.getElementById('region').value;
            const count = parseInt(document.getElementById('count').value) || 1;
            const resultDiv = document.getElementById('result');
            const submitBtn = document.getElementById('submitBtn');
            
            if (!name || !password) {
                resultDiv.className = 'error';
                resultDiv.innerHTML = '❌ Please fill in all fields';
                return;
            }
            
            if (count < 1 || count > 10) {
                resultDiv.className = 'error';
                resultDiv.innerHTML = '❌ Count must be between 1 and 10';
                return;
            }
            
            // Show loading
            resultDiv.className = 'loading';
            resultDiv.innerHTML = '<div class="loading-spinner"></div> Generating ' + count + ' account(s)...';
            submitBtn.disabled = true;
            
            try {
                const response = await fetch(`/gen?name=${encodeURIComponent(name)}&password=${encodeURIComponent(password)}&region=${encodeURIComponent(region)}&count=${count}`);
                const data = await response.json();
                
                if (data.success && data.successful > 0) {
                    resultDiv.className = 'success';
                    let html = '✅ <strong>Account Generation Complete!</strong><br><br>';
                    html += `<div class="summary">`;
                    html += `<span>📊 Total: <strong>${data.total}</strong></span>`;
                    html += `<span>✅ Success: <strong style="color:#7dffb3;">${data.successful}</strong></span>`;
                    html += `<span>❌ Failed: <strong style="color:#ff6b6b;">${data.failed}</strong></span>`;
                    html += `</div>`;
                    
                    data.accounts.forEach((acc, index) => {
                        if (acc.success) {
                            html += `<div class="account-box">`;
                            html += `<div class="account-title">✅ Account #${index + 1} <span class="badge-success">Success</span></div>`;
                            html += `<div class="account-item"><strong>UID:</strong> ${acc.uid}</div>`;
                            html += `<div class="account-item"><strong>Password:</strong> ${acc.password}</div>`;
                            html += `<div class="account-item"><strong>Name:</strong> ${acc.name}</div>`;
                            html += `<div class="account-item"><strong>Account ID:</strong> ${acc.account_id}</div>`;
                            html += `<div class="account-item"><strong>Region:</strong> ${acc.region}</div>`;
                            html += `</div>`;
                        } else {
                            html += `<div class="account-box" style="border-color:rgba(255,0,0,0.2);">`;
                            html += `<div class="account-title" style="color:#ff6b6b;">❌ Account #${index + 1} <span class="badge-failed">Failed</span></div>`;
                            html += `<div class="account-item"><strong>Error:</strong> ${acc.error || 'Unknown error'}</div>`;
                            if (acc.uid) {
                                html += `<div class="account-item"><strong>UID:</strong> ${acc.uid}</div>`;
                            }
                            if (acc.password) {
                                html += `<div class="account-item"><strong>Password:</strong> ${acc.password}</div>`;
                            }
                            html += `</div>`;
                        }
                    });
                    
                    resultDiv.innerHTML = html;
                } else {
                    resultDiv.className = 'error';
                    let html = `❌ <strong>Error: ${data.error || 'Generation failed'}</strong><br><br>`;
                    if (data.accounts) {
                        data.accounts.forEach((acc, index) => {
                            html += `<div class="result-item"><strong>Account #${index + 1}:</strong> ${acc.error || 'Unknown error'}</div>`;
                        });
                    }
                    resultDiv.innerHTML = html;
                }
            } catch (error) {
                resultDiv.className = 'error';
                resultDiv.innerHTML = `❌ Network Error: ${error.message}`;
            } finally {
                submitBtn.disabled = false;
            }
        });
        
        function copyText(text) {
            navigator.clipboard.writeText(text).then(() => {
                alert('✅ Copied to clipboard!');
            }).catch(() => {
                const input = document.createElement('input');
                input.value = text;
                document.body.appendChild(input);
                input.select();
                document.execCommand('copy');
                document.body.removeChild(input);
                alert('✅ Copied to clipboard!');
            });
        }
    </script>
</body>
</html>
'''

# ==================== FLASK API ====================
@app.route('/', methods=['GET'])
def home():
    return render_template_string(HTML_TEMPLATE)

@app.route('/gen', methods=['GET'])
def generate_account():
    name = request.args.get('name')
    password = request.args.get('password')
    region = request.args.get('region', 'BD')
    count = request.args.get('count', 1, type=int)
    
    if not name or not password:
        return jsonify({"error": "Missing required parameters: name and password"}), 400
    
    if region.upper() not in IPRotator.REGION_IP_CIDRS:
        return jsonify({"error": f"Invalid region. Supported regions: {list(IPRotator.REGION_IP_CIDRS.keys())}"}), 400
    
    if count < 1 or count > 10:
        return jsonify({"error": "Count must be between 1 and 10"}), 400
    
    result = register_account_full(name, password, region, count)
    return jsonify(result)

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({"status": "ok", "regions": list(IPRotator.REGION_IP_CIDRS.keys())})

# ==================== RUN ====================
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)