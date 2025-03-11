from flask import Flask, redirect, request, session, jsonify
import requests
import os
import secrets
import json
import hashlib
import base64
import urllib.parse
from dotenv import load_dotenv
import config

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "supersecretkey")  # Needed for session management

# DigiLocker API Endpoints
AUTH_URL = config.AUTH_URL
TOKEN_URL = config.TOKEN_URL
DOCS_URL = config.DOCS_URL

# DigiLocker API Credentials
CLIENT_ID = config.CLIENT_ID
CLIENT_SECRET = config.CLIENT_SECRET
REDIRECT_URI = config.REDIRECT_URI
USER_INFO_URL = config.USER_INFO_URL
AUTH_ENDPOINT = config.AUTH_ENDPOINT
ACCESS_TOKEN_URL = config.ACCESS_TOKEN_URL

def base64_url_encode_without_padding(data):
    """Encodes data in Base64 URL format without padding"""
    encoded = base64.urlsafe_b64encode(data).decode('utf-8')
    return encoded.rstrip("=")

def generate_code_challenge_verifier(nbytes, method):
    """Generates a code verifier and code challenge"""
    code_verifier = base64_url_encode_without_padding(os.urandom(nbytes))
    
    if method == 'S256':
        hash_digest = hashlib.sha256(code_verifier.encode()).digest()
        code_challenge = base64_url_encode_without_padding(hash_digest)
    else:
        code_challenge = code_verifier
    
    return {
        'code_verifier': code_verifier,
        'code_challenge': code_challenge
    }

@app.route('/')
def home():
    return "DigiLocker OAuth Demo"

@app.route('/login')
def login():
    """Step 1: Redirect User to DigiLocker for Authentication"""
    verifier_data = generate_code_challenge_verifier(96, 'S256')
    session["code_verifier"] = verifier_data['code_verifier']
    session["oauth_state"] = secrets.token_hex(16)  

    params = {
    "client_id": CLIENT_ID,
    "response_type": "code",
    "redirect_uri": REDIRECT_URI,
    "code_challenge": verifier_data['code_challenge'],
    "code_challenge_method": "S256",
    "state": session["oauth_state"],
    "scope": "userdetails email address avs",
    "prompt": "consent"
    }

    auth_url = f"{AUTH_ENDPOINT}?{urllib.parse.urlencode(params)}"
    return redirect(auth_url)

@app.route('/callback')
def callback():
    """Step 2: Handle Callback and Exchange Authorization Code for Access Token"""
    auth_code = request.args.get("code")
    received_state = request.args.get("state")

    if not auth_code or received_state != session.get("oauth_state"):
        return "Error: Authorization failed!", 400
    
    token_data = {
        "code": auth_code,
        "grant_type": "authorization_code",
        "client_id": CLIENT_ID,
        "code_verifier": session.get("code_verifier"),
        "client_secret": CLIENT_SECRET,
        "redirect_uri": REDIRECT_URI
    }

    response = requests.post(ACCESS_TOKEN_URL, data=token_data)
    
    if response.status_code == 200:
        token_info = response.json()
        session.update(token_info)

        print(f"🔹 Granted Scopes: {token_info.get('scope')}")

        user_data = fetch_user_info(session["access_token"])
        return jsonify({
            "session_data": dict(session),
            "token_info": token_info,
            "user_info": user_data
        })
    else:
        return f"❌ Error: {response.text}", response.status_code


def fetch_user_info(access_token):
    """Fetch user details from DigiLocker using access token"""
    headers = {"Authorization": f"Bearer {access_token}", "Accept": "application/json"}
    print(f"headers: {headers}")
    response = requests.get(USER_INFO_URL, headers=headers)
    print(f"user_info: {response.text}")
    return response.json() if response.status_code == 200 else {"error": response.text}

@app.route('/fetch-docs')
def fetch_documents():
    """Fetch user documents from DigiLocker"""
    access_token = session.get("access_token")
    if not access_token:
        return "Unauthorized! Please login first.", 401

    headers = {"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"}
    response = requests.get(DOCS_URL, headers=headers)
    return jsonify(response.json()) if response.status_code == 200 else ("Error Fetching Documents", response.status_code)

if __name__ == '__main__':
    app.run(debug=True, host="localhost", port=5000)
