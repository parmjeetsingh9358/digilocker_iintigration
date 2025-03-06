from flask import Flask, redirect, request, session, jsonify
import requests
import os
import secrets
import hashlib
import base64
from dotenv import load_dotenv
import urllib.parse

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "supersecretkey")  # Needed for session management

# DigiLocker API Endpoints
AUTH_URL = os.getenv("AUTH_URL")
TOKEN_URL = os.getenv("TOKEN_URL")
USER_INFO_URL = os.getenv("USER_INFO_URL")
DOCS_URL = os.getenv("DOCS_URL")

# DigiLocker API Credentials
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
REDIRECT_URI = os.getenv("REDIRECT_URI")

@app.route('/')
def home():
    return "DigiLocker OAuth Integration"

# Step 1: Redirect User to DigiLocker Login
@app.route('/login')
def login():
    """Redirect User to DigiLocker for Authentication"""

    code_verifier = secrets.token_urlsafe(64)
    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode()).digest()
    ).decode().rstrip("=")

    session["code_verifier"] = code_verifier
    session["oauth_state"] = secrets.token_hex(16)

    params = {
        "client_id": CLIENT_ID,
        "response_type": "code",
        "redirect_uri": REDIRECT_URI,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "state": session["oauth_state"],
        "scope": "avs_parent"  # Try "avs" if this does not work
    }

    auth_url = f"{AUTH_URL}?{urllib.parse.urlencode(params)}"
    print(f"Redirecting to Authorization URL: {auth_url}")

    return redirect(auth_url)

# Step 2: Handle Callback and Get Authorization Code
@app.route('/callback')
def callback():
    """Handle Callback and Exchange Authorization Code for Access Token"""

    print(f"Callback URL: {request.url}")

    auth_code = request.args.get("code")
    received_state = request.args.get("state")

    if not auth_code:
        return "Error: Authorization failed! No code received.", 400
    if not received_state:
        return "Error: Authorization failed! No state received.", 400
    if received_state != session.get("oauth_state"):
        return "Error: Invalid state! Possible CSRF attack.", 400

    # Step 2.1: Exchange authorization code for access token
    token_data = {
        "code": auth_code,
        "grant_type": "authorization_code",
        "client_id": CLIENT_ID,
        "code_verifier": session.get("code_verifier"),
        "client_secret": CLIENT_SECRET,
        "redirect_uri": REDIRECT_URI
    }

    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json"
    }

    print("Requesting Access Token...")

    response = requests.post(TOKEN_URL, data=token_data, headers=headers)

    print(f"Token Response: {response.status_code}, {response.text}")

    if response.status_code == 200:
        token_info = response.json()
        session["access_token"] = token_info.get("access_token")
        session["refresh_token"] = token_info.get("refresh_token")

        # Fetch User Info
        user_data = fetch_user_info(session["access_token"])

        print("User Information Data:", user_data)

        return jsonify({
            "session_data": dict(session),
            "token_info": token_info,
            "user_data": user_data
        })
    else:
        return f"❌ Error: {response.text}", response.status_code


def fetch_user_info(access_token):
    """Fetch user details from DigiLocker"""
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json"
    }
    response = requests.get(USER_INFO_URL, headers=headers)

    print(f"User Info Response: {response.status_code}, {response.text}")

    if response.status_code == 200:
        user_data = response.json()
        
        # Store user details in session
        session["digilocker_id"] = user_data.get("digilocker_id")
        session["name"] = user_data.get("name")
        session["eaadhar"] = user_data.get("eaadhaar")
        session["dob"] = user_data.get("dob")
        session["gender"] = user_data.get("gender")
        session["reference_key"] = user_data.get("reference_key")

        return user_data
    else:
        return {"error": f"Failed to fetch user data: {response.text}"}

# Step 3: Fetch User Documents from DigiLocker
@app.route('/fetch-docs')
def fetch_documents():
    """Fetch user documents from DigiLocker"""
    access_token = session.get("access_token")
    if not access_token:
        return "Unauthorized! Please login first.", 401

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json"
    }

    response = requests.get(DOCS_URL, headers=headers)

    print(f"Documents Response: {response.status_code}, {response.text}")

    if response.status_code == 200:
        return jsonify(response.json())
    else:
        return f"Error Fetching Documents: {response.text}", response.status_code

# Run Flask App
if __name__ == '__main__':
    app.run(debug=True, host="localhost", port=5000)
