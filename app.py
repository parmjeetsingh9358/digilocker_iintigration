from flask import Flask, redirect, request, session, jsonify
import requests
import os
import secrets
import json
import hashlib
import base64
from dotenv import load_dotenv
import config
import urllib.parse

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

@app.route('/')
def home():
    return "DigiLocker OAuth Demo"

# Step 1: Redirect User to DigiLocker Login
@app.route('/login')
def login():
    """Step 1: Redirect User to DigiLocker for Authentication"""

    # Generate PKCE (Proof Key for Code Exchange)
    code_verifier = secrets.token_urlsafe(64)
    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode()).digest()
    ).decode().rstrip("=")

    # Store code_verifier and state in session
    session["code_verifier"] = code_verifier
    session["oauth_state"] = secrets.token_hex(16)  

    # OAuth2 Authorization URL parameters
    params = {
            "client_id": CLIENT_ID,
            "response_type": "code",
            "redirect_uri": REDIRECT_URI,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "state": session["oauth_state"],
            "scope": "avs_parent"
        }
    # params = {
    #     "response_type": "code",
    #     "client_id": CLIENT_ID,
    #     "redirect_uri": REDIRECT_URI,
    #     "state": session["oauth_state"],
    #     "code_challenge": code_challenge,
    #     "code_challenge_method": "S256",
    #     "scope": "profile identity avs_partner"  # Add missing scopes
    # }

    # auth_url = f"{AUTH_URL}?{urllib.parse.urlencode(params)}"
    # print(f"Redirecting to Authorization URL: {auth_url}")  # Debugging
    # return redirect(auth_url)
    auth_url = f"{AUTH_ENDPOINT}?{urllib.parse.urlencode(params)}"
    print(f"Redirecting to Authorization URL: {auth_url}")  # ✅ Correct print statement

    return redirect(auth_url)

# Step 2: Handle Callback and Get Authorization Code
@app.route('/callback')
def callback():
    """Step 2: Handle Callback and Exchange Authorization Code for Access Token"""

    print(f"Callback URL: {request.url}")  # Debugging

    auth_code = request.args.get("code")
    received_state = request.args.get("state")

    print(f"auth_code: {auth_code}")
    print(f"received_state: {received_state}")

    # Validate received parameters
    if not auth_code:
        return "Error: Authorization failed! No code received.", 400
    if not received_state:
        return "Error: Authorization failed! No state received.", 400
    if received_state != session.get("oauth_state"):
        return "Error: Invalid state! Possible CSRF attack.", 400

    # ✅ Correct JSON Payload Format
    # token_data = {
    #     "grant_type": "authorization_code",  # ✅ Correct grant type
    #     "code": auth_code,
    #     "redirect_uri": REDIRECT_URI,
    #     "code_verifier": session.get("code_verifier"),
    #     "client_id": CLIENT_ID,
    #     "client_secret": CLIENT_SECRET,
    # }
    token_data = {
            "code": auth_code,
            "grant_type": "authorization_code",  # ✅ Correct grant type
            "client_id": CLIENT_ID,
            "code_verifier": session.get("code_verifier"),
            "client_secret": CLIENT_SECRET,
            "redirect_uri": REDIRECT_URI
        }
    # return self.connection.make_request(ACCESS_TOKEN_URL, "POST", data=request_body)

    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json"
    }

    print("Token Request Data:", token_data)  # Debugging

    # ✅ Use json= for correct request format
    
    response = requests.post(ACCESS_TOKEN_URL, data=token_data)  # ✅ Use 'data=' instead of 'json='

    print(f"Token Response: {response.status_code}, {response.text}")  # Debugging
    
    if response.status_code == 200:
        token_info = response.json()
        
        # ✅ Extracting and storing the necessary token details
        session["access_token"] = token_info.get("access_token")
        session["refresh_token"] = token_info.get("refresh_token")
        session["digilocker_id"] = token_info.get("digilocker_id")
        session["name"] = token_info.get("name")
        session["eaadhar"] = token_info.get("eaadhar")
        session["dob"] = token_info.get("dob")
        session["gender"] = token_info.get("gender")
        session["reference_key"] = token_info.get("reference_key")

        user_data = fetch_user_info(session["access_token"])

        print("User Information Data:", user_data)
        print("session Information Data:", session)
        print("Token Information Data:", token_info)
        print(jsonify(dict(session)))
        return jsonify({
            "session_data": dict(session),  # Convert session object to dictionary
            "token_info": token_info
        })  # ✅ Return full token response as JSON
    else:
        return f"❌ Error: {response.text}", response.status_code
    
    
def fetch_user_info(access_token):
    """Fetch user details from DigiLocker using access token"""
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json"
    }
    response = requests.get(USER_INFO_URL, headers=headers)

    print(f"User Info Response: {response.status_code}, {response.text}")  # Debugging

    if response.status_code == 200:
        return response.json()  # ✅ Return user details
    else:
        return {"error": f"Failed to fetch user data: {response.text}"}
    

# ✅ New Route to Print All Session Data for Debugging
@app.route('/session-info')
def session_info():
    """Returns all stored session data for debugging"""
    return jsonify(dict(session))


# Step 3: Fetch User Documents from DigiLocker
@app.route('/fetch-docs')
def fetch_documents():
    """Fetch user documents from DigiLocker"""
    access_token = session.get("access_token")
    if not access_token:
        return "Unauthorized! Please login first.", 401

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }

    response = requests.get(DOCS_URL, headers=headers)

    if response.status_code == 200:
        return jsonify(response.json())
    else:
        return f"Error Fetching Documents: {response.text}", response.status_code

# Move the app.run to the end!
if __name__ == '__main__':
    app.run(debug=True, host="localhost", port=5000)
