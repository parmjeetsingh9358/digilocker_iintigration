from flask import Flask, request, jsonify, redirect, session
import requests
import os
import secrets
import base64
import hashlib
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "supersecretkey")  # Set Flask session key

# DigiLocker API Base URL
BASE_URL = "https://digilocker.meripehchaan.gov.in/public/oauth2/1"

# API Credentials (From .env)
CLIENT_ID = "HMBAEBFEE0"
CLIENT_SECRET = "b48dd4cbb56a06cb2e03"
REDIRECT_URI = "https://testing.dpdp-privcy.in.net/callback"

def generate_code_challenge():
    """Generate a secure PKCE code challenge and code verifier"""
    code_verifier = secrets.token_urlsafe(64)
    session["code_verifier"] = code_verifier  # Store in session for later token exchange

    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode()).digest()
    ).decode().rstrip("=")  # Remove padding

    return code_challenge

@app.route("/authorize", methods=["GET"])
def authorize():
    """Initiates OAuth 2.0 flow and redirects user to DigiLocker"""
    session["oauth_state"] = secrets.token_hex(16)  # CSRF protection
    code_challenge = generate_code_challenge()

    auth_url = (
        f"{BASE_URL}/authorize?client_id=HMBAEBFEE0&response_type=code"
        f"&redirect_uri={REDIRECT_URI}&state={session['oauth_state']}"
        f"&code_challenge={code_challenge}&code_challenge_method=S256"
        f"&scope=avs_parent"  # Request multiple scopes
        f"&dl_flow=consent"
        f"&Verified_mobile=7830508718"  # Replace with actual verified mobile if required
    )

    return redirect(auth_url)

@app.route("/callback", methods=["GET"])
def callback():
    """Handles DigiLocker OAuth callback and fetches the Bearer Token"""
    auth_code = request.args.get("code")
    state = request.args.get("state")

    # Validate the authorization code and state
    if not auth_code:
        return jsonify({"error": "Missing authorization code"}), 400
    if state != session.get("oauth_state"):
        return jsonify({"error": "Invalid state parameter"}), 400

    code_verifier = session.get("code_verifier")
    if not code_verifier:
        return jsonify({"error": "Missing code_verifier"}), 400

    token_url = f"{BASE_URL}/token"
    payload = {
        "grant_type": "authorization_code",
        "code": auth_code,
        "redirect_uri": REDIRECT_URI,
        "code_verifier": code_verifier,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET
    }

    headers = {"Content-Type": "application/json"}
    response = requests.post(token_url, json=payload, headers=headers)

    if response.status_code == 200:
        token_data = response.json()
        bearer_token = token_data.get("access_token")
        refresh_token = token_data.get("refresh_token")
        granted_scopes = token_data.get("scope")  # Check granted scopes

        if bearer_token:
            session["BEARER_TOKEN"] = bearer_token  # Store access token in session
            session["REFRESH_TOKEN"] = refresh_token  # Store refresh token

            return jsonify({
                "message": "Bearer token generated successfully",
                "bearer_token": bearer_token,
                "refresh_token": refresh_token,
                "granted_scopes": granted_scopes
            })

    return jsonify({"error": "Failed to fetch Bearer Token", "details": response.text}), 400


@app.route("/refresh_token", methods=["POST"])
def refresh_access_token():
    """Refresh the access token using the refresh token"""
    refresh_token = session.get("REFRESH_TOKEN")

    if not refresh_token:
        return jsonify({"error": "Refresh token not found"}), 401

    token_url = f"{BASE_URL}/token"
    payload = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET
    }

    headers = {"Content-Type": "application/json"}
    response = requests.post(token_url, json=payload, headers=headers)

    if response.status_code == 200:
        token_data = response.json()
        new_access_token = token_data.get("access_token")
        new_refresh_token = token_data.get("refresh_token")  # Update refresh token

        session["BEARER_TOKEN"] = new_access_token
        session["REFRESH_TOKEN"] = new_refresh_token

        return jsonify({
            "message": "Access token refreshed successfully",
            "bearer_token": new_access_token,
            "refresh_token": new_refresh_token
        })

    return jsonify({"error": "Failed to refresh access token", "details": response.text}), 400


@app.route("/device_auth", methods=["POST"])
def get_token_using_device_code():
    """Obtain an access token using a device code and OTP"""
    data = request.json
    device_code = data.get("device_code")
    dl_otp = data.get("dl_otp")

    if not device_code or not dl_otp:
        return jsonify({"error": "Missing device_code or dl_otp"}), 400

    token_url = f"{BASE_URL}/token"
    payload = {
        "client_id": CLIENT_ID,
        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        "device_code": device_code,
        "dl_otp": dl_otp
    }

    headers = {"Content-Type": "application/json"}
    response = requests.post(token_url, json=payload, headers=headers)

    if response.status_code == 200:
        token_data = response.json()
        bearer_token = token_data.get("access_token")

        if bearer_token:
            session["BEARER_TOKEN"] = bearer_token  # Store access token in session
            return jsonify({
                "message": "Bearer token generated successfully",
                "bearer_token": bearer_token
            })

    return jsonify({"error": "Failed to obtain access token via device code", "details": response.text}), 400


@app.route("/get_user_info", methods=["GET"])
def get_user_info():
    """Fetch user information from DigiLocker"""
    bearer_token = session.get("BEARER_TOKEN")
    if not bearer_token:
        return jsonify({"error": "Bearer Token not found"}), 401

    headers = {"Authorization": f"Bearer {bearer_token}"}
    response = requests.get(f"{BASE_URL}/user", headers=headers)

    if response.status_code == 200:
        return jsonify(response.json())
    
    return jsonify({"error": "Request failed", "details": response.text}), response.status_code

if __name__ == "__main__":
    app.run(debug=True)
