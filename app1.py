from flask import Flask, request, jsonify, redirect
import requests
import os
import json

app = Flask(__name__)

# DigiLocker API Base URL
BASE_URL = "https://digilocker.meripehchaan.gov.in/public/oauth2/1"

# API Credentials (Replace with actual values)
CLIENT_ID = os.getenv("CLIENT_ID", "HMBAEBFEE0")
CLIENT_SECRET = os.getenv("CLIENT_SECRET", "b48dd4cbb56a06cb2e03")
REDIRECT_URI = os.getenv("REDIRECT_URI", "https://testing.dpdp-privcy.in.net/callback")

# Authorization URL
@app.route("/authorize", methods=["GET"])
def authorize():
    """Initiates the OAuth 2.0 authorization flow"""
    auth_url = (
        f"{BASE_URL}/authorize?client_id={CLIENT_ID}&response_type=code"
        f"&redirect_uri={REDIRECT_URI}&state=12345"
        f"&code_challenge=base64_url_encode_without_padding(sha256(code_verifier))"
        f"&code_challenge_method=S256"
    )
    return redirect(auth_url)

# Callback URL to get the Bearer Token
@app.route("/callback", methods=["GET"])
def callback():
    """Handles DigiLocker OAuth callback and fetches the Bearer Token"""
    auth_code = request.args.get("code")  # Get the authorization code from DigiLocker

    if not auth_code:
        return jsonify({"error": "Authorization code not found"}), 400

    token_url = f"{BASE_URL}/token"

    payload = {
        "code": auth_code,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "redirect_uri": REDIRECT_URI,
        "grant_type": "authorization_code"
    }

    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    response = requests.post(token_url, data=payload, headers=headers)

    if response.status_code == 200:
        token_data = response.json()
        bearer_token = token_data.get("access_token")

        if bearer_token:
            # Store token in environment variable (for current session)
            os.environ["BEARER_TOKEN"] = bearer_token
            return jsonify({"message": "Bearer token generated successfully", "bearer_token": bearer_token})

    return jsonify({"error": "Failed to fetch Bearer Token", "details": response.text}), 400

# Fetch the Bearer Token securely
def get_bearer_token():
    return os.getenv("BEARER_TOKEN", "your_bearer_token")

# Example API request using Bearer Token
@app.route("/get_user_info", methods=["GET"])
def get_user_info():
    """Fetches user information from DigiLocker using the Bearer Token"""
    bearer_token = get_bearer_token()
    
    if bearer_token == "your_bearer_token":
        return jsonify({"error": "Bearer Token not available"}), 401

    headers = {"Authorization": f"Bearer {bearer_token}"}

    response = requests.get(f"{BASE_URL}/user", headers=headers)

    return jsonify(response.json()) if response.status_code == 200 else jsonify({"error": "Failed to fetch user info"}), 400

if __name__ == "__main__":
    app.run(debug=True)
