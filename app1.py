import hashlib
import base64
import os
from flask import Flask, request, jsonify, session
import requests
import config
import logging

app = Flask(__name__)
app.secret_key = "b48dd4cbb56a06cb2e13"  # Change this to a strong, random value

# DigiLocker API Credentials
CLIENT_ID = config.CLIENT_ID
CLIENT_SECRET = config.CLIENT_SECRET
REDIRECT_URI = config.REDIRECT_URI
BASE_URL = "https://digilocker.meripehchaan.gov.in/public/oauth2"

logging.basicConfig(level=logging.INFO)

def generate_code_verifier():
    """Generate a secure random code_verifier"""
    verifier = base64.urlsafe_b64encode(os.urandom(32)).decode("utf-8")
    return verifier.rstrip("=")

def generate_code_challenge(code_verifier):
    """Generate code_challenge using SHA256 hashing"""
    digest = hashlib.sha256(code_verifier.encode("utf-8")).digest()
    challenge = base64.urlsafe_b64encode(digest).decode("utf-8")
    return challenge.rstrip("=")

@app.route("/auth", methods=["GET"])
def authenticate():
    """Initiate DigiLocker Authentication with PKCE"""
    state = request.args.get("state", "default_state")  
    session["state"] = state  # Store state in session

    # Generate PKCE values
    code_verifier = generate_code_verifier()
    code_challenge = generate_code_challenge(code_verifier)
    
    session["code_verifier"] = code_verifier

    auth_url = (
        f"{BASE_URL}/authorize?"
        f"response_type=code&client_id={CLIENT_ID}"
        f"&redirect_uri={REDIRECT_URI}&state={state}"
        f"&code_challenge={code_challenge}"
        f"&code_challenge_method=S256"
        f"&scope=avs"
    )

    logging.info(f"Generated Auth URL: {auth_url}")
    return jsonify({"auth_url": auth_url})


@app.route("/token", methods=["POST"])
def get_token():
    """Exchange authorization code for access token using PKCE"""
    code = request.json.get("code")
    if not code:
        return jsonify({"error": "Missing authorization code"}), 400

    code_verifier = session.get("code_verifier")
    if not code_verifier:
        return jsonify({"error": "Missing code_verifier"}), 400

    data = {
        "grant_type": "authorization_code",
        "code": code,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "redirect_uri": REDIRECT_URI,
        "code_verifier": code_verifier,
    }

    response = requests.post(f"{BASE_URL}/token", data=data)
    
    if response.status_code != 200:
        logging.error(f"Error fetching token: {response.text}")
        return jsonify({"error": "Failed to fetch access token"}), response.status_code

    token_data = response.json()
    session["access_token"] = token_data.get("access_token")  # Store access token in session

    return jsonify(token_data)


@app.route("/callback", methods=["GET"])
def callback():
    """Handle DigiLocker OAuth2 callback."""
    code = request.args.get("code")
    state = request.args.get("state")

    if not code:
        return jsonify({"error": "Authorization code missing"}), 400

    # Retrieve stored state from session (for validation)
    stored_state = session.get("state")
    if state != stored_state:
        return jsonify({"error": "Invalid state parameter"}), 400

    # Store authorization code in session (optional)
    session["auth_code"] = code

    # Proceed to token exchange
    return jsonify({"message": "Authorization successful", "code": code})


@app.route("/fetch-documents", methods=["GET"])
def fetch_documents():
    """Fetch user's documents from DigiLocker."""
    access_token = request.headers.get("Authorization")

    # Try fetching token from session if not found in headers
    logging.error(f"Error Access Token: {access_token}")
    if not access_token:
        access_token = session.get("access_token")

    if not access_token:
        return jsonify({"error": "Missing access token"}), 401

    headers = {"Authorization": f"Bearer {access_token}"}
    response = requests.get("https://digilocker.gov.in/api/v1/fetch/documents", headers=headers)
    logging.error(f"Error fetching documents: {response}")
    
    if response.status_code != 200:
        logging.error(f"Error fetching documents: {response.text}")
        return jsonify({"error": "Failed to fetch documents"}), response.status_code

    return jsonify(response.json())

@app.route("/verify-otp", methods=["POST"])
def verify_otp():
    """Verify OTP received from DigiLocker."""
    otp = request.json.get("otp")
    transaction_id = request.json.get("transaction_id")
    
    if not otp or not transaction_id:
        return jsonify({"error": "Missing OTP or transaction ID"}), 400
    
    data = {
        "otp": otp,
        "transaction_id": transaction_id,
    }
    
    response = requests.post("https://digilocker.gov.in/api/v1/verify/otp", json=data)
    return jsonify(response.json())

if __name__ == "__main__":
    app.run(debug=True)
