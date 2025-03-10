from flask import Flask, request, jsonify
import requests
import config

app = Flask(__name__)

# DigiLocker API Credentials
CLIENT_ID = config.CLIENT_ID
CLIENT_SECRET = config.CLIENT_SECRET
REDIRECT_URI = config.REDIRECT_URI
BASE_URL = "https://digilocker.gov.in/public/oauth2"

@app.route("/auth", methods=["GET"])
def authenticate():
    """Initiate DigiLocker Authentication."""
    auth_url = f"{BASE_URL}/authorize?response_type=code&client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&state=xyz"
    return jsonify({"auth_url": auth_url})

@app.route("/token", methods=["POST"])
def get_token():
    """Exchange code for access token."""
    code = request.json.get("code")
    if not code:
        return jsonify({"error": "Missing authorization code"}), 400
    
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "redirect_uri": REDIRECT_URI
    }
    
    response = requests.post(f"{BASE_URL}/token", data=data)
    return jsonify(response.json())

@app.route("/fetch-documents", methods=["GET"])
def fetch_documents():
    """Fetch user's documents from DigiLocker."""
    access_token = request.headers.get("Authorization")
    if not access_token:
        return jsonify({"error": "Missing access token"}), 401
    
    headers = {"Authorization": f"Bearer {access_token}"}
    response = requests.get("https://digilocker.gov.in/api/v1/fetch/documents", headers=headers)
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
