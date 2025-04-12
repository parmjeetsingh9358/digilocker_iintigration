from flask import Flask, redirect, request
import requests

app = Flask(__name__)

CLIENT_ID = '86ufub8dc5p65z'
CLIENT_SECRET = 'WPL_AP1.qvN6Z6WXd7rc9UD2.np8QRg=='
REDIRECT_URI = 'https://testing.dpdp-privcy.in.net/callback'  # Ensure this is exactly the same as in LinkedIn app settings

@app.route('/')
def login():
    auth_url = (
        "https://www.linkedin.com/oauth/v2/authorization"
        "?response_type=code"
        f"&client_id={CLIENT_ID}"
        f"&redirect_uri={REDIRECT_URI}"
        "&scope=r_liteprofile%20r_emailaddress%20w_member_social"
    )
    return redirect(auth_url)

@app.route('/callback')
def callback():
    auth_code = request.args.get('code')
    if not auth_code:
        return 'No auth code received', 400

    token_url = 'https://www.linkedin.com/oauth/v2/accessToken'
    data = {
        'grant_type': 'authorization_code',
        'code': auth_code,
        'redirect_uri': REDIRECT_URI,
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
    }

    response = requests.post(token_url, data=data)
    token_data = response.json()

    if 'access_token' in token_data:
        return f"Access Token: {token_data['access_token']}"
    return f"Error: {token_data}", 400

if __name__ == '__main__':
    app.run(debug=True)
