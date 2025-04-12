from flask import Flask, redirect, request
import requests

app = Flask(__name__)

CLIENT_ID = '86ufub8dc5p65z'
CLIENT_SECRET = 'WPL_AP1.qvN6Z6WXd7rc9UD2.np8QRg=='
REDIRECT_URI = 'https://testing.dpdp-privcy.in.net/callback'

# Step 1: Redirect user to LinkedIn Auth URL
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

# Step 2: LinkedIn redirects to this route with "code"
@app.route('/callback')
def callback():
    auth_code = request.args.get('code')
    if not auth_code:
        return 'No auth code received', 400

    # Step 3: Exchange auth code for access token
    token_url = 'https://www.linkedin.com/oauth/v2/accessToken'
    print(token_url, "========token_url =========")
    data = {
        'grant_type': 'authorization_code',
        'code': auth_code,
        'redirect_uri': REDIRECT_URI,
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
    }
    print(data, "======data======")
    response = requests.post(token_url, data=data)
    token_data = response.json()
    print(token_data, "==================")

    if 'access_token' in token_data:
        access_token = token_data['access_token']
        return f'Access Token: {access_token}'
    else:
        return f'Error: {token_data}', 400

if __name__ == '__main__':
    app.run(debug=True)
