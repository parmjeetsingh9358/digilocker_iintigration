import os

# CLIENT_ID = "HMBAEBFEE0"
CLIENT_ID = "VL558E2260"
# CLIENT_SECRET = "b48dd4cbb56a06cb2e03"
CLIENT_SECRET = "b635a872f2ce72667ea0"
REDIRECT_URI = "https://testing.dpdp-privcy.in.net/callback"

SETU_CLIENT_ID = "HMBAEBFEE0"
SETU_CLIENT_SECRET = "b48dd4cbb56a06cb2e03"
SETU_PRODUCT_INSTANCE_ID = "891707ee-d6cd-4744-a28d-058829e30f10"

AUTH_URL = "https://digilocker.meripehchaan.gov.in/public/oauth2/1/authorize"
TOKEN_URL = "https://digilocker.meripehchaan.gov.in/public/oauth2/1/token"
DOCS_URL = "https://digilocker.meripehchaan.gov.in/public/oauth2/1/files"
# USER_INFO_URL = "https://digilocker.meripehchaan.gov.in/public/oauth2/1/user"

BASE_URL = "https://api.digitallocker.gov.in/public/oauth2/1"

AUTH_ENDPOINT = "{}/authorize".format(BASE_URL)
ACCESS_TOKEN_URL = "{}/token".format(BASE_URL)
USER_INFO_URL = "{}/user".format(BASE_URL)

# Flask App Settings
SECRET_KEY = os.urandom(24)