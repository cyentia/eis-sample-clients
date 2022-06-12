#!/usr/bin/env python3

# For local authentication we have to tell oath2 that it's OK
# that our callback endpoint is _not_ SSL.
import os

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

import json  # For parsing responses and writing tokens
import webbrowser  # For loading the authorization page

# Does the OATH2 workflow heavy lifting
# Available with `pip install requests_oathlib`
# More information can be found
# here https://requests-oauthlib.readthedocs.io/en/latest/ and
# here https://github.com/requests/requests-oauthlib
from requests_oauthlib import OAuth2Session

base_api_url = "https://api.eis.cyentia.com/v1/"  # API endpoint
client_id = "REDAXCTED"  # Your client id
client_secret = "REDACTeD"  # Your client secret
authorization_base_url = "https://auth.cyentia.com/authorize?audience=https://eis-api.cyentia.com"  # Cyentia EIS authorization URL
token_url = "https://auth.cyentia.com/oauth/token"  # Token server

# A local callback url, note this does not have to be listening for anything.
# We just need a valid (to EIS) place to send the token url information
# back to. This _could_ be a local flask app running that receives the
# the call back information and finishes the workflow, receiving the token.
# It could also be a full blown app! If you'd like to do that let us know
# and we can ensure that your internet facing app can authenticate.
# It is important that it is "http://localhost:3000/callback", as
# we restrict where exactly we'll send the info.
redirect_uri = "http://localhost:3000/callback"

# EIS specific scope information.
scope = "openid profile email offline_access read:enhanced"

# Let's see if we've already gotten a token, and if so if it works
token = None
try:
    with open("token.json", "r") as token_file:
        token = json.load(token_file)
except FileNotFoundError:  # Whoops no file, let's do the workflow
    # sets up a 'requests.session'-like object with authorization
    eis = OAuth2Session(client_id, redirect_uri=redirect_uri, scope=scope)

    # Gets us the right authorization url
    authorization_url, state = eis.authorization_url(authorization_base_url)
    try:
        # Try to visit with the webbrowser package
        webbrowser.open_new_tab(authorization_url)
    except:
        # Whoops user didn't like that, ask them to do it manually
        print(
            "Please visit this website and copy the url after authentication and redirection"
        )
        print(authorization_url)

    # After authentication the oath2 workflow will redirect to a
    # user specific authentication page. We use that to actually
    # get the token. Note it doesn't have to be listening, we jusit
    # need the url
    auth_response = input("Enter full url after redirection: ")

    # Once we've got it, send it to the token authorization url
    # which will respond with the actual token
    token = eis.fetch_token(
        token_url, authorization_response=auth_response, client_secret=client_secret
    )

    # Save this token for future use
    with open("token.json", "w") as token_file:
        json.dump(token, token_file)
else:
    # If we managed to open the token just use it
    # create a new oath2 requests.session-like object.
    eis = OAuth2Session(client_id, token=token)

# A simple lloop so you can query until your hearts content
while True:
    endpoint = input("Enter desired endpoint, help for help, exit to exit: ")
    if endpoint == "exit":
        break

    if endpoint == "help":
        print("Possible endpoints are: ")
        print(
            "\t`cve/[CVE_ID]`, e.g. `cve/CVE-2019-1122`: Gets specific cve information"
        )
        print(
            "\t`cve/list/[year]`, e.g. `cve/list/2010`: Return all cves for a specific year"
        )
        print(
            "\t`export/[YYYYMMDD]`, e.g. `export/20210910`: returns a secure link to download all data available on a specific date"
        )
        print("\t exit: Quits this prompt")
        continue

    resp = eis.get(base_api_url + endpoint)
    if resp.status_code == 200:
        json_resp = json.loads(resp.content)
        print(json.dumps(json_resp, indent=2))
    else:
        print(
            "Failed to retrieve API call. Response code {code}".format(
                code=resp.status_code
            )
        )
        if resp.status_code == 401:
            print(
                "Token may have expired, consider deleting 'token.json' and re-authorizing"
            )
