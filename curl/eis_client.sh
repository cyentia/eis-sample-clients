#! /usr/bin/env bash
 
CLIENT_ID=<provided client id>
CLIENT_SECRET=<provided client secret>
SCOPE="openid%20profile%20read:enhanced%20offline_access"
ENDPOINT=https://auth.cyentia.com/authorize
AUDIENCE=https://eis-api.cyentia.com
CALLBACK=http://localhost:1410
 
URL="$ENDPOINT?client_id=$CLIENT_ID&response_type=code&scope=$SCOPE&access_type=offline&audience=$AUDIENCE&redirect_uri=$CALLBACK"
 
echo $URL
read -e -p "Enter the code portion of the URL generated by visiting the URL above: " AUTH_CODE
 
echo "Proceeding with AUTH_CODE: $AUTH_CODE"
 
generate_post_data()
{
    cat<<EOF
{
 "grant_type": "authorization_code",
 "client_id": "$CLIENT_ID",
 "client_secret": "$CLIENT_SECRET",
 "redirect_uri": "$CALLBACK",
 "code":"$AUTH_CODE"
}
EOF
}
 
echo "Post data is $(generate_post_data)"
 
ACCESS_TOKEN=$(curl --request POST \
    --silent \
    --url https://auth.cyentia.com/oauth/token \
    --header 'content-type: application/json' \
    --data "$(generate_post_data)" | jq -r '.access_token')
 
echo "Retrieved a JWT Access Token of: $ACCESS_TOKEN"
 
API_ENDPOINT=https://api.eis.cyentia.com/v1/cve/list/2010
 
curl --request GET \
     --url $API_ENDPOINT \
    --header 'Authorization: Bearer '"$ACCESS_TOKEN"

