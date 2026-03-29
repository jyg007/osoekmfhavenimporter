FRONTEND_URL="http://localhost:8080/FrontendEKMFCmd"
FRONTEND_URL="https://localhost:4433/payload/oso1"
CONTENT_FILE="K/keys_set.$1.gz.b64"
UUID="ekmfimport-$(uuidgen)"

# Sign the content and encode in base64
if [[ ! -f K/senderprivate.key ]]
then
	echo "Missing sender private key"
	exit 1
fi
CONTENT=$(<"$CONTENT_FILE")

SIGNATURE=$(openssl pkeyutl -sign -inkey K/senderprivate.key -in "$CONTENT_FILE" | base64 -w 0)
# Build JSON payload with embedded signature
cat <<EOF > /tmp/payload.$1.json
{
  "content": "$CONTENT",
  "signature": "$SIGNATURE",
  "metadata": {
    "type": "EKMFKEYSIMPORT",
    "id": "$UUID"
  }
}
EOF

curl -sk --cert certs/client.crt --key certs/client.key -X POST "$FRONTEND_URL" \
  -H "Content-Type: application/json" \
  --data-binary @/tmp/payload.$1.json

#rm /tmp/payload.$1.json*
