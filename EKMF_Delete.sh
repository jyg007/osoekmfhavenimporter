#curl -X POST http://localhost:8080/FrontendCreateRSAKeyPairRequest
FRONTEND_URL="https://localhost:4433/payload/oso1"

# Check argument
if [ -z "$1" ]; then
    echo "Usage: $0 key1 key2 ..."
    exit 1
fi


CONTENT="["
for k in "$@"; do
    CONTENT+="\"$k\","
done
CONTENT="${CONTENT%,}"
CONTENT+="]"
CONTENT_STR=$(printf '%s' "$CONTENT" | sed 's/"/\\"/g')
CONTENT_FILE=$(mktemp)
echo -n "$CONTENT" > "$CONTENT_FILE"
cat $CONTENT_FILE
# --- Sign content ---
SIGNATURE=$(openssl pkeyutl -sign -inkey K/senderprivate.key -in "$CONTENT_FILE" | base64 -w 0)

# --- Build final payload ---
EKMF_JSON=$(cat <<EOF
{
  "Content": "$CONTENT_STR",
  "Signature":"$SIGNATURE" ,
  "Metadata": {
    "type": "EKMFDELETE"
  }
}
EOF
)

# Send request
curl -k --cert certs/client.crt --key certs/client.key -X POST "$FRONTEND_URL" \
  -H "Content-Type: application/json" \
  -d "$EKMF_JSON"
