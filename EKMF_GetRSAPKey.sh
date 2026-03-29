#curl -X POST http://localhost:8080/FrontendCreateRSAKeyPairRequest
FRONTEND_URL="https://localhost:4433/payload/oso1"
EKMF_JSON=$(cat <<EOF
{
  "Content": "",
  "Signature": "",
  "Metadata": {
    "type": "EKMFGENRSAKEYPAIR"
  }
}
EOF
)

#curl -X POST http://localhost:8080/FrontendEKMFCmd \
curl -sk --cert certs/client.crt --key certs/client.key -X POST "$FRONTEND_URL" \
  -H "Content-Type: application/json" \
  -d "$EKMF_JSON"
