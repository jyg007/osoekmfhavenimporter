#curl -X POST http://localhost:8080/FrontendCreateRSAKeyPairRequest

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

curl -X POST http://localhost:8080/FrontendEKMFCmd \
  -H "Content-Type: application/json" \
  -d "$EKMF_JSON"
