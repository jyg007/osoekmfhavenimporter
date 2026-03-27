#curl -X POST http://localhost:8080/FrontendCreateRSAKeyPairRequest

cmd=$1

EKMF_JSON=$(cat <<EOF
{
  "Content": "",
  "Signature": "",
  "Metadata": {
    "type": "$1"
  }
}
EOF
)

curl -X POST http://localhost:8080/FrontendEKMFCmd \
  -H "Content-Type: application/json" \
  -d "$EKMF_JSON"
