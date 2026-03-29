#!/bin/bash

# --- 1. Configuration ---
#FRONTEND_URL="http://localhost:8080/FrontendEKMFCmd"
FRONTEND_URL="https://localhost:4433/payload/oso1"

# --- 2. Check for Arguments ---
if [ "$#" -ne 3 ]; then
    echo "Usage: $0 <pubkey_path> <rsa_id> <tkey blob>"
    echo "Example: $0 /tmp/public.pem rsa-123 8c123..."
    exit 1
fi

PUB_KEY=$1
RSA_ID=$2
HEX_SEED=$3

# --- 3. Prepare Wrapped Key ---
# Convert public key to DER + hex
ASN1PK=$(openssl pkey -pubin -in "$PUB_KEY" -outform DER | xxd -p -c 1000)

# Wrap key using your HSM tool
WRAPPEDKEY=$(./hsmrsawrapTKEY "$ASN1PK" "$HEX_SEED" | grep -v Initia)

if [ -z "$WRAPPEDKEY" ]; then
    echo "Error: hsmrsawrapTKEY failed or produced no output."
    exit 1
fi

# --- 4. Build EKMF JSON payload ---
# Content = wrapped key
# Metadata = JSON string with type and keyid
EKMF_JSON=$(jq -n \
    --arg content "$WRAPPEDKEY" \
    --arg type "EKMFTKEY" \
    --arg keyid "$RSA_ID" \
    '{
        Content: $content,
        Signature: "",
        Metadata: {
            type: $type,
            keyid: $keyid
        }
    }'
)

# --- 5. POST to Frontend ---
#echo "Uploading EKMF command to $FRONTEND_URL..."
#response=$(echo "$EKMF_JSON" | curl -s -X POST "$FRONTEND_URL" \
response=$(echo "$EKMF_JSON" | curl -k -s --cert certs/client.crt --key certs/client.key -X POST "$FRONTEND_URL" \
    -H "Content-Type: application/json" \
    -d @-)

# --- 6. Log Result ---
echo "$(date): ID=$RSA_ID - Response: $response"
