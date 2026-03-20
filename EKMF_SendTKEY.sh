#!/bin/bash

# --- 1. Configuration ---
# Update this to your actual frontend address
FRONTEND_URL="http://localhost:8080/FrontEndUploadTKEY"

# --- 2. Check for Arguments ---
# We expect 3 arguments: pubkey_path rsa_id hex_seed
if [ "$#" -ne 3 ]; then
    echo "Usage: $0 <pubkey_path> <rsa_id> <hex_seed>"
    echo "Example: $0 /tmp/public.pem rsa-123 8c123..."
    exit 1
fi

PUB_KEY=$1
RSA_ID=$2
HEX_SEED=$3

# --- 3. Run the Wrapper and Capture JSON ---
# We use grep to ignore the "Successfully loaded..." text line
RAW_JSON=$(./rsawrapTKEY "$PUB_KEY" "$RSA_ID" "$HEX_SEED" | grep -o '{.*}')

if [ -z "$RAW_JSON" ]; then
    echo "Error: rsawrapTKEY failed or produced no JSON output."
    exit 1
fi

# --- 4. POST to Frontend ---
echo "Uploading to $FRONTEND_URL..."

# -s: Silent (no progress bar)
# -d @-: Reads the JSON from the pipe (stdin)
response=$(echo "$RAW_JSON" | curl -s -X POST "$FRONTEND_URL" \
     -H "Content-Type: application/json" \
     -d @-)

# --- 5. Log Result ---
# Append the server's response to your log file
echo "$(date): ID=$RSA_ID - Response: $response" 

