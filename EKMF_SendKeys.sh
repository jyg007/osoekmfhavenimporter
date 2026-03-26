#!/bin/bash
FRONTEND_URL="http://localhost:8080/FrontendEKMFCmd"

UUID="ekmfimport-$(uuidgen)"

printf '{"content":"' > /tmp/payload.$1.json

cat K/keys_set.$1.gz.b64 >> /tmp/payload.$1.json

printf '","signature":"","metadata":{"type":"EKMFKEYSIMPORT","id":"%s"}}\n' "$UUID" >> /tmp/payload.$1.json


curl -X POST "$FRONTEND_URL" \
  -H "Content-Type: application/json" \
  --data-binary @/tmp/payload.$1.json

#rm /tmp/payload.$1.json
