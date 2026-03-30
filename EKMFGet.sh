tmp=$(mktemp)

curl -k -s --cert certs/client.crt --key certs/client.key  https://localhost:4433/response/oso1 > "$tmp"

cat "$tmp" | jq -r .

if jq -e '.count > 0' "$tmp" >/dev/null; then
    mv "$tmp" Q.json
else
    rm -f "$tmp"
fi
