printf '{"json_gzip_base64":"' > /tmp/payload.$1.json
#cat /tmp/o.$1.gz.b64 >> /tmp/payload.$1.json
cat K/keys_set.$1.gz.b64 >> /tmp/payload.$1.json
printf '"}\n' >> /tmp/payload.$1.json

curl -X POST http://localhost:8080/FrontendUpload \
  -H "Content-Type: application/json" \
  --data-binary @/tmp/payload.$1.json

rm /tmp/payload.$1.json
