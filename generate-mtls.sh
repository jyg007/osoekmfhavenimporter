#!/usr/bin/env bash
set -e

mkdir -p certs
cd certs

echo "== Generating CA =="
openssl genrsa -out ca.key 4096

openssl req -x509 -new -nodes \
    -key ca.key \
    -sha256 -days 3650 \
    -subj "/C=FR/ST=IDF/O=TestCA/CN=Test-Root-CA" \
    -out ca.crt


echo "== Generating server key =="
openssl genrsa -out server.key 4096

echo "== Generating server CSR =="
openssl req -new \
    -key server.key \
    -subj "/C=FR/ST=IDF/O=TestServer/CN=localhost" \
    -out server.csr


echo "== Signing server certificate with CA =="

cat > server.ext <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
IP.1  = 127.0.0.1
EOF

openssl x509 -req \
    -in server.csr \
    -CA ca.crt \
    -CAkey ca.key \
    -CAcreateserial \
    -out server.crt \
    -days 3650 \
    -sha256 \
    -extfile server.ext


echo "== Generating client key =="
openssl genrsa -out client.key 4096

echo "== Generating client CSR =="
openssl req -new \
    -key client.key \
    -subj "/C=FR/ST=IDF/O=TestClient/CN=client1" \
    -out client.csr


echo "== Signing client certificate with CA =="

cat > client.ext <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature
extendedKeyUsage = clientAuth
EOF

openssl x509 -req \
    -in client.csr \
    -CA ca.crt \
    -CAkey ca.key \
    -CAcreateserial \
    -out client.crt \
    -days 3650 \
    -sha256 \
    -extfile client.ext


echo ""
echo "== Done =="
echo ""
echo "Files created in ./certs:"
echo "ca.crt"
echo "server.crt  server.key"
echo "client.crt  client.key"
