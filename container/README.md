
#EKMF Addon - backend 
```
podman run --rm   -p 9080:9080   -e mode=backend   -e EP11_IBM_TARGET_HSM="4.16 3.16"  --volume ./data:/data:Z   --device /dev/z90crypt:/dev/z90crypt   localhost/emkfimport:1.0
```

# EKMF Addon - frontend

`OSOQUEUE` specifies the name of OSO queue to used when contactings EKMF API server to retrieve msgs or post respones.
`CLIENTCERT`, `CLIENTKEY` and `CACERTS` are used for mtls between the EKMF addon and the EKMF API server

`ED25519_PUBLIC_KEY` used to verify the intgrity of the EKMF message injected in the EKMF API server.  Only EKMFKEYSIMPORT are checked.

```
export ED25519_PUBLIC_KEY=$(openssl pkey -pubin -in K/senderpublic.pem -pubout -outform DER | base64 -w0)
export CLIENTCERT=$(base64 -w0 certs/client.crt)
export CLIENTKEY=$(base64 -w0 certs/client.key)
export CACERT=$(base64 -w0 certs/ca.crt)

podman run --rm \
  -p 8080:8080 \
  -e ED25519_PUBLIC_KEY \
  -e CLIENTCERT \
  -e CLIENTKEY \
  -e CACERT \
  -e mode=frontend \
  -e OSOQUEUE=oso1 \
  localhost/emkfimport:1.0
```

# EKMF API server

Server queried by the EKMF addons

`OSOQUEUES="oso1" ./bin/ekmfQ`
