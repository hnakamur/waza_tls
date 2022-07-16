#!/bin/bash
keyfile=./tests/p256-self-signed.key.pem
certfile=./tests/p256-self-signed.crt.pem

openssl ecparam -genkey -name prime256v1 -out "${keyfile}"

openssl req -new -sha256 -x509 -nodes \
    -days 365 \
    -subj "/C=JP/ST=Osaka/L=Osaka City/CN=www.my-example.test" \
    -key "${keyfile}" \
    -out "${certfile}"

sed -i.bak '/^-----BEGIN EC PARAMETERS-----$/,/^-----END EC PARAMETERS-----$/d' "${keyfile}"
