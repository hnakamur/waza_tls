#!/bin/bash
keyfile=./tests/rsa2048.key.pem
certfile=./tests/rsa2048.crt.pem

# make header BEGIN RSA PRIVATE KEY, not BEGIN PRIVATE KEY with -traditional
openssl genrsa -traditional -out "$keyfile" 2048

openssl req -new -sha256 -x509 -nodes \
    -days 365 \
    -subj "/C=JP/ST=Osaka/L=Osaka City/CN=my-server.example.test" \
    -key "${keyfile}" \
    -out "${certfile}"
