waza_tls
========

waza_tls is an experimental TLS library written in Zig.

This project is meant for me to learn Zig and TLS.
I'm not a security expert and this library is not meant for production use.

## steps to generate keys, self-signed certificates, self-signed CA for tests

### `tests/rsa2048.{crt,key}.pem`

Install OpenSSL CLI and run the following command:

```
./create_rsa2048_self_signed_cert.sh
```

### `tests/p256-self-signed.{crt,key}.pem`

Install OpenSSL CLI and run the following command:

```
./create_p256_self_signed_cert.sh
```

### `tests/client_cert/my-root-ca.{crt,key}` and `tests/client_cert/my-client.{crt,key}`

Install [smallstep/cli: 🧰 A zero trust swiss army knife for working with X509, OAuth, JWT, OATH OTP, etc.](https://github.com/smallstep/cli) with the steps described at [Installation](https://github.com/smallstep/cli#installation).

Then run the following command:

```
(cd tests/client_cert; ./gen_ca_and_cert.sh)
```

## Run tests

```
$ zig build test
Test [102/184] tls.socket.test "ServerOnly_tls13_p256"... SKIP
Test [103/184] tls.socket.test "Connect to localhost TLS 1.3 skip_verify"... SKIP
Test [104/184] tls.socket.test "Connect to localhost TLS 1.3 one request"... SKIP
Test [105/184] tls.socket.test "Connect to localhost TLS 1.2 skip_verify"... SKIP
Test [106/184] tls.socket.test "Connect to localhost TLS 1.2 verify"... SKIP
Test [107/184] tls.socket.test "Connect to Internet with TLS 1.3"... SKIP
Test [108/184] tls.socket.test "Connect to Internet with TLS 1.2"... SKIP
177 passed; 7 skipped; 0 failed.
```

```
$ zig version
0.10.0-dev.3007+6ba2fb3db
```
