#!/bin/sh
# for installing step CLI, see https://github.com/smallstep/cli#installation
step certificate create my-root-ca my-root-ca.crt my-root-ca.key --profile root-ca --no-password --insecure
step certificate create my-client my-client.crt my-client.key --profile leaf --ca my-root-ca.crt --ca-key my-root-ca.key --no-password --insecure
