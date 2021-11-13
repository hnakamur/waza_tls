#!/bin/bash
zig test \
 --pkg-begin http ./src/main.zig \
  --pkg-begin tigerbeetle-io ./lib/tigerbeetle-io/src/main.zig --pkg-end \
 --pkg-end \
 --pkg-begin tigerbeetle-io ./lib/tigerbeetle-io/src/main.zig --pkg-end \
 --pkg-begin datetime ./lib/zig-datetime/src/main.zig --pkg-end \
 "$@"
