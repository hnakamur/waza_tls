#!/bin/bash
sudo tcpdump -i any -U -w "tcpdump.bin.log" tcp port 8443 &
tcpdump_pid=$!
sleep 2
zig build test -Dtest-filter=ClientServer_tls12_p256_no_client_certificate_two_requests
sudo kill $tcpdump_pid
