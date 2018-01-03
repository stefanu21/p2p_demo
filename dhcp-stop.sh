#!/bin/bash
interface=$1
peer_ip=$2
mask=$3
echo "$0 called with: interface=$interface, ip=$peer_ip, maks=$mask"
kill $(cat /var/run/dhcpd-test.pid)
