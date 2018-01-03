#!/bin/bash

echo "stop dhclient"
kill $(cat /var/run/dhclient-test.pid)

