#!/bin/bash

echo "start dhclient $1"
dhclient -v -pf /var/run/dhclient-test.pid $1;

