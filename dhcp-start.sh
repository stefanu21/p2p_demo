#!/bin/bash

interface_id="miralan"
leases_file="/tmp/dhcpd-test.lease"
pid_file="/var/run/dhcpd-test.pid"
#kill $(cat $pid_file)
#kill -9 $(cat $pid_file)
#touch $leases_filei
sleep 1
dhcpd -pf $pid_file $1
