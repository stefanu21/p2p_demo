#!/bin/bash

CONFIG_FILE=/etc/dhcp/dhcpd.conf
[ -e /var/lib/dhcp/dhcpd.leases ] || touch /var/lib/dhcp/dhcpd.leases
chown root:dhcpd /var/lib/dhcp /var/lib/dhcp/dhcpd.leases;
chmod 775 /var/lib/dhcp ; chmod 664 /var/lib/dhcp/dhcpd.leases;

exec dhcpd -user dhcpd -group dhcpd -f -4 -pf /run/dhcp-server/dhcpd.pid -cf $CONFIG_FILE $1

