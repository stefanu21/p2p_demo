HOW TO RUN
##########

Tested on Ubuntu 21.04

1) systemctl disable NetworkManager.service
2) install isc-dhcp-server
3) add config to '/etc/dhcp/dhcpd.conf'

::
        subnet 172.31.254.0 netmask 255.255.255.0 {
                range 172.31.254.1 172.31.254.10;
                option routers 172.31.254.100;
        }
4) run 'sudo ./p2pd'
5) run 'sudo ./dhcp-start.sh p2p-wlp0s20-0'

