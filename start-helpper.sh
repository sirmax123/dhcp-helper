#!/bin/bash


rm ./dhcp-helper
make

set +x

#strace \
./dhcp-helper \
    -i eth101 \
    -i dhcp \
    -s 172.31.99.1 \
    -d

exit
#

-s 172.31.99.1 \
    -b main_to_dhcp_ns \
