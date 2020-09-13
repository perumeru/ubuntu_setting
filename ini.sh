#!/bin/bash
# パス
PATH=/sbin:/usr/sbin:/bin:/usr/bin

iptables -F
iptables -X
iptables -Z
iptables -P INPUT   ACCEPT
iptables -P OUTPUT  ACCEPT
iptables -P FORWARD ACCEPT
iptables-save -c > /etc/iptables/rules.v4 && iptables-restore < /etc/iptables/rules.v4
service netfilter-persistent start
