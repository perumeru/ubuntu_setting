#!/bin/bash

SSH=22
FTP=20,21
DNS=53
SMTP=25,465,587
POP3=110,995
IMAP=143,993
HTTP=80,443
IDENT=113
NTP=123
MYSQL=3306
NET_BIOS=135,137,138,139,445
DHCP=67,68

finailize()
{
/etc/init.d/iptables save &&
/etc/init.d/iptables restart &&
return 0
return 1
}

if [ "$1" == "dev" ]
then
iptables() { echo "iptables $@"; }
finailize() { echo "finailize"; }
fi

iptables -F
iptables -X
iptables -Z
iptables -P INPUT   ACCEPT
iptables -P OUTPUT  ACCEPT
iptables -P FORWARD ACCEPT

PATH=/sbin:/usr/sbin:/bin:/usr/bin

LOGIN=`cat /etc/ssh/sshd_config | grep '^#\?Port ' | tail -n 1 | sed -e 's/^[^0-9]*\([0-9]\+\).*$/\1/'`

LOCAL_COUNTRY_CODE="JP"
BLOCK_COUNTRY_CODE="CN|HK|MO|KR|KP"

FORMAT="grep ^[0-9] | cut -d' ' -f1"

PREPROCESS=
POSTPROCESS=

ROLES=(GLOBAL LOCAL CONNECTION SYSTEM NETWORK AUTH PRIVATE CUSTOMER PUBLIC TEST)
GLOBAL=(FW_BROADCAST FW_MULTICAST BLOCK_COUNTRY)
LOCAL=(IPS ACCEPT)
CONNECTION=(FIREWALL IPS ACCEPT)
SYSTEM=(whitelist/system FIREWALL IPF IPS ACCEPT)
NETWORK=(whitelist/network FIREWALL IPF IPS ACCEPT)
AUTH=(whitelist/auth LOCAL_COUNTRY FIREWALL IPF IPS ACCEPT)
PRIVATE=("whitelist/{auth,user}|DROP" LOCAL_COUNTRY FIREWALL IPF IPS ACCEPT)
CUSTOMER=(LOCAL_COUNTRY FIREWALL IPS ACCEPT)
PUBLIC=(FIREWALL IPS ACCEPT)
TEST=("whitelist/{auth,user}|TRACK_PROWLER|DROP" LOCAL_COUNTRY FIERWALL IPF "IPS|DROP")

MAP=("${MAP[@]}" "INPUT -i lo -j LOCAL")
MAP=("${MAP[@]}" "OUTPUT -o lo -j LOCAL")
MAP=("${MAP[@]}" "FORWARD -i lo -j LOCAL")
MAP=("${MAP[@]}" "FORWARD -o lo -j LOCAL")

MAP=("${MAP[@]}" "INPUT -m state --state ESTABLISHED,RELATED -j CONNECTION")
MAP=("${MAP[@]}" "OUTPUT -m state --state NEW,ESTABLISHED -j CONNECTION")
MAP=("${MAP[@]}" "FORWARD -m state --state ESTABLISHED,RELATED -j CONNECTION")

MAP=("${MAP[@]}" "INPUT -j GLOBAL")
MAP=("${MAP[@]}" "OUTPUT -j GLOBAL")
MAP=("${MAP[@]}" "FORWARD -j GLOBAL")

MAP=("${MAP[@]}" "INPUT -p icmp --icmp-type destination-unreachable -j SYSTEM")
MAP=("${MAP[@]}" "INPUT -p icmp --icmp-type source-quench -j SYSTEM")
MAP=("${MAP[@]}" "INPUT -p icmp --icmp-type redirect -j SYSTEM")
MAP=("${MAP[@]}" "INPUT -p icmp --icmp-type time-exceeded -j SYSTEM")
MAP=("${MAP[@]}" "INPUT -p icmp --icmp-type parameter-problem -j SYSTEM")

NAMESERVERS=$(echo $(grep '^nameserver' /etc/resolv.conf | cut -d' ' -f2) | tr ' ' ,)
MAP=("${MAP[@]}" "INPUT -s $NAMESERVERS -p udp --dport 53 -j SYSTEM")
MAP=("${MAP[@]}" "OUTPUT -d $NAMESERVERS -p udp --sport 53 -j SYSTEM")
MAP=("${MAP[@]}" "FORWARD -s $NAMESERVERS -p udp --dport 53 -j SYSTEM")
MAP=("${MAP[@]}" "FORWARD -d $NAMESERVERS -p udp --sport 53 -j SYSTEM")

NTPSERVERS=$(echo $(grep '^server' /etc/{ntp,chrony}.conf 2>/dev/null | cut -d' ' -f2) | tr ' ' ,)
MAP=("${MAP[@]}" "INPUT -s $NTPSERVERS -p udp --dport 123 -j SYSTEM")
MAP=("${MAP[@]}" "OUTPUT -d $NTPSERVERS -p udp --sport 123 -j SYSTEM")
MAP=("${MAP[@]}" "FORWARD -s $NTPSERVERS -p udp --dport 123 -j SYSTEM")
MAP=("${MAP[@]}" "FORWARD -d $NTPSERVERS -p udp --sport 123 -j SYSTEM")

MAP=("${MAP[@]}" "INPUT -p tcp -m multiport --dports $LOGIN -j AUTH")
MAP=("${MAP[@]}" "INPUT -p tcp --dport 80 -j PUBLIC")
MAP=("${MAP[@]}" "INPUT -p tcp --dport 443 -j CUSTOMER")
MAP=("${MAP[@]}" "INPUT -p tcp --dport 113 -j REJECT --reject-with tcp-reset")
MAP=("${MAP[@]}" "INPUT -p tcp --dport 25 -j PRIVATE")
MAP=("${MAP[@]}" "INPUT -p tcp --dport 465 -j AUTH")
MAP=("${MAP[@]}" "INPUT -p tcp --dport 110 -j PRIVATE")
MAP=("${MAP[@]}" "INPUT -p tcp --dport 995 -j AUTH")
MAP=("${MAP[@]}" "INPUT -j TRAP_PORTSCAN")
MAP=("${MAP[@]}" "FORWARD -j TRAP_PORTSCAN")

INTERVAL=7
IDSIPS=
SECURE=
LOG_LIMIT=60/m
LOG_LIMIT_BURST=1000
IPTABLES=iptables
LIST_DIR=/etc/iptables/
CACHE_DIR=/var/cache/iptables/

echo "iptables firewall"

RESULT=0
SECURE=${SECURE:-false}

if [ ! $IDSIPS ]; then
if [ `ps alx | grep -v grep | grep /snort | head -n 1 | cut -c1` ]; then
IDSIPS=Snort
else
IDSIPS=false
fi
fi

WGET="wget -N --retr-symlinks -P ${CACHE_DIR}"

[ ! -e $CACHE_DIR ] && mkdir -p $CACHE_DIR
if [[ $(find ${CACHE_DIR} -name delegated-*-extended-latest -ctime -$INTERVAL 2>&1) ]]; then
UPDATE=0
echo "UPDATE		NO"
else
UPDATE=1
echo "UPDATE		YES"
$WGET ftp://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest
$WGET ftp://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest
$WGET ftp://ftp.apnic.net/pub/stats/apnic/delegated-apnic-extended-latest
$WGET ftp://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-extended-latest
$WGET ftp://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-extended-latest
fi
if [ $UPDATE -ne 0 ] && [[ $(find ${CACHE_DIR} -name delegated-*-extended-latest -mtime -$INTERVAL 2>&1) ]]; then
RESET=1
echo "DELETE	All Chains"
$IPTABLES -F
$IPTABLES -X
else
RESET=0
$IPTABLES -F INPUT
$IPTABLES -F OUTPUT
$IPTABLES -F FORWARD
for CHAIN in `$IPTABLES -S | grep ^-N | cut -d" " -f2`; do
if [ LOCAL_COUNTRY = $CHAIN ] || [ BLOCK_COUNTRY = $CHAIN ]; then continue;fi
$IPTABLES -F $CHAIN
done

for CHAIN in `$IPTABLES -S | grep ^-N | cut -d" " -f2`; do
if [ LOCAL_COUNTRY = $CHAIN ] || [ BLOCK_COUNTRY = $CHAIN ]; then continue;fi
$IPTABLES -X $CHAIN
done
fi

$IPTABLES -Z
$IPTABLES -P INPUT DROP
$IPTABLES -P OUTPUT DROP
$IPTABLES -P FORWARD DROP

$IPTABLES -N LOCAL_COUNTRY 2>/dev/null
$IPTABLES -N BLOCK_COUNTRY 2>/dev/null

$IPTABLES -N FIREWALL
$IPTABLES -N FW_BASIC
$IPTABLES -N IPS
$IPTABLES -N IDS

echo "PREPROCESS	$PREPROCESS"
`$PREPROCESS`

iptables -P INPUT   DROP
iptables -P OUTPUT  ACCEPT
iptables -P FORWARD DROP

iptables -A INPUT -i lo -j ACCEPT

if [ "$LOCAL_NET" ]
then
iptables -A INPUT -p tcp -s $LOCAL_NET -j ACCEPT # LOCAL_NET -> SELF
fi

if [ "${ALLOW_HOSTS}" ]
then
for allow_host in ${ALLOW_HOSTS[@]}
do
iptables -A INPUT -p tcp -s $allow_host -j ACCEPT # allow_host -> SELF
done
fi

if [ "${DENY_HOSTS}" ]
then
for deny_host in ${DENY_HOSTS[@]}
do
iptables -A INPUT -s $deny_host -m limit --limit 1/s -j LOG --log-prefix "deny_host: "
iptables -A INPUT -s $deny_host -j DROP
done
fi

iptables -A INPUT  -p tcp -m state --state ESTABLISHED,RELATED -j ACCEPT

iptables -N STEALTH_SCAN
iptables -A STEALTH_SCAN -j LOG --log-prefix "stealth_scan_attack: "
iptables -A STEALTH_SCAN -j DROP

iptables -A INPUT -p tcp --tcp-flags SYN,ACK SYN,ACK -m state --state NEW -j STEALTH_SCAN
iptables -A INPUT -p tcp --tcp-flags ALL NONE -j STEALTH_SCAN

iptables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN         -j STEALTH_SCAN
iptables -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST         -j STEALTH_SCAN
iptables -A INPUT -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j STEALTH_SCAN

iptables -A INPUT -p tcp --tcp-flags FIN,RST FIN,RST -j STEALTH_SCAN
iptables -A INPUT -p tcp --tcp-flags ACK,FIN FIN     -j STEALTH_SCAN
iptables -A INPUT -p tcp --tcp-flags ACK,PSH PSH     -j STEALTH_SCAN
iptables -A INPUT -p tcp --tcp-flags ACK,URG URG     -j STEALTH_SCAN

iptables -A INPUT -f -j LOG --log-prefix 'fragment_packet:'
iptables -A INPUT -f -j DROP

iptables -N PING_OF_DEATH
iptables -A PING_OF_DEATH -p icmp --icmp-type echo-request \
-m hashlimit \
--hashlimit 1/s \
--hashlimit-burst 10 \
--hashlimit-htable-expire 300000 \
--hashlimit-mode srcip \
--hashlimit-name t_PING_OF_DEATH \
-j RETURN

iptables -A PING_OF_DEATH -j LOG --log-prefix "ping_of_death_attack: "
iptables -A PING_OF_DEATH -j DROP

iptables -A INPUT -p icmp --icmp-type echo-request -j PING_OF_DEATH

iptables -N SYN_FLOOD
iptables -A SYN_FLOOD -p tcp --syn \
-m hashlimit \
--hashlimit 200/s \
--hashlimit-burst 3 \
--hashlimit-htable-expire 300000 \
--hashlimit-mode srcip \
--hashlimit-name t_SYN_FLOOD \
-j RETURN

iptables -A SYN_FLOOD -j LOG --log-prefix "syn_flood_attack: "
iptables -A SYN_FLOOD -j DROP

iptables -A INPUT -p tcp --syn -j SYN_FLOOD

iptables -N HTTP_DOS
iptables -A HTTP_DOS -p tcp -m multiport --dports $HTTP \
-m hashlimit \
--hashlimit 1/s \
--hashlimit-burst 100 \
--hashlimit-htable-expire 300000 \
--hashlimit-mode srcip \
--hashlimit-name t_HTTP_DOS \
-j RETURN

iptables -A HTTP_DOS -j LOG --log-prefix "http_dos_attack: "
iptables -A HTTP_DOS -j DROP

iptables -A INPUT -p tcp -m multiport --dports $HTTP -j HTTP_DOS

iptables -A INPUT -p tcp -m multiport --dports $IDENT -j REJECT --reject-with tcp-reset

# SSHサーバがパスワード認証ONの場合、以下をアンコメントアウトする
#iptables -A INPUT -p tcp --syn -m multiport --dports $SSH -m recent --name ssh_attack --set
#iptables -A INPUT -p tcp --syn -m multiport --dports $SSH -m recent --name ssh_attack --rcheck --seconds 60 --hitcount 5 -j LOG --log-prefix "ssh_brute_force: "
#iptables -A INPUT -p tcp --syn -m multiport --dports $SSH -m recent --name ssh_attack --rcheck --seconds 60 --hitcount 5 -j REJECT --reject-with tcp-reset

iptables -A INPUT -d 192.168.1.255   -j LOG --log-prefix "drop_broadcast: "
iptables -A INPUT -d 192.168.1.255   -j DROP
iptables -A INPUT -d 255.255.255.255 -j LOG --log-prefix "drop_broadcast: "
iptables -A INPUT -d 255.255.255.255 -j DROP
iptables -A INPUT -d 224.0.0.1       -j LOG --log-prefix "drop_broadcast: "
iptables -A INPUT -d 224.0.0.1       -j DROP

iptables -A INPUT -p icmp -j ACCEPT
iptables -A INPUT -p tcp -m multiport --dports $HTTP -j ACCEPT
iptables -A INPUT -p tcp -m multiport --dports $SSH -j ACCEPT
iptables -A INPUT -p tcp -m multiport --sports $SMTP -j ACCEPT
iptables -A INPUT -p tcp -m multiport --sports $POP3 -j ACCEPT

if [ "$LIMITED_LOCAL_NET" ]
then
iptables -A INPUT -p tcp -s $LIMITED_LOCAL_NET -m multiport --dports $SSH -j ACCEPT
fi

if [ "$ZABBIX_IP" ]
then
iptables -A INPUT -p tcp -s $ZABBIX_IP --dport 10050 -j ACCEPT
fi

iptables -A INPUT  -j LOG --log-prefix "drop: "
iptables -A INPUT  -j DROP

echo "POSTPROCESS	$POSTPROCESS"
`$POSTPROCESS`
CIDR_COUNT_LIST=()
declare -A CIDR_TABLE
for ((CIDR=32;0<CIDR;CIDR--))
do
CIDR_COUNT=$((2**(32-$CIDR)))
CIDR_COUNT_LIST=($CIDR_COUNT "${CIDR_COUNT_LIST[@]}")
CIDR_TABLE[$CIDR_COUNT]=$CIDR
done
$IPTABLES -F IPS
$IPTABLES -F IDS
if [ $IDSIPS = Snort ]; then

$IPTABLES -A IPS -p icmp -j NFQUEUE --queue-num 2
$IPTABLES -A IPS -p udp -j NFQUEUE --queue-num 2
$IPTABLES -A IPS -p tcp -j NFQUEUE --queue-num 2

echo "IDS/IPS		Snort"

else
echo "IDS/IPS		DISABLE"
fi

sed -i '/net.ipv4.conf.*.rp_filter/d' /etc/sysctl.conf
for dev in `ls /proc/sys/net/ipv4/conf/`
do
sysctl -w net.ipv4.conf.$dev.rp_filter=1 > /dev/null
echo "net.ipv4.conf.$dev.rp_filter=1" >> /etc/sysctl.conf
done

sed -i '/net.ipv4.conf.*.accept_redirects/d' /etc/sysctl.conf
for dev in `ls /proc/sys/net/ipv4/conf/`
do
sysctl -w net.ipv4.conf.$dev.accept_redirects=0 > /dev/null
echo "net.ipv4.conf.$dev.accept_redirects=0" >> /etc/sysctl.conf
done

sed -i '/net.ipv4.conf.*.accept_source_route/d' /etc/sysctl.conf
for dev in `ls /proc/sys/net/ipv4/conf/`
do
sysctl -w net.ipv4.conf.$dev.accept_source_route=0 > /dev/null
echo "net.ipv4.conf.$dev.accept_source_route=0" >> /etc/sysctl.conf
done

sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1 > /dev/null
sed -i '/net.ipv4.icmp_echo_ignore_broadcasts/d' /etc/sysctl.conf
echo "net.ipv4.icmp_echo_ignore_broadcasts=1" >> /etc/sysctl.conf

sysctl -w net.ipv4.tcp_syncookies=1 > /dev/null
sed -i '/net.ipv4.tcp_syncookies/d' /etc/sysctl.conf
echo "net.ipv4.tcp_syncookies=1" >> /etc/sysctl.conf

sysctl -w net.ipv4.tcp_timestamps=1 > /dev/null
sed -i '/net.ipv4.tcp_timestamps/d' /etc/sysctl.conf
echo "net.ipv4.tcp_timestamps=1" >> /etc/sysctl.conf

$IPTABLES -N IPF 2>/dev/null
$IPTABLES -N ANTI_INTRUDER
$IPTABLES -N ANTI_INTRUDER_
$IPTABLES -N ANTI_INTRUDER__
$IPTABLES -A IPF -p tcp ! --dport 0:1023 -m state --state NEW,INVALID -j ANTI_INTRUDER
$IPTABLES -A IPF -p udp -m state --state NEW,INVALID -j ANTI_INTRUDER
$IPTABLES -A IPF -p icmp -j ANTI_INTRUDER
$IPTABLES -A ANTI_INTRUDER -i e+ -j ANTI_INTRUDER_
$IPTABLES -A ANTI_INTRUDER -i p+ -j ANTI_INTRUDER_
$IPTABLES -A ANTI_INTRUDER -i w+ -j ANTI_INTRUDER_

$IPTABLES -A ANTI_INTRUDER_ -m recent --name attacker-rapid --update --rttl -j ANTI_INTRUDER__
$IPTABLES -A ANTI_INTRUDER_ -m recent --name attacker-fast --update --rttl -j ANTI_INTRUDER__
$IPTABLES -A ANTI_INTRUDER_ -m recent --name attacker-medium --update --rttl -j ANTI_INTRUDER__
$IPTABLES -A ANTI_INTRUDER_ -m recent --name attacker-slow --update --rttl -j ANTI_INTRUDER__
$IPTABLES -A ANTI_INTRUDER_ -m recent --name prowler-rapid --update --rttl -j ANTI_INTRUDER__
$IPTABLES -A ANTI_INTRUDER_ -m recent --name prowler-fast --update --rttl -j ANTI_INTRUDER__
$IPTABLES -A ANTI_INTRUDER_ -m recent --name prowler-medium --update --rttl -j ANTI_INTRUDER__
$IPTABLES -A ANTI_INTRUDER_ -m recent --name prowler-slow --update --rttl -j ANTI_INTRUDER__
$IPTABLES -A ANTI_INTRUDER__ -m limit --limit $LOG_LIMIT --limit-burst $LOG_LIMIT_BURST -j LOG --log-level debug --log-prefix '[IPTABLES INTRUDER] : '
$IPTABLES -A ANTI_INTRUDER__ -j DROP
#$IPTABLES -A FIREWALL -j IPF && echo "FIREWALL	ANTI_INTRUDER"

$IPTABLES -N TRACK_PROWLER 2>/dev/null
$IPTABLES -N ANTI_PROWLER
$IPTABLES -N ANTI_PROWLER_
$IPTABLES -A TRACK_PROWLER -j ANTI_PROWLER
$IPTABLES -A ANTI_PROWLER -i e+ -j ANTI_PROWLER_
$IPTABLES -A ANTI_PROWLER -i p+ -j ANTI_PROWLER_
$IPTABLES -A ANTI_PROWLER -i w+ -j ANTI_PROWLER_
$IPTABLES -A ANTI_PROWLER_ -m recent --name prowler-rapid --update --rttl --seconds 10 -j RETURN
$IPTABLES -A ANTI_PROWLER_ -m recent --name prowler-rapid --set
$IPTABLES -A ANTI_PROWLER_ \
-m hashlimit \
--hashlimit-name prowler-rapid \
--hashlimit-above 6/m \
--hashlimit-mode srcip \
--hashlimit-htable-expire 10000 \
-j RETURN
$IPTABLES -A ANTI_PROWLER_ -m recent --name prowler-fast --update --rttl --seconds 60 -j RETURN
$IPTABLES -A ANTI_PROWLER_ -m recent --name prowler-fast --set
$IPTABLES -A ANTI_PROWLER_ \
-m hashlimit \
--hashlimit-name prowler-fast \
--hashlimit-above 1/m \
--hashlimit-mode srcip \
--hashlimit-htable-expire 60000 \
-j RETURN
$IPTABLES -A ANTI_PROWLER_ -m recent --name prowler-medium --update --rttl --seconds 3600 -j RETURN
$IPTABLES -A ANTI_PROWLER_ -m recent --name prowler-medium --set
#$IPTABLES -A ANTI_PROWLER_ -m recent --name prowler-slow --update --rttl --seconds 86400 -j RETURN
$IPTABLES -A ANTI_PROWLER_ -m recent --name prowler-slow --set

$IPTABLES -N TRACK_ATTACKER 2>/dev/null
$IPTABLES -N ANTI_ATTACKER
$IPTABLES -N ANTI_ATTACKER_
$IPTABLES -A TRACK_ATTACKER -j ANTI_ATTACKER
$IPTABLES -A ANTI_ATTACKER -i e+ -j ANTI_ATTACKER_
$IPTABLES -A ANTI_ATTACKER -i p+ -j ANTI_ATTACKER_
$IPTABLES -A ANTI_ATTACKER -i w+ -j ANTI_ATTACKER_
$IPTABLES -A ANTI_ATTACKER_ -m recent --name attacker-rapid --update --rttl --seconds 10 -j RETURN
$IPTABLES -A ANTI_ATTACKER_ -m recent --name attacker-rapid --set
$IPTABLES -A ANTI_ATTACKER_ \
-m hashlimit \
--hashlimit-name attacker-rapid \
--hashlimit-above 6/m \
--hashlimit-mode srcip \
--hashlimit-htable-expire 10000 \
-j RETURN
$IPTABLES -A ANTI_ATTACKER_ -m recent --name attacker-fast --update --rttl --seconds 60 -j RETURN
$IPTABLES -A ANTI_ATTACKER_ -m recent --name attacker-fast --set
$IPTABLES -A ANTI_ATTACKER_ \
-m hashlimit \
--hashlimit-name attacker-fast \
--hashlimit-above 1/m \
--hashlimit-mode srcip \
--hashlimit-htable-expire 60000 \
-j RETURN
$IPTABLES -A ANTI_ATTACKER_ -m recent --name attacker-medium --update --rttl --seconds 3600 -j RETURN
$IPTABLES -A ANTI_ATTACKER_ -m recent --name attacker-medium --set
#$IPTABLES -A ANTI_ATTACKER_ -m recent --name attacker-slow --update --rttl --seconds 86400 -j RETURN
$IPTABLES -A ANTI_ATTACKER_ -m recent --name attacker-slow --set

$IPTABLES -N FW_BROADCAST 2>/dev/null
$IPTABLES -N DENY_BROADCAST
$IPTABLES -A FW_BROADCAST -i e+ -j DENY_BROADCAST
$IPTABLES -A FW_BROADCAST -i p+ -j DENY_BROADCAST
$IPTABLES -A FW_BROADCAST -i w+ -j DENY_BROADCAST
$IPTABLES -A DENY_BROADCAST -m pkttype --pkt-type broadcast -j DROP

$IPTABLES -N FW_MULTICAST 2>/dev/null
$IPTABLES -N DENY_MULTICAST
$IPTABLES -A FW_MULTICAST -i e+ -j DENY_MULTICAST
$IPTABLES -A FW_MULTICAST -i p+ -j DENY_MULTICAST
$IPTABLES -A FW_MULTICAST -i w+ -j DENY_MULTICAST
$IPTABLES -A DENY_MULTICAST -m pkttype --pkt-type multicast -j DROP

$IPTABLES -N FW_FRAGMENT 2>/dev/null
$IPTABLES -N DENY_FRAGMENT
$IPTABLES -N DENY_FRAGMENT_
$IPTABLES -A FW_FRAGMENT -i e+ -j DENY_FRAGMENT
$IPTABLES -A FW_FRAGMENT -i p+ -j DENY_FRAGMENT
$IPTABLES -A FW_FRAGMENT -i w+ -j DENY_FRAGMENT
$IPTABLES -A DENY_FRAGMENT -f -j DENY_FRAGMENT_
$IPTABLES -A DENY_FRAGMENT_ -m limit --limit $LOG_LIMIT --limit-burst $LOG_LIMIT_BURST -j LOG --log-level debug --log-prefix '[IPTABLES FRAGMENT] : '
$IPTABLES -A DENY_FRAGMENT_ -j TRACK_ATTACKER
$IPTABLES -A DENY_FRAGMENT_ -j DROP
$IPTABLES -A FIREWALL -j FW_FRAGMENT && echo "FIREWALL	DENY_FRAGMENT"

$IPTABLES -N FW_INVALID 2>/dev/null
$IPTABLES -N DENY_INVALID
$IPTABLES -N DENY_INVALID_
$IPTABLES -A FW_INVALID -i e+ -j DENY_INVALID
$IPTABLES -A FW_INVALID -i p+ -j DENY_INVALID
$IPTABLES -A FW_INVALID -i w+ -j DENY_INVALID
$IPTABLES -A DENY_INVALID -m state --state INVALID -j DENY_INVALID_
$IPTABLES -A DENY_INVALID_ -m limit --limit $LOG_LIMIT --limit-burst $LOG_LIMIT_BURST -j LOG --log-level debug --log-prefix '[IPTABLES INVALID] : '
$IPTABLES -A DENY_INVALID_ -j DROP
$IPTABLES -A FIREWALL -j FW_INVALID && echo "FIREWALL	DENY_INVALID"

$IPTABLES -N FW_NETBIOS 2>/dev/null
$IPTABLES -N DENY_NETBIOS
$IPTABLES -N DENY_NETBIOS_
$IPTABLES -A FW_NETBIOS -i e+ -j DENY_NETBIOS
$IPTABLES -A FW_NETBIOS -i p+ -j DENY_NETBIOS
$IPTABLES -A FW_NETBIOS -i w+ -j DENY_NETBIOS
$IPTABLES -A DENY_NETBIOS -p tcp -m multiport --dports 135,137,138,139,445 -j DENY_NETBIOS_
$IPTABLES -A DENY_NETBIOS -p udp -m multiport --dports 135,137,138,139,445 -j DENY_NETBIOS_
$IPTABLES -A DENY_NETBIOS_ -m limit --limit $LOG_LIMIT --limit-burst $LOG_LIMIT_BURST -j LOG --log-level debug --log-prefix '[IPTABLES NETBIOS] : '
$IPTABLES -A DENY_NETBIOS_ -j TRACK_ATTACKER
$IPTABLES -A DENY_NETBIOS_ -j DROP
$IPTABLES -A FIREWALL -j FW_NETBIOS && echo "FIREWALL	DENY_NETBIOS"
$IPTABLES -A FW_BASIC -j FW_NETBIOS

$IPTABLES -N FW_STEALTHSCAN 2>/dev/null
$IPTABLES -N ANTI_STEALTHSCAN
$IPTABLES -N ANTI_STEALTHSCAN_
$IPTABLES -N ANTI_STEALTHSCAN__
$IPTABLES -A FW_STEALTHSCAN -j ANTI_STEALTHSCAN
$IPTABLES -A ANTI_STEALTHSCAN -i e+ -p tcp -m state --state NEW -j ANTI_STEALTHSCAN_
$IPTABLES -A ANTI_STEALTHSCAN -i p+ -p tcp -m state --state NEW -j ANTI_STEALTHSCAN_
$IPTABLES -A ANTI_STEALTHSCAN -i w+ -p tcp -m state --state NEW -j ANTI_STEALTHSCAN_
$IPTABLES -A ANTI_STEALTHSCAN_ -p tcp --dport 0:1023 -j RETURN

$IPTABLES -A ANTI_STEALTHSCAN_ -p tcp -m state --state NEW --tcp-flags SYN,ACK SYN,ACK -j ANTI_STEALTHSCAN__

$IPTABLES -A ANTI_STEALTHSCAN_ -p tcp --tcp-flags ACK,FIN FIN -j ANTI_STEALTHSCAN__
$IPTABLES -A ANTI_STEALTHSCAN_ -p tcp --tcp-flags ACK,PSH PSH -j ANTI_STEALTHSCAN__
$IPTABLES -A ANTI_STEALTHSCAN_ -p tcp --tcp-flags ACK,URG URG -j ANTI_STEALTHSCAN__

$IPTABLES -A ANTI_STEALTHSCAN_ -p tcp --tcp-flags SYN,FIN SYN,FIN -j ANTI_STEALTHSCAN__

$IPTABLES -A ANTI_STEALTHSCAN_ -p tcp --tcp-flags SYN,RST SYN,RST -j ANTI_STEALTHSCAN__

$IPTABLES -A ANTI_STEALTHSCAN_ -p tcp --tcp-flags FIN,RST FIN,RST -j ANTI_STEALTHSCAN__

$IPTABLES -A ANTI_STEALTHSCAN_ -p tcp --tcp-flags ALL ALL -j ANTI_STEALTHSCAN__

$IPTABLES -A ANTI_STEALTHSCAN_ -p tcp --tcp-flags ALL NONE -j ANTI_STEALTHSCAN__

$IPTABLES -A ANTI_STEALTHSCAN_ -p tcp --tcp-flags ALL FIN -j ANTI_STEALTHSCAN__

$IPTABLES -A ANTI_STEALTHSCAN_ -p tcp --tcp-flags ALL FIN,PSH,URG -j ANTI_STEALTHSCAN__

$IPTABLES -A ANTI_STEALTHSCAN_ -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j ANTI_STEALTHSCAN__
$IPTABLES -A ANTI_STEALTHSCAN_ -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG,PSH -j ANTI_STEALTHSCAN__
$IPTABLES -A ANTI_STEALTHSCAN__ -m limit --limit $LOG_LIMIT --limit-burst $LOG_LIMIT_BURST -j LOG --log-level debug --log-prefix '[IPTABLES STEALTHSCAN] : '
$IPTABLES -A ANTI_STEALTHSCAN__ -j TRACK_ATTACKER
$IPTABLES -A ANTI_STEALTHSCAN__ -j DROP

$IPTABLES -N FW_SPOOFING 2>/dev/null
$IPTABLES -N ANTI_SPOOFING
$IPTABLES -N ANTI_SPOOFING_
$IPTABLES -N ANTI_SPOOFING__
$IPTABLES -A FW_SPOOFING -j ANTI_SPOOFING
$IPTABLES -A ANTI_SPOOFING -i e+ -j ANTI_SPOOFING_
$IPTABLES -A ANTI_SPOOFING -i p+ -j ANTI_SPOOFING_
$IPTABLES -A ANTI_SPOOFING -i w+ -j ANTI_SPOOFING_
$IPTABLES -A ANTI_SPOOFING_ -s 127.0.0.0/8    -j ANTI_SPOOFING__
$IPTABLES -A ANTI_SPOOFING_ -s 10.0.0.0/8     -j ANTI_SPOOFING__
$IPTABLES -A ANTI_SPOOFING_ -s 172.16.0.0/12  -j ANTI_SPOOFING__
$IPTABLES -A ANTI_SPOOFING_ -s 192.168.0.0/16 -j ANTI_SPOOFING__
$IPTABLES -A ANTI_SPOOFING__ -m limit --limit $LOG_LIMIT --limit-burst $LOG_LIMIT_BURST -j LOG --log-level debug --log-prefix '[IPTABLES SPOOFING] : '
$IPTABLES -A ANTI_SPOOFING__ -j TRACK_ATTACKER
$IPTABLES -A ANTI_SPOOFING__ -j DROP
$IPTABLES -A FIREWALL -j FW_SPOOFING && echo "FIREWALL	ANTI_SPOOFING"
$IPTABLES -A FW_BASIC -j FW_SPOOFING

$IPTABLES -N FW_BRUTEFORCE 2>/dev/null
$IPTABLES -N ANTI_BRUTEFORCE
$IPTABLES -N ANTI_BRUTEFORCE_
$IPTABLES -A FW_BRUTEFORCE -p tcp -m multiport --dports $LOGIN -j ANTI_BRUTEFORCE
$IPTABLES -A ANTI_BRUTEFORCE -i e+ -p tcp -m state --state NEW -j ANTI_BRUTEFORCE_
$IPTABLES -A ANTI_BRUTEFORCE -i p+ -p tcp -m state --state NEW -j ANTI_BRUTEFORCE_
$IPTABLES -A ANTI_BRUTEFORCE -i w+ -p tcp -m state --state NEW -j ANTI_BRUTEFORCE_
$IPTABLES -A ANTI_BRUTEFORCE_ \
-m hashlimit \
--hashlimit-name bruteforce \
--hashlimit 1/m \
--hashlimit-burst 7 \
--hashlimit-mode srcip \
--hashlimit-htable-expire 180000 \
-j RETURN
$IPTABLES -A ANTI_BRUTEFORCE_ -m limit --limit $LOG_LIMIT --limit-burst $LOG_LIMIT_BURST -j LOG --log-level debug --log-prefix '[IPTABLES BRUTEFORCE] : '
$IPTABLES -A ANTI_BRUTEFORCE_ -j TRACK_ATTACKER
$IPTABLES -A ANTI_BRUTEFORCE_ -j DROP
$IPTABLES -A FIREWALL -j FW_BRUTEFORCE && echo "FIREWALL	ANTI_BRUTEFORCE"
$IPTABLES -A FW_BASIC -j FW_BRUTEFORCE

$IPTABLES -N FW_PINGDEATH 2>/dev/null
$IPTABLES -N ANTI_PINGDEATH
$IPTABLES -N ANTI_PINGDEATH_
$IPTABLES -A FW_PINGDEATH -i e+ -p icmp --icmp-type echo-request -j ANTI_PINGDEATH
$IPTABLES -A FW_PINGDEATH -i p+ -p icmp --icmp-type echo-request -j ANTI_PINGDEATH
$IPTABLES -A FW_PINGDEATH -i w+ -p icmp --icmp-type echo-request -j ANTI_PINGDEATH
$IPTABLES -A ANTI_PINGDEATH -j ANTI_PINGDEATH_
$IPTABLES -A ANTI_PINGDEATH_ \
-m hashlimit \
--hashlimit-name ping \
--hashlimit 1/s \
--hashlimit-burst 4 \
--hashlimit-mode srcip \
--hashlimit-htable-expire 1000 \
-j RETURN
$IPTABLES -A ANTI_PINGDEATH_ -m limit --limit $LOG_LIMIT --limit-burst $LOG_LIMIT_BURST -j LOG --log-level debug --log-prefix '[IPTABLES PINGDEATH] : '
$IPTABLES -A ANTI_PINGDEATH_ -j TRACK_ATTACKER
$IPTABLES -A ANTI_PINGDEATH_ -j DROP
$IPTABLES -A FIREWALL -j FW_PINGDEATH && echo "FIREWALL	ANTI_PINGDEATH"

$IPTABLES -N FW_SYNFLOOD 2>/dev/null
$IPTABLES -N ANTI_SYNFLOOD
$IPTABLES -N ANTI_SYNFLOOD_
$IPTABLES -A FW_SYNFLOOD -p tcp --dport 80 -j ANTI_SYNFLOOD
$IPTABLES -A ANTI_SYNFLOOD -i e+ -p tcp -m state --state NEW -j ANTI_SYNFLOOD_
$IPTABLES -A ANTI_SYNFLOOD -i p+ -p tcp -m state --state NEW -j ANTI_SYNFLOOD_
$IPTABLES -A ANTI_SYNFLOOD -i w+ -p tcp -m state --state NEW -j ANTI_SYNFLOOD_
$IPTABLES -A ANTI_SYNFLOOD_ \
-m hashlimit \
--hashlimit-name http \
--hashlimit 10/m \
--hashlimit-burst 60 \
--hashlimit-mode srcip \
--hashlimit-htable-expire 60000 \
-j RETURN
$IPTABLES -A ANTI_SYNFLOOD_ -m limit --limit $LOG_LIMIT --limit-burst $LOG_LIMIT_BURST -j LOG --log-level debug --log-prefix '[IPTABLES SYNFLOOD] : '
$IPTABLES -A ANTI_SYNFLOOD_ -j DROP
$IPTABLES -A FIREWALL -j FW_SYNFLOOD && echo "FIREWALL	ANTI_SYNFLOOD"

$IPTABLES -N FW_SYNFLOOD_SSL 2>/dev/null
$IPTABLES -N ANTI_SYNFLOOD_SSL
$IPTABLES -N ANTI_SYNFLOOD_SSL_
$IPTABLES -A FW_SYNFLOOD_SSL -p tcp --dport 443 -j ANTI_SYNFLOOD_SSL
$IPTABLES -A ANTI_SYNFLOOD_SSL -i e+ -p tcp -m state --state NEW -j ANTI_SYNFLOOD_SSL_
$IPTABLES -A ANTI_SYNFLOOD_SSL -i p+ -p tcp -m state --state NEW -j ANTI_SYNFLOOD_SSL_
$IPTABLES -A ANTI_SYNFLOOD_SSL -i w+ -p tcp -m state --state NEW -j ANTI_SYNFLOOD_SSL_
$IPTABLES -A ANTI_SYNFLOOD_SSL_ \
-m hashlimit \
--hashlimit-name https \
--hashlimit 30/m \
--hashlimit-burst 60 \
--hashlimit-mode srcip \
--hashlimit-htable-expire 60000 \
-j RETURN
$IPTABLES -A ANTI_SYNFLOOD_SSL_ -m limit --limit $LOG_LIMIT --limit-burst $LOG_LIMIT_BURST -j LOG --log-level debug --log-prefix '[IPTABLES SYNFLOOD(SSL)] : '
$IPTABLES -A ANTI_SYNFLOOD_SSL_ -j DROP
$IPTABLES -A FIREWALL -j FW_SYNFLOOD_SSL && echo "FIREWALL	ANTI_SYNFLOOD_SSL"

$IPTABLES -N FW_UDPFLOOD 2>/dev/null
$IPTABLES -N ANTI_UDPFLOOD
$IPTABLES -N ANTI_UDPFLOOD_
$IPTABLES -A FW_UDPFLOOD -j ANTI_UDPFLOOD
$IPTABLES -A ANTI_UDPFLOOD -i e+ -p udp -m state --state NEW -j ANTI_UDPFLOOD_
$IPTABLES -A ANTI_UDPFLOOD -i p+ -p udp -m state --state NEW -j ANTI_UDPFLOOD_
$IPTABLES -A ANTI_UDPFLOOD -i w+ -p udp -m state --state NEW -j ANTI_UDPFLOOD_
$IPTABLES -A ANTI_UDPFLOOD_ \
-m hashlimit \
--hashlimit-name udp \
--hashlimit 30/m \
--hashlimit-burst 60 \
--hashlimit-mode srcip \
--hashlimit-htable-expire 60000 \
-j RETURN
$IPTABLES -A ANTI_UDPFLOOD_ -m limit --limit $LOG_LIMIT --limit-burst $LOG_LIMIT_BURST -j LOG --log-level debug --log-prefix '[IPTABLES UDPFLOOD] : '
$IPTABLES -A ANTI_UDPFLOOD_ -j DROP
$IPTABLES -A FIREWALL -j FW_UDPFLOOD && echo "FIREWALL	ANTI_UDPFLOOD"

$IPTABLES -N FW_ICMPFLOOD 2>/dev/null
$IPTABLES -N ANTI_ICMPFLOOD
$IPTABLES -N ANTI_ICMPFLOOD_
$IPTABLES -A FW_ICMPFLOOD -j ANTI_ICMPFLOOD
$IPTABLES -A ANTI_ICMPFLOOD -i e+ -p icmp -j ANTI_ICMPFLOOD_
$IPTABLES -A ANTI_ICMPFLOOD -i p+ -p icmp -j ANTI_ICMPFLOOD_
$IPTABLES -A ANTI_ICMPFLOOD -i w+ -p icmp -j ANTI_ICMPFLOOD_
$IPTABLES -A ANTI_ICMPFLOOD_ \
-m hashlimit \
--hashlimit-name icmp \
--hashlimit 30/m \
--hashlimit-burst 60 \
--hashlimit-mode srcip \
--hashlimit-htable-expire 60000 \
-j RETURN
$IPTABLES -A ANTI_ICMPFLOOD_ -m limit --limit $LOG_LIMIT --limit-burst $LOG_LIMIT_BURST -j LOG --log-level debug --log-prefix '[IPTABLES ICMPFLOOD] : '
$IPTABLES -A ANTI_ICMPFLOOD_ -j DROP
$IPTABLES -A FIREWALL -j FW_ICMPFLOOD && echo "FIREWALL	ANTI_ICMPFLOOD"

$IPTABLES -N TRAP_PORTSCAN
$IPTABLES -N ANTI_PORTSCAN
$IPTABLES -N ANTI_PORTSCAN_
$IPTABLES -A TRAP_PORTSCAN -j ANTI_PORTSCAN
$IPTABLES -A ANTI_PORTSCAN -i e+ -j ANTI_PORTSCAN_
$IPTABLES -A ANTI_PORTSCAN -i p+ -j ANTI_PORTSCAN_
$IPTABLES -A ANTI_PORTSCAN -i w+ -j ANTI_PORTSCAN_
$IPTABLES -A ANTI_PORTSCAN_ -j FW_BROADCAST
$IPTABLES -A ANTI_PORTSCAN_ -j FW_MULTICAST
$IPTABLES -A ANTI_PORTSCAN_ -m limit --limit $LOG_LIMIT --limit-burst $LOG_LIMIT_BURST -j LOG --log-level debug --log-prefix '[IPTABLES PORTSCAN] : '
$IPTABLES -A ANTI_PORTSCAN_ -j TRACK_PROWLER
COUNT_TO_CIDR(){
local COUNT=$1
local CIDR_COUNT
for CIDR_COUNT in ${CIDR_COUNT_LIST[@]}
do
if [ $CIDR_COUNT -gt $COUNT ]; then continue;fi
local CIDR=${CIDR_TABLE[$CIDR_COUNT]}
break
done
echo $CIDR
}
CIDR_TO_COUNT(){
local CIDR=$1
local COUNT=$((2**(32-$CIDR)))
echo $COUNT
}
FILE_TO_CHAIN(){
local FILE=$1
local NAME=$2
if [ "`$IPTABLES -S | grep "^-N $NAME$"`" ]; then
return 0
elif [ ! -r $FILE ]; then
return 1
fi
$IPTABLES -N $NAME
$IPTABLES -F $NAME
local ifs=$IFS
IFS=$'\n'
local LINE
for LINE in `eval "cat $FILE | $FORMAT"`
do
$IPTABLES -A $NAME -s $LINE -j RETURN
done
IFS=$ifs
return 0
}
BUILD_RULE(){
local RULE=$1
if [ `echo $RULE | grep -E "^(ACCEPT|DROP|RETURN|(REJECT|LOG|NFQUEUE)( .*)?)$"` ]; then
RULE=$RULE
elif [ "`$IPTABLES -S | grep "^\(-N $RULE$\|-P $RULE \)"`" ]; then
RULE=$RULE
elif [ `echo $RULE | grep -E ^[A-Z_]\+$` ]; then
$IPTABLES -N $RULE
[ $? -ne 0 ] && RULE=
else
local FILE=`echo $LIST_DIR$RULE | sed 's|.*//|/|'`
if [ -r $FILE ]; then
RULE=${RULE##*/}
RULE=`echo WL_$RULE | cut -d. -f1 | tr '[a-z]' '[A-Z]'`
FILE_TO_CHAIN $FILE $RULE
else
RULE=
[ $SECURE = false ]
fi
[ $? -ne 0 ] && RULE=
fi
echo $RULE
}
BUILD_ROLE(){
local ROLE
local RULES
local RULE
for ROLE in ${ROLES[@]}; do
$IPTABLES -N $ROLE
eval RULES="\${${ROLE}[@]}"
local LINE=
for RULE in ${RULES[@]}; do
local AS_WHITELIST=
local ERROR=
if [ ! "`echo $RULE | grep [,\|]`" ]; then
ERROR=$RULE
RULE=`BUILD_RULE $RULE`
[ ! $RULE ] && [ $SECURE != false ] && RESULT=1
if [ ! $RULE ]; then [ $SECURE != false ] && echo "ERROR		$ROLE[$ERROR]" >&2; continue; fi
AS_WHITELIST=`echo $RULE | grep ^WL_`
LINE="${LINE:+$LINE }$RULE"
else
local C_RULES=(`eval echo ${RULE//|/ }`)
local C_RULE
RULE=`echo ${ROLE}_${C_RULES[0]##*/} | cut -d. -f1 | tr '[a-z]' '[A-Z]'`
$IPTABLES -N $RULE
LINE="${LINE:+$LINE }$RULE("
for C_RULE in ${C_RULES[@]}; do
AS_WHITELIST=
ERROR=$C_RULE
C_RULE=`BUILD_RULE $C_RULE`
[ ! $C_RULE ] && [ $SECURE != false ] && RESULT=1
if [ ! $C_RULE ]; then [ $SECURE != false ] && echo "ERROR		$ROLE[$ERROR]" >&2; continue; fi
LINE="$LINE$C_RULE,"
local ifs=$IFS
IFS=$'\n'
if [ `echo $C_RULE | grep -E "^(ACCEPT|DROP|RETURN|(REJECT|LOG|NFQUEUE)( .*)?)$"` ]; then
AS_WHITELIST=${AS_WHITELIST:+}
eval "$IPTABLES -A $RULE -j $C_RULE"
elif [ `echo $C_RULE | grep ^WL_` ]; then
AS_WHITELIST=${AS_WHITELIST:-1}
for C_RULE in `$IPTABLES -S ${C_RULE} | grep ' -j RETURN' | sed -e 's/^-A[^-]*//'`; do
eval "$IPTABLES -A $RULE $C_RULE"
done
else
AS_WHITELIST=${AS_WHITELIST:+}
for C_RULE in `$IPTABLES -S ${C_RULE} | grep '^-[AI] ' | sed -e 's/^-A[^-]*//'`; do
eval "$IPTABLES -A $RULE $C_RULE"
done
fi
IFS=$ifs
done
LINE="${LINE%,})"
fi
eval "$IPTABLES -A $ROLE -j $RULE"
if [ $AS_WHITELIST ]; then
$IPTABLES -A $RULE -j TRACK_PROWLER
$IPTABLES -A $RULE -j DROP
fi
done
eval RULES="\${${ROLE}[@]}"
echo "ROLE_CONF	$ROLE[$(echo "${RULES[@]}")]"
echo "ROLE_APPL	$ROLE[$LINE]"
done
}
BUILD_ROLE

SHIFT_ADDR(){
local ADDR=$1
local COUNT=$2
local D1=$(($COUNT/(256**3)))
[ $D1 -ne 0 ] && COUNT=0
local D2=$(($COUNT/(256**2)))
[ $D2 -ne 0 ] && COUNT=0
local D3=$(($COUNT/(256**1)))
[ $D3 -ne 0 ] && COUNT=0
local D4=$(($COUNT/(256**0)))
ADDR=`echo $ADDR | awk -v D1=$D1 -v D2=$D2 -v D3=$D3 -v D4=$D4 -F"." '{ print $1+D1 "." $2+D2 "." $3+D3 "." $4+D4 }'`

echo $ADDR
}

MAPPING(){
local PARAM
local ifs=$IFS
IFS=$'\n'
for PARAM in ${MAP[@]}; do
eval "$IPTABLES -A $PARAM"
echo "MAP		$PARAM"
done
IFS=$ifs
}
MAPPING

BUILD_COUNTRY(){
if [ ! -s $CACHE_DIR$1 ] || [ ! $2 -a ! $3 ];then return;fi
echo "LOAD	$1"
local LINE
for LINE in `cat $CACHE_DIR$1 | grep -E "\|($2|$3)\|ipv4\|"`
do
local CODE=`echo $LINE | cut -d "|" -f 2`
local ADDR=`echo $LINE | cut -d "|" -f 4`
local COUNT=`echo $LINE | cut -d "|" -f 5`
local CIDR=32
if [ $2 ] && [ `echo $CODE | grep -E $2` ]; then
BUILD_COUNTRY_RULE $ADDR $COUNT BUILD_COUNTRY_RULE_ACCEPT
printf "%-10s%-4s%-20s%s\n" ACCEPT $CODE $ADDR/$? $LINE
elif [ $3 ] && [ `echo $CODE | grep -E $3` ]; then
BUILD_COUNTRY_RULE $ADDR $COUNT BUILD_COUNTRY_RULE_DROP
printf "%-10s%-4s%-20s%s\n" DROP   $CODE $ADDR/$? $LINE
fi
done
}
BUILD_COUNTRY_RULE(){
local ADDR=$1
local COUNT=$2
local CALLBACK=$3
local CIDR=`COUNT_TO_CIDR $COUNT`
eval "$CALLBACK $ADDR $CIDR"

local REM=$(($COUNT-`CIDR_TO_COUNT $CIDR`))
if [ $REM -gt 0 ]; then
ADDR=`SHIFT_ADDR $ADDR $(CIDR_TO_COUNT $CIDR)`
BUILD_COUNTRY_RULE $ADDR $REM $CALLBACK
fi
return $CIDR
}
BUILD_COUNTRY_RULE_ACCEPT(){
local ADDR=$1
local CIDR=$2
$IPTABLES -A LOCAL_COUNTRY -s $ADDR/$CIDR -j RETURN
}
BUILD_COUNTRY_RULE_DROP(){
local ADDR=$1
local CIDR=$2
$IPTABLES -A BLOCK_COUNTRY -s $ADDR/$CIDR -j DROP
}

if [ $RESET -ne 0 ] || [ ! -z "$LOCAL_COUNTRY_CODE" -a $($IPTABLES -S LOCAL_COUNTRY 2>/dev/null | awk 'END{print NR}') -le 2 ] || [ ! -z "$BLOCK_COUNTRY_CODE" -a $($IPTABLES -S BLOCK_COUNTRY 2>/dev/null | awk 'END{print NR}') -le 2 ]; then
echo "BUILD		Chain LOCAL_COUNTRY"
echo "BUILD		Chain BLOCK_COUNTRY"

$IPTABLES -F LOCAL_COUNTRY
$IPTABLES -A LOCAL_COUNTRY -i lo -j RETURN
$IPTABLES -A LOCAL_COUNTRY -o lo -j RETURN

$IPTABLES -F BLOCK_COUNTRY
$IPTABLES -A BLOCK_COUNTRY -i lo -j RETURN
$IPTABLES -A BLOCK_COUNTRY -o lo -j RETURN

if [ $SECURE != false ]; then
$IPTABLES -I LOCAL_COUNTRY -j DROP
$IPTABLES -I BLOCK_COUNTRY -j DROP
else
$IPTABLES -I LOCAL_COUNTRY -j RETURN
$IPTABLES -I BLOCK_COUNTRY -j RETURN
fi

BUILD_COUNTRY "delegated-apnic-extended-latest"   $LOCAL_COUNTRY_CODE $BLOCK_COUNTRY_CODE
BUILD_COUNTRY "delegated-arin-extended-latest"    $LOCAL_COUNTRY_CODE $BLOCK_COUNTRY_CODE
BUILD_COUNTRY "delegated-ripencc-extended-latest" $LOCAL_COUNTRY_CODE $BLOCK_COUNTRY_CODE
BUILD_COUNTRY "delegated-lacnic-extended-latest"  $LOCAL_COUNTRY_CODE $BLOCK_COUNTRY_CODE
BUILD_COUNTRY "delegated-afrinic-extended-latest" $LOCAL_COUNTRY_CODE $BLOCK_COUNTRY_CODE

$IPTABLES -A LOCAL_COUNTRY -j DROP

$IPTABLES -D LOCAL_COUNTRY 1 2>/dev/null
$IPTABLES -D BLOCK_COUNTRY 1 2>/dev/null

else
[ $LOCAL_COUNTRY_CODE ] && echo "REUSE		Chain LOCAL_COUNTRY"
[ $BLOCK_COUNTRY_CODE ] && echo "REUSE		Chain BLOCK_COUNTRY"
fi

trap 'finailize && exit 0' 2
echo "In 30 seconds iptables will be automatically reset."
echo "Don't forget to test new SSH connection!"
echo "If there is no problem then press Ctrl-C to finish."
sleep 30
echo "rollback..."

[ $RESULT -eq 0 ] && echo "RESULT		Success" || echo "RESULT		Failure"
echo "Enter or y > save, n or timeout > revert"
read -t 60 input
if [ $? -eq 0 ] && [ "$input" != n ]; then
service iptables save
sysctl -p 2>&1 | grep -v -E "^error:.*(ipv6|bridge-nf-call)"
service rsyslog restart
else
service iptables restart
fi

echo complete

exit $RESULT
initialize