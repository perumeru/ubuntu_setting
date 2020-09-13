#!/bin/bash

# パス
PATH=/sbin:/usr/sbin:/bin:/usr/bin

ALLOW_LOCAL_HOSTS=(
"192.168.0.0/24"
"192.168.57.0/22"
)
ALLOW_SSH_HOSTS=(
"192.168.57.0/22"
)
ALLOW_ALWAY=(
	"91.189.88.0/19"
	"160.26.0.0/16"
	"1.1.1.2"
	"1.0.0.2"
	"8.8.8.8"
	"185.228.168.9"
)

# ログの最大生成速度
LOG_LIMIT=45/m
LOG_LIMIT_BURST=512
# ポート定義
SSH=`cat /etc/ssh/sshd_config | grep '^#\?Port ' | tail -n 1 | sed -e 's/^[^0-9]*\([0-9]\+\).*$/\1/'`
ALLOW_LOCAL_PORT="20,21,53,80,443,990,1344,2222"
ALLOW_GLOBAL_PORT="2222"
##
readonly UBUNTU=true
initialize() 
{
	iptables -F
	iptables -X
	iptables -Z
	echo "iptables clear!!"
	iptables -P INPUT   ACCEPT
	iptables -P OUTPUT  ACCEPT
	iptables -P FORWARD ACCEPT
	echo "INPUT:AC,OUTPUT:AC,FORWARD:AC"
}
PolicyDecision()
{
	echo "Enter or y > do, n or timeout > revert"
	read -t 60 input
	if [ $? -eq 0 ] && [ "$input" != n ]; then
		iptables -P INPUT   DROP # すべてDROP。すべての穴をふさいでから必要なポートを空けていくのが良い。
		iptables -P OUTPUT  ACCEPT 
		iptables -P FORWARD DROP
	else
		trap 'finailize && exit 0' 2 # Ctrl-C をトラップする
		echo "If there is no problem then press Ctrl-C to finish."
		sleep 60
	fi
	
	echo "INPUT:DR,OUTPUT:AC,FORWARD:DR"
}
__initialize()
{
	if [ -z "$SSH" ]; then
		$SSH=22 #処理
	fi
	echo "sshport:$SSH"

	echo "Enter or y > install, n or timeout > revert"
	read -t 60 input
	if [ $? -eq 0 ] && [ "$input" != n ]; then
	if "${UBUNTU}"; then
		apt-get install iptables-persistent && 
		apt-get update && 
		modprobe -r ip_tables
	fi
	fi
}
finailize()
{
	echo "Enter or y > save, n or timeout > revert"
	read -t 60 input
	if [ $? -eq 0 ] && [ "$input" != n ]; then
		if "${UBUNTU}"; then
			iptables-save -c > /etc/iptables/rules.v4 && iptables-restore < /etc/iptables/rules.v4 &&
			sysctl -p 2>&1 | grep -v -E "^error:.*(ipv6|bridge-nf-call)" &&
			service iptables-persistent start || service netfilter-persistent start && return 0
		fi
		service iptables save && sysctl -p 2>&1 | grep -v -E "^error:.*(ipv6|bridge-nf-call)" &&
		service rsyslog restart && return 0
		/etc/init.d/iptables save && sysctl -p 2>&1 | grep -v -E "^error:.*(ipv6|bridge-nf-call)" &&
		/etc/init.d/iptables restart && return 0
	else
		if "${UBUNTU}"; then
			service iptables-persistent restart || service netfilter-persistent restart && return 0
		fi
		service iptables restart && return 0
		/etc/init.d/iptables restart && return 0
	fi
	echo "finailizeError!!"
	return 1
}
###########################################################
echo "initialize"
###########################################################
initialize
__initialize
PolicyDecision
###########################################################
echo "ALLOW_LOCAL_HOSTS"
###########################################################
iptables -A INPUT -i lo -j ACCEPT # SELF -> SELF
#PRIVATE IP許可
if [ "${ALLOW_LOCAL_HOSTS}" ]
then
	for allow_prihost in ${ALLOW_LOCAL_HOSTS[@]}
	do
		iptables -A INPUT -p tcp -s $allow_prihost -m multiport --dports $ALLOW_LOCAL_PORT -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
		iptables -A INPUT -p udp -s $allow_prihost -m multiport --dports $ALLOW_LOCAL_PORT -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
		echo -en " allow:$allow_prihost \r"
	done
fi
###########################################################
echo "Allow packet communication after session is established"
###########################################################
iptables -A INPUT -p tcp -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -p udp -m state --state ESTABLISHED,RELATED -j ACCEPT

###########################################################
echo "Measures start"
###########################################################
echo "Source IP spoofing prevention"
sed -i '/net.ipv4.conf.*.rp_filter/d' /etc/sysctl.conf
for dev in `ls /proc/sys/net/ipv4/conf/`
do
    sysctl -w net.ipv4.conf.$dev.rp_filter=1 > /dev/null
    echo "net.ipv4.conf.$dev.rp_filter=1" >> /etc/sysctl.conf
done
echo "Reject ICMP Redirect packets"
sed -i '/net.ipv4.conf.*.accept_redirects/d' /etc/sysctl.conf
for dev in `ls /proc/sys/net/ipv4/conf/`
do
    sysctl -w net.ipv4.conf.$dev.accept_redirects=0 > /dev/null
    echo "net.ipv4.conf.$dev.accept_redirects=0" >> /etc/sysctl.conf
done
echo "Deny Source Routed packet"
sed -i '/net.ipv4.conf.*.accept_source_route/d' /etc/sysctl.conf
for dev in `ls /proc/sys/net/ipv4/conf/`
do
    sysctl -w net.ipv4.conf.$dev.accept_source_route=0 > /dev/null
    echo "net.ipv4.conf.$dev.accept_source_route=0" >> /etc/sysctl.conf
done
echo "Smurf attack countermeasures"
sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1 > /dev/null
sed -i '/net.ipv4.icmp_echo_ignore_broadcasts/d' /etc/sysctl.conf
echo "net.ipv4.icmp_echo_ignore_broadcasts=1" >> /etc/sysctl.conf
# SYN Cookies ON
echo "TCP SYN Flood attack countermeasures"
sysctl -w net.ipv4.tcp_syncookies=1 > /dev/null
sed -i '/net.ipv4.tcp_syncookies/d' /etc/sysctl.conf
echo "net.ipv4.tcp_syncookies=1" >> /etc/sysctl.conf
# システムの連続稼働時間を通知しない
echo "Kernel version specific measures"
sysctl -w net.ipv4.tcp_timestamps=1 > /dev/null
sed -i '/net.ipv4.tcp_timestamps/d' /etc/sysctl.conf
echo "net.ipv4.tcp_timestamps=1" >> /etc/sysctl.conf
# 攻撃を行っているIPを攻撃者として記録
echo "Record the attacking IP as an attacker"
iptables -N TRACK_ATTACKER 2>/dev/null
iptables -N ANTI_ATTACKER
iptables -N ANTI_ATTACKER_
iptables -A TRACK_ATTACKER -j ANTI_ATTACKER
iptables -A ANTI_ATTACKER -i e+ -j ANTI_ATTACKER_
iptables -A ANTI_ATTACKER -i p+ -j ANTI_ATTACKER_
iptables -A ANTI_ATTACKER -i w+ -j ANTI_ATTACKER_
iptables -A ANTI_ATTACKER_ -m recent --name attacker-rapid --update --rttl --seconds 10 -j RETURN
iptables -A ANTI_ATTACKER_ -m recent --name attacker-rapid --set
iptables -A ANTI_ATTACKER_ \
          -m hashlimit \
          --hashlimit-name attacker-rapid \
          --hashlimit-above 6/m \
          --hashlimit-mode srcip \
          --hashlimit-htable-expire 10000 \
          -j RETURN
iptables -A ANTI_ATTACKER_ -m recent --name attacker-fast --update --rttl --seconds 60 -j RETURN
iptables -A ANTI_ATTACKER_ -m recent --name attacker-fast --set
iptables -A ANTI_ATTACKER_ \
          -m hashlimit \
          --hashlimit-name attacker-fast \
          --hashlimit-above 1/m \
          --hashlimit-mode srcip \
          --hashlimit-htable-expire 60000 \
          -j RETURN
iptables -A ANTI_ATTACKER_ -m recent --name attacker-medium --update --rttl --seconds 3600 -j RETURN
iptables -A ANTI_ATTACKER_ -m recent --name attacker-medium --set
#iptables -A ANTI_ATTACKER_ -m recent --name attacker-slow --update --rttl --seconds 86400 -j RETURN
iptables -A ANTI_ATTACKER_ -m recent --name attacker-slow --set
echo "INVALIDpacket NG"
iptables -N FW_INVALID 2>/dev/null
iptables -N DENY_INVALID
iptables -N DENY_INVALID_
iptables -A FW_INVALID -i e+ -j DENY_INVALID
iptables -A FW_INVALID -i p+ -j DENY_INVALID
iptables -A FW_INVALID -i w+ -j DENY_INVALID
iptables -A DENY_INVALID -m state --state INVALID -j DENY_INVALID_
iptables -A DENY_INVALID_ -m limit --limit $LOG_LIMIT --limit-burst $LOG_LIMIT_BURST -j LOG --log-level debug --log-prefix 'INVALIDpacket : '
iptables -A DENY_INVALID_ -j DROP
echo "NetBIOS NG"
iptables -N FW_NETBIOS 2>/dev/null
iptables -N DENY_NETBIOS
iptables -N DENY_NETBIOS_
iptables -A FW_NETBIOS -i e+ -j DENY_NETBIOS
iptables -A FW_NETBIOS -i p+ -j DENY_NETBIOS
iptables -A FW_NETBIOS -i w+ -j DENY_NETBIOS
iptables -A DENY_NETBIOS -p tcp -m multiport --dports 135,137,138,139,445 -j DENY_NETBIOS_
iptables -A DENY_NETBIOS -p udp -m multiport --dports 135,137,138,139,445 -j DENY_NETBIOS_
iptables -A DENY_NETBIOS_ -m limit --limit $LOG_LIMIT --limit-burst $LOG_LIMIT_BURST -j LOG --log-level debug --log-prefix 'NETBIOS NG : '
iptables -A DENY_NETBIOS_ -j TRACK_ATTACKER
iptables -A DENY_NETBIOS_ -j DROP
echo "Stealth Scan"
iptables -N STEALTH_SCAN
iptables -A STEALTH_SCAN -m limit --limit $LOG_LIMIT --limit-burst $LOG_LIMIT_BURST -j LOG --log-level debug --log-prefix "stealth_scan_attack: "
iptables -A STEALTH_SCAN -j TRACK_ATTACKER
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

iptables -A INPUT -f -m limit --limit $LOG_LIMIT --limit-burst $LOG_LIMIT_BURST -j LOG --log-level debug --log-prefix 'fragment_packet:'
iptables -A INPUT -f -j DROP
echo "DDoS Attack"
iptables -N FW_SYNFLOOD 2>/dev/null
iptables -N ANTI_SYNFLOOD
iptables -N ANTI_SYNFLOOD_
iptables -A FW_SYNFLOOD -p tcp -m multiport --dport $ALLOW_LOCAL_PORT -j ANTI_SYNFLOOD
iptables -A FW_SYNFLOOD -p udp -m multiport --dport $ALLOW_LOCAL_PORT -j ANTI_SYNFLOOD
iptables -A ANTI_SYNFLOOD -i e+ -p tcp -m state --state NEW -j ANTI_SYNFLOOD_
iptables -A ANTI_SYNFLOOD -i e+ -p udp -m state --state NEW -j ANTI_SYNFLOOD_
iptables -A ANTI_SYNFLOOD -i p+ -p tcp -m state --state NEW -j ANTI_SYNFLOOD_
iptables -A ANTI_SYNFLOOD -i p+ -p udp -m state --state NEW -j ANTI_SYNFLOOD_
iptables -A ANTI_SYNFLOOD -i w+ -p tcp -m state --state NEW -j ANTI_SYNFLOOD_
iptables -A ANTI_SYNFLOOD -i w+ -p udp -m state --state NEW -j ANTI_SYNFLOOD_
iptables -A ANTI_SYNFLOOD_ \
-m hashlimit \
--hashlimit-name dns \
--hashlimit 25/m \
--hashlimit-burst 60 \
--hashlimit-mode srcip \
--hashlimit-htable-expire 60000 \
-j RETURN
iptables -A ANTI_SYNFLOOD_ -m limit --limit $LOG_LIMIT --limit-burst $LOG_LIMIT_BURST -j LOG --log-prefix 'DDoS Attack(dns) : '
iptables -A ANTI_SYNFLOOD_ -j DROP
echo "Ping of Death"
iptables -N FW_PINGDEATH 2>/dev/null
iptables -N ANTI_PINGDEATH
iptables -N ANTI_PINGDEATH_
iptables -A FW_PINGDEATH -i e+ -p icmp --icmp-type echo-request -j ANTI_PINGDEATH
iptables -A FW_PINGDEATH -i p+ -p icmp --icmp-type echo-request -j ANTI_PINGDEATH
iptables -A FW_PINGDEATH -i w+ -p icmp --icmp-type echo-request -j ANTI_PINGDEATH
iptables -A ANTI_PINGDEATH -j ANTI_PINGDEATH_
iptables -A ANTI_PINGDEATH_ \
          -m hashlimit \
          --hashlimit-name ping \
          --hashlimit 1/s \
          --hashlimit-burst 4 \
          --hashlimit-mode srcip \
          --hashlimit-htable-expire 1000 \
          -j RETURN
iptables -A ANTI_PINGDEATH_ -m limit --limit $LOG_LIMIT --limit-burst $LOG_LIMIT_BURST -j LOG --log-level debug --log-prefix 'Ping_of_Death : '
iptables -A ANTI_PINGDEATH_ -j TRACK_ATTACKER
iptables -A ANTI_PINGDEATH_ -j DROP
echo "IP spoofing attack countermeasures"
iptables -N FW_SPOOFING 2>/dev/null
iptables -N ANTI_SPOOFING
iptables -N ANTI_SPOOFING_
iptables -N ANTI_SPOOFING__
iptables -A FW_SPOOFING -j ANTI_SPOOFING
iptables -A ANTI_SPOOFING -i e+ -j ANTI_SPOOFING_
iptables -A ANTI_SPOOFING -i p+ -j ANTI_SPOOFING_
iptables -A ANTI_SPOOFING -i w+ -j ANTI_SPOOFING_
iptables -A ANTI_SPOOFING_ -s 127.0.0.0/8    -j ANTI_SPOOFING__
iptables -A ANTI_SPOOFING_ -s 10.0.0.0/8     -j ANTI_SPOOFING__
iptables -A ANTI_SPOOFING_ -s 172.16.0.0/12  -j ANTI_SPOOFING__
iptables -A ANTI_SPOOFING_ -s 192.168.0.0/16 -j ANTI_SPOOFING__
iptables -A ANTI_SPOOFING_ -s 224.0.0.0/3 -j ANTI_SPOOFING__
iptables -A ANTI_SPOOFING__ -m limit --limit $LOG_LIMIT --limit-burst $LOG_LIMIT_BURST -j LOG --log-level debug --log-prefix 'IP_spoofing : '
iptables -A ANTI_SPOOFING__ -j TRACK_ATTACKER
iptables -A ANTI_SPOOFING__ -j DROP

###########################################################
echo "Measures end"
###########################################################

###########################################################
echo "IP permit"
###########################################################
#echo "GLOBAL IP permission"
#if [ "${ALLOW_ROUGHLY_HOSTS}" ]
#then
#	for allow_grohost in ${ALLOW_ROUGHLY_HOSTS[@]}
#	do
#		iptables -A INPUT -p tcp -s $allow_grohost -m multiport --dports $ALLOW_GLOBAL_PORT -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
#		echo -en " allow:$allow_grohost \r"
#	done
#fi
#echo "SSH IP permission"
#if [ "${ALLOW_SSH_HOSTS}" ]
#then
#	for allow_sshhost in ${ALLOW_SSH_HOSTS[@]}
#	do
#		iptables -A INPUT -p tcp -s $allow_sshhost -m multiport --dports $SSH -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT # LIMITED_LOCAL_NET -> SELF
#		echo -en " allow:$allow_sshhost \r"
#	done
#fi
###########################################################
echo "throughput"
###########################################################
iptables -t mangle -A PREROUTING -p tcp --dport 53 -j TOS --set-tos Maximize-Throughput
###########################################################
echo "finailize"
###########################################################
iptables -A INPUT  -j LOG --log-prefix "drop: "
iptables -A INPUT  -j DROP
trap 'finailize && exit 0' 2 # Ctrl-C をトラップする
echo "If there is no problem then press Ctrl-C to finish."
sleep 60
echo "rollback..."
initialize