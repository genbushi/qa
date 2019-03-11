#!/bin/sh

# qa.sh
# FreeBSD not supported.
# Oct-2018 PM
# vsw@vswsystems.com

#### Variables Here ####
REL="1058"
DATE=`date +%m-%d-%Y`
HOST=$(hostname)
EMAIL="email@domain.com"
SUBJ="Linux Server Q/A Report $HOST"
MSG="/root/$HOST.log"
ARCH='uname -m'
download="/usr/bin/wget -nv"
RHDEPS="httpd mod_ssl php mysql php-mysql mysql-server"
RH7DEPS="httpd mod_ssl php mariadb php-mysql mariadb-server"
DEBDEPS="apache2 ssl-cert apache2-utils ssl-cert php5 libapache2-mod-php5 mysql-server mysql-client php5-mysql"
CHKCONFIG="cups apmd bluetooth restorecond mcstrans pcscd portmap rpcgssd rpcidmapd smartd atd anacron auditd yum-updatesd avahi-daemon firstboot kudzu iptables yum-cron"
YUMREM="rhn-virtualization-host xen-libs rhn-virtualization-common yum-cron"
APTREM="apparmor"
RHEL=0
#### End Variables ####
#### Do NOT Edit Below This Line ####

#### Start ####
echo
echo "###############################"
echo "# Linux Server Post Installer #"
echo "###############################"
echo
echo "This will set up basic stuff on fresh server install"
echo
echo "Linux support ONLY at this time"
echo
echo "!! REGISTER RHEL BEFORE RUNNING THIS SCRIPT !!"
echo
echo "!! REGISTER RHEL BEFORE RUNNING THIS SCRIPT !!"
echo
sleep 1
echo "Ctl-C Now if you do NOT want to proceed"
echo
sleep 1
echo "3......"
echo
sleep 1
echo "2...."
echo
sleep 1
echo "1.."
echo
sleep 1

#### Sanity check for Previous Q/A ####
if [ -f /root/$HOST.log ]
then
    echo "!! Hold on Partner - Problem Detected !!" 
    echo "It appears this machine may have been Q/A'd already, there's a preexisting Installer Log in /root" 
    echo "Halting this Q/A and exiting - Please check server it may have been Q/A'd already." 
    exit 1
else
    echo "" 
fi

#### Determine OS ####
echo "...determining operating system"
echo "........................"
echo
echo "...argh ! Found it:"
echo
sleep 1
if [ "$(uname -s)" = 'FreeBSD' ]; then
  DIST='freebsd'
  echo "Error: FreeBSD Not Supported with this Installer."
  echo
  exit 1

elif [ -f "/etc/enterprise-release" ]; then
ELSV=$(egrep -o 'Enterprise' /etc/enterprise-release)
  case $ELSV in
	Enterprise*)	
	DIST='oracle'
	BASE='rpm'
	echo "You Are Running Oracle Linux"
	echo
	;;
  esac

elif [ -f "/etc/oracle-release" ]; then
ORCV=$(egrep -o 'Oracle' /etc/oracle-release)
  case $ORCV in
	Oracle)	
	DIST='oracle'
	BASE='rpm'
	echo "You Are Running Oracle Linux"
	echo
	;;
  esac

elif [ -f "/etc/redhat-release" ]; then
RHV=$(egrep -o 'Fedora|CentOS|Red' /etc/redhat-release)
  case $RHV in
	Red)	
	if grep -q -i "release 5" /etc/redhat-release;  then
        DIST='redhat'
        BASE='rpm'
        RHEL=1
        echo "You Are Running Redhat Enterprise 5 - Getting old buddy."
	elif grep -q -i "release 6" /etc/redhat-release;  then
        DIST='redhat'
        BASE='rpm'
        RHEL=1
        echo "You Are Running Redhat Enterprise 6 - Pimp Daddy !!"
	elif grep -q -i "release 7" /etc/redhat-release; then
        DIST='redhat7'
        BASE='rpm'
        RHEL=2
        echo "You Are Running Redhat Enterprise 7 - eh, not a fan so far !!"
	fi
	echo
	;;
    	Fedora)
	DIST='redhat'
	BASE='rpm'
	echo "You Are Running Fedora"
	echo "Most Stuff in Here Will Work, May See Some Errors."
	echo
	;;
    	CentOS)	
	if grep -q -i "release 5" /etc/redhat-release;  then
        DIST='redhat'
        BASE='rpm'
        echo "You Are Running CentOS 5 - Getting old buddy."
	elif grep -q -i "release 6" /etc/redhat-release;  then
        DIST='redhat'
        BASE='rpm'
        echo "You Are Running CentOS 6 - Pimp Daddy !!"
	elif grep -q -i "release 7" /etc/redhat-release; then
        DIST='redhat7'
        BASE='rpm'
        echo "You Are Running CentOS 7 - eh, not a fan so far !!"
	fi
	echo
	;;
  esac

elif [ -f "/etc/debian_version" ]; then
DEBV=$(egrep -o 'Ubuntu|Debian' /etc/issue)
  case $DEBV in
    	Ubuntu)  
	DIST='ubuntu'
	BASE='deb'
	echo "You Are Running Ubuntu"
	echo
	;;
    	Debian)
	DIST='debian'
	BASE='deb'
	echo "You Are Running Debian"
	echo
	;;
  esac

else 
  echo "Error: Your OS Not Supported at this Time."
  exit 1
fi

#### Important Fixes ####
echo
echo "...correcting some image stuff before we get too far along"
echo "........................"
echo "nameserver 1.1.1.1" > /etc/resolv.conf
echo "nameserver 1.0.0.1" >> /etc/resolv.conf
echo "nameserver 208.67.222.222" >> /etc/resolv.conf
echo "........................"

#### Timezone ####
echo "...applying EST Timezone"
if [ -f /etc/sysconfig/clock ]; then sed -i 's/Chicago/New_York/g' /etc/sysconfig/clock; fi
rm -f /etc/localtime
ln -s /usr/share/zoneinfo/America/New_York /etc/localtime
wait
echo "........................"

#### WGET Useful Utilities ####
wget -q http://mysqltuner.pl -O /usr/local/bin/mysqltuner.pl
chmod +x /usr/local/bin/mysqltuner.pl

#### Package Removals ####
echo
echo "...removing some packages we have in our imaging system that we don't need"
if [ "$DIST" = "redhat" ]; then
	service yum-cron stop && service yum-updatesd stop
	wait
	yum -y remove $YUMREM
	wait
	sleep 1
elif [ "$DIST" = "ubuntu" ]; then
	/etc/init.d/apparmor stop && /etc/init.d/apparmor teardown
	wait
	apt-get -y purge $APTREM
	wait
	sleep 1
else
	echo "...continuing"
	echo		
fi
echo "........................"

#### System Check ####
echo
echo "Basic System check, Output in /root/$HOST.log..."
echo
sleep 1
echo "####== Linux Q/A Report for $HOST ==####" | tee /root/$HOST.log
echo
echo "" >> /root/$HOST.log
date >> /root/$HOST.log
echo "-Auto Generated by Post Install Setup Script v$REL-" >> /root/$HOST.log
echo "" >> /root/$HOST.log
sleep 1
echo "### Hostname ###" | tee -a /root/$HOST.log
hostname | tee -a /root/$HOST.log
echo "" | tee -a /root/$HOST.log
sleep 1
echo "### Installed OS and Arch ###" | tee -a /root/$HOST.log
if [ "$DIST" = "oracle" ]; then
	cat /etc/issue | tee -a /root/$HOST.log
elif [ "$BASE" = "rpm" ]; then
	cat /etc/redhat-release | tee -a /root/$HOST.log
elif [ "$BASE" = "deb" ]; then
	cat /etc/issue | tee -a /root/$HOST.log
else
	echo "Un-Identified Linux Distro (ULD)" | tee -a /root/$HOST.log	
fi
uname -m | tee -a /root/$HOST.log
echo "" | tee -a /root/$HOST.log
sleep 1
echo "### IP Addresses ###" | tee -a /root/$HOST.log
ifconfig -a|grep 'inet addr'|grep -v '127.0.0.1'|cut -d: -f2|cut -d" " -f1 | tee -a /root/$HOST.log
echo "" | tee -a /root/$HOST.log
sleep 1
echo "### CPU Cores ###" | tee -a /root/$HOST.log
cat /proc/cpuinfo |grep name | tee -a /root/$HOST.log
echo "" | tee -a /root/$HOST.log
sleep 1
echo "### Memory Total ###" | tee -a /root/$HOST.log
cat /proc/meminfo |grep -i MemTotal | tee -a /root/$HOST.log
dmesg |grep Memory: | tee -a /root/$HOST.log
echo "" | tee -a /root/$HOST.log
sleep 1
echo "### Hard Drives and Partioning ###" | tee -a /root/$HOST.log
dmesg |grep "sd[a-d]"|grep sectors | tee -a /root/$HOST.log
echo "" | tee -a /root/$HOST.log
cat /proc/scsi/scsi | tee -a /root/$HOST.log
echo "" | tee -a /root/$HOST.log
fdisk -l | tee -a /root/$HOST.log
echo "" | tee -a /root/$HOST.log
df -h | tee -a /root/$HOST.log
echo "" | tee -a /root/$HOST.log
echo "### Connectivity and Name Resolution ###" >> /root/$HOST.log
ping -c 3 -q google.com >> /root/$HOST.log
echo "" >> /root/$HOST.log
echo
echo "...finished with base system checks"
sleep 1
echo "........................"

#### Cron ####
echo
echo "...setting Up Cron for Updates and Time"
if [ "$BASE" = "rpm" ]; then
cat << EOF >> /var/spool/cron/root
# Time synchronization
35 3 * * * /usr/sbin/ntpdate -s time.google.com
# Run Updates Daily. Disable if you do not want automatic updates.
35 3 * * * /usr/bin/yum -y upgrade >/dev/null 2>&1
EOF
elif [ "$BASE" = "deb" ]; then
cat << EOF >> /var/spool/cron/crontabs/root
# Time synchronization
35 3 * * * /usr/sbin/ntpdate -s time.google.com
# Run Updates Daily. Disable if you do not want automatic updates.
35 3 * * * /usr/bin/apt-get -y update && /usr/bin/apt-get -y dist-upgrade >/dev/null 2>&1
EOF
else
	echo
fi
echo "........................"
echo "### Current Cron Jobs ###" >> /root/$HOST.log
crontab -l >> /root/$HOST.log
echo "" >> /root/$HOST.log
echo

#### Services ####
echo "........................"
echo "...disabling some services"
echo "........................"
if [ "$DIST" = "redhat" ]; then
	for service in $CHKCONFIG; do
		chkconfig $service off > /dev/null 2>&1 
	done
elif [ "$DIST" = "redhat7" ]; then
	systemctl stop NetworkManager && systemctl disable NetworkManager && systemctl mask NetworkManager
	wait
	systemctl enable network && systemctl start network && chkconfig network on
	wait
	systemctl stop firewalld && systemctl disable firewalld && systemctl mask firewalld
	wait
	yum remove NetworkManager*
	wait
	yum install iptables-services && systemctl enable iptables && systemctl enable ip6tables
	wait	
else
	echo "........................"
fi

#### Updates ####
echo "...going to run updates"
if [ "$BASE" = "rpm" ]; then
        yum clean all && yum -y upgrade
        wait
        sleep 1
elif [ "$BASE" = "deb" ]; then
        apt-get clean && apt-get -y update && apt-get -y dist-upgrade
        wait
        sleep 1
else
        echo
fi

#### Firewall ####
echo
echo "...going to set up basic firewall (basics), manually add any other special ports"
if [ "$BASE" = "rpm" ]; then
chkconfig ip6tables on
wait
sed -i 's/IPTABLES_MODULES=""/IPTABLES_MODULES="ip_conntrack_ftp"/g' /etc/sysconfig/iptables-config
wait
echo -n > /etc/sysconfig/iptables
echo "........................"
cat << EOF >> /etc/sysconfig/iptables
# Firewall configuration written by system-config-securitylevel
# Manual customization of this file is not recommended.
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
:RH-Firewall-1-INPUT - [0:0]
-A INPUT -j RH-Firewall-1-INPUT
-A FORWARD -j RH-Firewall-1-INPUT
-A RH-Firewall-1-INPUT -i lo -j ACCEPT
-A RH-Firewall-1-INPUT -i eth1 -j ACCEPT
-A RH-Firewall-1-INPUT -p icmp --icmp-type any -j ACCEPT
-A RH-Firewall-1-INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
-A RH-Firewall-1-INPUT -p udp -m udp --dport 53 -j ACCEPT
-A RH-Firewall-1-INPUT -p tcp -m tcp --dport 53 -j ACCEPT
-A RH-Firewall-1-INPUT -m state --state NEW -m tcp -p tcp --dport 22 -j ACCEPT
-A RH-Firewall-1-INPUT -m state --state NEW -m tcp -p tcp --dport 80 -j ACCEPT
-A RH-Firewall-1-INPUT -m state --state NEW -m tcp -p tcp --dport 443 -j ACCEPT
-A RH-Firewall-1-INPUT -j DROP 
COMMIT
EOF
wait
echo -n > /etc/sysconfig/ip6tables
echo "........................"
cat << EOF >> /etc/sysconfig/ip6tables
# Firewall configuration written by system-config-securitylevel
# Manual customization of this file is not recommended.
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
:RH-Firewall-1-INPUT - [0:0]
-A INPUT -j RH-Firewall-1-INPUT
-A FORWARD -j RH-Firewall-1-INPUT
-A RH-Firewall-1-INPUT -i lo -j ACCEPT
-A RH-Firewall-1-INPUT -p ipv6-icmp -j ACCEPT
-A RH-Firewall-1-INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
-A RH-Firewall-1-INPUT -s some:thing::0/64 -j ACCEPT
-A RH-Firewall-1-INPUT -j DROP 
COMMIT
EOF
elif [ "$BASE" = "deb" ]; then
echo -n > /etc/iptables.up.rules
echo "#post-up iptables-restore < /etc/iptables.up.rules" >> /etc/network/interfaces
echo "post-up ip6tables-restore < /etc/ip6tables.up.rules" >> /etc/network/interfaces
echo "........................"
cat << EOF >> /etc/iptables.up.rules
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
:Firewall-1-INPUT - [0:0]
-A INPUT -j Firewall-1-INPUT
-A FORWARD -j Firewall-1-INPUT
-A Firewall-1-INPUT -i lo -j ACCEPT
-A Firewall-1-INPUT -i eth1 -j ACCEPT
-A Firewall-1-INPUT -p icmp --icmp-type any -j ACCEPT
-A Firewall-1-INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
-A Firewall-1-INPUT -p udp -m udp --dport 53 -j ACCEPT
-A Firewall-1-INPUT -p tcp -m tcp --dport 53 -j ACCEPT
-A Firewall-1-INPUT -m state --state NEW -m tcp -p tcp --dport 22 -j ACCEPT
-A Firewall-1-INPUT -m state --state NEW -m tcp -p tcp --dport 80 -j ACCEPT
-A Firewall-1-INPUT -m state --state NEW -m tcp -p tcp --dport 443 -j ACCEPT
-A Firewall-1-INPUT -j DROP 
COMMIT
EOF
wait
echo -n > /etc/ip6tables.up.rules
echo "........................"
cat << EOF >> /etc/ip6tables.up.rules
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
:Firewall-1-INPUT - [0:0]
-A INPUT -j Firewall-1-INPUT
-A FORWARD -j Firewall-1-INPUT
-A Firewall-1-INPUT -i lo -j ACCEPT
-A Firewall-1-INPUT -p ipv6-icmp -j ACCEPT
-A Firewall-1-INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
-A Firewall-1-INPUT -s some:thing::0/64 -j ACCEPT
-A Firewall-1-INPUT -j DROP 
COMMIT
EOF
else
	echo
fi
echo "........................"

#### Final Stage ####
echo
echo "...finishing final stage"
echo "........................"
echo "" >> /root/$HOST.log
echo "##### END #####" >> /root/$HOST.log
echo "........................"
echo "........................"
echo "...cleaning up and generating Q/A Report"
if [ "$BASE" = "rpm" ]; then
	mail -s "$SUBJ" "$EMAIL" < $MSG
	yum clean all
	history -c
elif [ "$BASE" = "deb" ]; then
        mail -s "$SUBJ" "$EMAIL" < $MSG
        apt-get clean 
        history -c
else
	cat /dev/null > ~/.bash_history
fi
echo "........................"
echo "==== Finished ===="
echo "........................"
sleep 1
echo "==== Reboot and/or Install Software if Required by Q/A ===="
unlink $0
