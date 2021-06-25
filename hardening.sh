Extended Binary Hardening
========================================================
chmod 700 /usr/bin/wget
chmod 700 /usr/bin/lynx
chmod 700 /usr/bin/bcc
chmod 700 /usr/bin/byacc
chmod 700 /usr/bin/cc
chmod 700 /usr/bin/gcc
chmod 700 /usr/bin/i386-redhat-linux-gcc
chmod 0000 /usr/bin/finger
chattr +i /usr/bin/finger

========================================================

/tmp Hardening

========================================================

Scan and harden /tmp /var/tmp directories

/scripts/securetmp

========================================================

Secure root login
========================================================
adduser adminco
passwd adminco
Add this user to wheel group.
Comment out “PermitRootLogin yes” in /etc/ssh/sshd_config and add,
“PermitRootLogin no”
/etc/init.d/sshd restart

======================================================================

Change sshd default port (NB: Make changes to the firewall)
======================================================================

In /etc/ssh/sshd_config, comment out “Port 22″ and add a new entry
eg: Port 4412
/etc/init.d/sshd restart

======================================================================

Secure named configuration
======================================================================

Disable allow-recursion in /etc/named.conf
Add “listen-on” directive to specify the network interface on which named
listens for queries.

eg :
options {
listen-on { 65.110.45.80; };
};

======================================================================
Inetd hardening
======================================================================
mv  /etc/xinetd.d/telnet /etc/xinetd.d/telnet.bk
/etc/rc.d/init.d/xinetd restart
======================================================================
Host.conf Hardening
======================================================================
cp -p /etc/host.conf /etc/host.conf.bk
vi /etc/host.conf
multi on
nospoof on
======================================================================
Hardening Pure/Proftpd
======================================================================
cp -p /etc/pure-ftpd.conf /etc/pure-ftpd.conf.bk
vi /etc/pure-ftpd.conf
AnonymousOnly no
NoAnonymous yes
PassivePortRange 30000 30050
======================================================================
Php Open_Basedir Tweak
======================================================================
Enable php open_basedir Protection,
In WHM, Main >> Security >> Tweak Security >> Php open_basedir Tweak
======================================================================
Root Login Email alert
======================================================================
cd /root
3. vi .bashrc
4. Scroll to the end of the file then add the following:
echo ‘ALERT – Root Shell Access (hostname) on:’ `date` `who` | mail -s “Alert:
Root Access from `who | cut -d’(‘ -f2 | cut -d’)’ -f1`” root@hostname.com
======================================================================
Sysctl Hardening
======================================================================
“Sysctl hardening for preventing SYNC/DOS attack”
cp -p /etc/sysctl.conf /etc/sysctl.conf.bk
In /etc/sysctl.conf
Paste the following into the file, you can overwrite the current information.
#Kernel sysctl configuration file for Red Hat Linux
# For binary values, 0 is disabled, 1 is enabled. See sysctl(8) and
# sysctl.conf(5) for more details.
# Disables packet forwarding
net.ipv4.ip_forward=0
# Disables IP source routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.lo.accept_source_route = 0
net.ipv4.conf.eth0.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
# Enable IP spoofing protection, turn on source route verification
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.lo.rp_filter = 1
net.ipv4.conf.eth0.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
# Disable ICMP Redirect Acceptance
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.lo.accept_redirects = 0
net.ipv4.conf.eth0.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
# Enable Log Spoofed Packets, Source Routed Packets, Redirect Packets
net.ipv4.conf.all.log_martians = 0
net.ipv4.conf.lo.log_martians = 0
net.ipv4.conf.eth0.log_martians = 0
# Disables IP source routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.lo.accept_source_route = 0
net.ipv4.conf.eth0.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
# Enable IP spoofing protection, turn on source route verification
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.lo.rp_filter = 1
net.ipv4.conf.eth0.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
# Disable ICMP Redirect Acceptance
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.lo.accept_redirects = 0
net.ipv4.conf.eth0.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
# Disables the magic-sysrq key
kernel.sysrq = 0
# Decrease the time default value for tcp_fin_timeout connection
net.ipv4.tcp_fin_timeout = 15
# Decrease the time default value for tcp_keepalive_time connection
net.ipv4.tcp_keepalive_time = 1800
# Turn off the tcp_window_scaling
net.ipv4.tcp_window_scaling = 0
# Turn off the tcp_sack
net.ipv4.tcp_sack = 0
# Turn off the tcp_timestamps
net.ipv4.tcp_timestamps = 0
# Enable TCP SYN Cookie Protection
net.ipv4.tcp_syncookies = 1
# Enable ignoring broadcasts request
net.ipv4.icmp_echo_ignore_broadcasts = 1
# Enable bad error message Protection
net.ipv4.icmp_ignore_bogus_error_responses = 1
# Log Spoofed Packets, Source Routed Packets, Redirect Packets
net.ipv4.conf.all.log_martians = 1
# Increases the size of the socket queue (effectively, q0).
net.ipv4.tcp_max_syn_backlog = 1024
# Increase the tcp-time-wait buckets pool size
net.ipv4.tcp_max_tw_buckets = 1440000
# Allowed local port range
net.ipv4.ip_local_port_range = 16384 65536
then
Run /sbin/sysctl -p and sysctl -w net.ipv4.route.flush=1 to enable the changes
without a reboot.
========================================================
ClamAV Installation

========================================================

cd /usr/local
wget http://sourceforge.net/projects/clamav/files/clamav/0.97/clamav-0.97.tar.gz/download
tar -xzvf clamav-0.97.tar.gz
cd clamav-0.97
groupadd clamav
useradd -g clamav clamav
mkdir /usr/local/share/clamav
chown clamav:clamav /usr/local/share/clamav
./configure
make
make install

root~] freshclam

yum install zlib zlib-devel
========================================================
========================================================
##############   PHASE 2 Installation ######################
========================================================
========================================================
Install Mod_security apache module with latest custom rules
========================================================
In WHM, Main >> cPanel >> Addon Modules >> Modsecurity
Add more rules to /usr/local/apache/conf/modsec.user.conf
Ref: http://www.gotroot.com/downloads/ftp/mod_security/rules.conf
========================================================
Chkrootkit Installation
========================================================
cd /usr/local/src
wget ftp://ftp.pangeia.com.br/pub/seg/pac/chkrootkit.tar.gz
tar -zxvf chkrootkit.tar.gz
cd chkrootkit
make sense
./chkrootkit
========================================================
Rkhunter Installation
========================================================
cd /usr/local/src
wget http://ncu.dl.sourceforge.net/project/rkhunter/rkhunter/1.4.0/rkhunter-1.4.0.tar.gz
tar -zxvf rkhunter-1.4.0.tar.gz
cd rkhunter
./installer.sh –layout default –install
# /usr/local/bin/rkhunter --update
# /usr/local/bin/rkhunter --propupd
========================================================
LibSafe Installation
========================================================
Refer:- http://enekumvenamorublog.wordpress.com/2013/02/24/libsafe-installation/
cd /usr/local/src
wget http://www.sfr-fresh.com/linux/misc/libsafe-2.0-16.tgz
tar -zxvf libsafe-2.0-16.tgz
cd libsafe-2.0-16
make
make install
$ LD_PRELOAD=/lib/libsafe.so.2
$ export LD_PRELOAD
echo ‘/lib/libsafe.so.2′ >> /etc/ld.so.preload
========================================================
Logcheck Installation
========================================================
Refer : http://linuxtechme.wordpress.com/2012/01/31/install-logcheck/
mkdir -p /usr/src/downloads
cd /usr/src/downloads
wget http://heanet.dl.sourceforge.net/sourceforge/sentrytools/logcheck-1.1.1.tar.gz
cd logcheck-1.1.1/systems
cd linux
vi logcheck.sh
Now change the variable SYSADMIN to root@hostname.com
cd ../../
mkdir -p /usr/local/etc/tmp
make linux
0 3 * * * /usr/local/etc/logcheck.sh
/etc/init.d/cron restart
========================================================
yum install sysstat
========================================================
logwatch Installation
========================================================
wget ftp://ftp.kaybee.org/pub/linux/logwatch-7.3.6.tar.gz
tar -zxvf logwatch-7.3.6.tar.gz
./install_logwatch.sh
/etc/log.d/scripts/logwatch.pl
set email in /usr/share/logwatch/default.conf/logwatch.conf to root@hostname.com
====================================================================
yum install smartmontools
======================================================================
======================================================================
Install Mod_evasive
======================================================================
cp -p /usr/local/apache/conf/httpd.conf /usr/local/apache/conf/httpd.conf.date
wget http://www.zdziarski.com/projects/mod_evasive/mod_evasive_1.10.1.tar.gz
tar -zxvf mod_evasive_1.10.1.tar.gz
cd mod_evasive
Compile mod_evasive apache module (Apache 2):
/usr/local/apache/bin/apxs -i -a -c mod_evasive20.c
vi /usr/local/apache/conf/httpd.conf
<IfModule mod_evasive20.c>
DOSHashTableSize 3097
DOSPageCount 5
DOSSiteCount 100
DOSPageInterval 2
DOSSiteInterval 2
DOSBlockingPeriod 10
DOSBlockingPeriod 600
DOSEmailNotify user@domain.com
</IfModule>
======================================================================
Prevent the execution of spamming scripts
======================================================================
cp -p /etc/apf/conf.apf /etc/apf/conf.apf.bk
a – iptables module ipt_owner
b – enable EGF in apf “Outbound (egress) filtering”
c – add this line that will be explained later in the EGF section.
EG_TCP_UID=”0:25,8:25,47:25,32002:25,0:465,8:465,47:465,32002:465″
d – restart apf
=====================================================
