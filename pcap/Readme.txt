1. To install web tcpreplay, user needs to install the following 2 files:
    a. pcap.php
    b. REPLAY.sh

2. Setup /etc/php5/apache2/php.ini
file_uploads = On
upload_max_filesize = 520M

3. Install the following packages:
   ubuntu:
	apt-get install tcpreplay ipcalc php5 php-ssh2 php-seclib php-securitylib

4. Create 3 directories:
   a. /opt/autoweb/pcap to store pcap.php
   b. /opt/utils  to store REPLAY.sh + tester.pem ( where tester is the user name and pem key was obtained from this ssh-keygen for this user ).
   Please also make sure that do 
   	  sudo chown tester:tester /opt/utils/tester.pem
    	  sudo chmod 700 /opt/utils/tester.pem
   c. /opt/uploads to store all the new pcap files

5. Create symbolic link:
    sudo ln -s /opt/autoweb /var/www/autoweb

6. Add tester user name to /etc/sudoers:
tester  ALL=(ALL:ALL) NOPASSWD: /usr/sbin/tcpdump *, /usr/bin/tcpreplay *, /opt/autoweb/pcap/REPLAY.sh * 
