Bath
==========
From the [original README](README-orig):
>bath.sh is a shell script that connects to the webpage using curl for instances where a web browser is cumbersome, or just not available.

(Almost) Automatic Setup
----------
Run `sudo ./deploy.sh`  
This will do *most* of the Bath setup after some initial error checking. You may have to update your version of sudo, install apache, edit your sudoers file, or edit your hosts file (see Manual Setup below). If those checks pass, the script will copy all of the files to their correct locations in the file system and do some basic Apache setup.

Manual Setup
----------

* Copy the files to the correct locations (as dictated by the directory structure)

* Assuming you've installed Apache, navigate to /etc/apache2 and run: `sudo a2enmod ssl`

* Delete/comment out everything in /etc/apache2/ports.conf

* Add the following line to your /etc/apt/sources.list:  

        deb http://backports.debian.org/debian-backports squeeze-backports main

* Run: `sudo apt-get update && sudo apt-get -t squeeze-backports install sudo`  
This installs a newer version of sudo that doesn't have [this bug](http://comments.gmane.org/gmane.comp.tools.sudo.user/3838).

* Run: `su -`  
Type in your root password  
Run: `visudo`

* Add the following line after any existing defaults:  

        Defaults secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

* Add the following lines under "# Cmnd alias specification":  

        Cmnd_Alias CREATESSH = /sbin/iptables -A INPUT -p tcp -m tcp --dport 22 -m state --state NEW -j REJECT -m comment --comment *  
        Cmnd_Alias ADDSSH = /sbin/iptables -I INPUT -p tcp --dport 22 -m state --state NEW -j ACCEPT -s *  
        Cmnd_Alias DELSSH = /sbin/iptables -D INPUT -p tcp --dport 22 -m state --state NEW -j ACCEPT -s *  
        Cmnd_Alias SHOWSSH = /sbin/iptables -n -L INPUT

* Add the following line under "# User privilege specification":

        www-data ALL=NOPASSWD: CREATESSH, ADDSSH, DELSSH, SHOWSSH

* Save and quit, and log out of root

* Navigate to /etc/apache2 and run: `sudo a2dissite 000-default && sudo a2ensite port443`

* Edit /etc/hosts so that the IP next to your hostname is your IP rather than 127.0.0.1

* Edit /var/lib/bath/app/libbath.py to return some string (single quotes) after line 22 (the string can be anything)

* Run: `sudo chown -R www-data:www-data /var/lib/bath`

* Run: `sudo /etc/init.d/apache2 reload`

* Run: `sudo /etc/init.d/apache2 restart`