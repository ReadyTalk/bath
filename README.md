Bath
==========
From the [original README](README-orig):
>bath.sh is a shell script that connects to the webpage using curl for instances where a web browser is cumbersome, or just not available.

### Dependencies
Debian Squeeze (6.0) or greater

apache2  
apache2-threaded-dev  
libapache2-mod-python  
python-dev  
python-bottle  
python-ipaddr  

### (Almost) Automatic Setup
* Install dependencies

        sudo apt-get install apache2 libapache2-mod-python libapache2-mod-python python-dev python-bottle python-ipaddr

* Edit */etc/hosts* so that the IP next to your hostname is your IP rather than 127.0.0.1
* Update sudoers

          sudo /usr/sbin/visudo

  * Add the following line after any existing defaults:

            Defaults secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

  * Add the following lines under "# Cmnd alias specification":

            Cmnd_Alias CREATESSH = /sbin/iptables -A INPUT -p tcp -m tcp --dport 22 -m state --state NEW -j REJECT -m comment --comment *
            Cmnd_Alias ADDSSH = /sbin/iptables -I INPUT -p tcp --dport 22 -m state --state NEW -j ACCEPT -s *
            Cmnd_Alias DELSSH = /sbin/iptables -D INPUT -p tcp --dport 22 -m state --state NEW -j ACCEPT -s *
            Cmnd_Alias SHOWSSH = /sbin/iptables -n -L INPUT

  * Add the following line under "# User privilege specification":

            www-data ALL=NOPASSWD: CREATESSH, ADDSSH, DELSSH, SHOWSSH

* If the server is running Debian Squeeze then install a newer version of sudo that doesn't have [this bug](http://comments.gmane.org/gmane.comp.tools.sudo.user/3838):
  * Add the backports Apt repository:

            if ! grep -q squeeze-backports <(apt-cache policy); then
              sudo bash -c 'echo "deb http://backports.debian.org/debian-backports squeeze-backports main" >> /etc/apt/sources.list'
            fi

  * Install the newest sudoers:

            sudo apt-get update && sudo apt-get -t squeeze-backports install sudo

* Run the deploy script:

        sudo ./deploy.sh

  This will do *most* of the Bath setup after some initial error checking. If those checks pass, the script will copy all of the files to their correct locations in the file system and do some basic Apache setup. It will then reload Apache and start the bathd daemon.
* Finally, you need to edit /etc/apache2/sites-enabled/bath-ssl and configure the ServerName, SSLCertificate, and authorization (LDAP/htpasswd/etc) settings. Then reload Apache:

        sudo service apache2 reload

* If all goes well then your new Bath instance should be availabe at [http://your.server.com/](http://your.server.com/).
