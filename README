BATH

The python files go in /var/lib/bath
The database and pid file get created in /var/lib/bath/daemon

bath.sh is a shell script that connects to the webpage using curl for instances where a web browser is cumbersome, or just not available.

REQUIREMENTS
 - python 2.6.3+
 - bottle (http://bottlepy.org)
 - sudo (but not the version with this bug (http://comments.gmane.org/gmane.comp.tools.sudo.user/3838)). See ISSUES
 - apache2 w/ssl mod_python
 - iptables


INSTALLATION

First, you need to install apache (or really, anything that honors 'REMOTE_ADDR' and 'AUTHENTICATE_UID' with ssl (because not using ssl kind of defeats the purpose). If you are using apache2, this is the config you need to make bath work (aside from ssl and all the relevant stuff for that):
----------------------------------
Alias /bath /var/lib/bath/app

<Location /bath>
  Options FollowSymLinks
  AllowOverride None
  DirectoryIndex bath.py
  AddHandler mod_python .py
  PythonHandler mod_python.publisher
</Location>
----------------------------------

These lines needs to be in the /etc/sudoers file (bath is an unprivileged user):
----------------------------------
# Cmnd alias specification
Cmnd_Alias CREATERULE = /sbin/iptables --append INPUT --protocol tcp --dport [0-9][0-9]* --match state --state NEW --jump REJECT --match comment --comment *
Cmnd_Alias ADDRULE = /sbin/iptables --insert INPUT --protocol tcp --dport [0-9][0-9]* --match state --state NEW --jump ACCEPT --source *
Cmnd_Alias DELRULE = /sbin/iptables --delete INPUT --protocol tcp --dport [0-9][0-9]* --match state --state NEW --jump ACCEPT --source *
Cmnd_Alias SHOWRULE = /sbin/iptables --numeric --list INPUT
bath        bath-dev=NOPASSWD: CREATERULE, ADDRULE, DELRULE, SHOWRULE
----------------------------------

the bathd script is the init file that starts the daemon, and should go into /etc/init.d/

CONFIG

take a look at daemon/bath.conf
pay particular attnetion to the iptable rules, which must match with what's been put in the /etc/sudoers file
also take a look at client.conf

PIDFILE in the init script must match the pidfile in the config if you wish to use the init script

Admins:
to set up your user as an admin, edit the admin directory in the sqlite database (this database is created either by the daemon running, or the first time someone accesses the website.  The following command will add a user for you (bath.db should be owned by apache user, so you need to run this with root priveleges)

sqlite3 bath.db "INSERT INTO admin VALUES('ADMINUSER', 1);"

ISSUES

sudo -n: some versions of sudo do not like not having a tty allocated. To get around this, use 'sudo -n'

hanging process (iptables, /bin/sh) or no return values: Some older version of sudo (such as 1.7.4p4-2.squeeze.3 0) do not terminate properly. In Debian, this is fixed by backporting the Wheezy sudo package to squeeze. 1.8.3p2-1.1 is the version known to work.
