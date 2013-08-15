#!/usr/bin/env bash

# TODO:
# - Check for required packages
# - Include Apache setup

# Check if root
who=`whoami`
if [[ $who != 'root' ]]
then
	echo "You must run this script as root."
    exit 1
fi

# Check if www-data user exists
id -u www-data &> /dev/null
if [[ $? -ne 0 ]]
then
	echo "The www-data user does not exist."
	exit 1
fi

# Check sudo version
sudo_version=`sudo -V | grep "Sudo version" | awk '{print $3}'`
if [[ sudo_version < "1.7.8p2" ]]
then
	echo "You must use a version of sudo >= 1.7.8p2"
	exit 1
fi

# Check sudoers file
SECURE_PATH_REGEX='Defaults(\s+)secure_path(\s*)=(\s*)"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"'
CREATESSH_ALIAS_REGEX='Cmnd_Alias(\s+)CREATESSH(\s*)=(\s*)/sbin/iptables -A INPUT -p tcp -m tcp --dport 22 -m state --state NEW -j REJECT -m comment --comment \*'
ADDSSH_ALIAS_REGEX='Cmnd_Alias(\s+)ADDSSH(\s*)=(\s*)/sbin/iptables -I INPUT -p tcp --dport 22 -m state --state NEW -j ACCEPT -s \*'
DELSSH_ALIAS_REGEX='Cmnd_Alias(\s+)DELSSH(\s*)=(\s*)/sbin/iptables -D INPUT -p tcp --dport 22 -m state --state NEW -j ACCEPT -s \*'
SHOWSSH_ALIAS_REGEX='Cmnd_Alias(\s+)SHOWSSH(\s*)=(\s*)/sbin/iptables -n -L INPUT'

egrep -q "${SECURE_PATH_REGEX}" /etc/sudoers
r1=$?
egrep -q "${CREATESSH_ALIAS_REGEX}" /etc/sudoers
r2=$?
egrep -q "${ADDSSH_ALIAS_REGEX}" /etc/sudoers
r3=$?
egrep -q "${DELSSH_ALIAS_REGEX}" /etc/sudoers
r4=$?
egrep -q "${SHOWSSH_ALIAS_REGEX}" /etc/sudoers
r5=$?
if [[ ${r1} -ne 0 ]] || [[ ${r2} -ne 0 ]] || [[ ${r3} -ne 0 ]] || [[ ${r4} -ne 0 ]] || [[ ${r5} -ne 0 ]]
then
	echo "The sudoers file needs to be modified. See the README for what must be changed."
	exit 1
fi

# Check hosts file
h=$(grep ${HOSTNAME} /etc/hosts | awk '{ print $1 }')
if [[ ${h} = "127.0.0.1" ]]
then
	echo "The hosts file needs to be modified. See the README for what must be changed."
	exit 1
fi

# Prepare
START_DIR=${PWD}
CODE_DIR=$(dirname $(realpath $0))
cd ${CODE_DIR}

# Copy files to correct locations
echo "Copying files..."

APACHE_DIR="etc/apache2"
SITES_AVAILABLE="${APACHE_DIR}/sites-available"
INIT_D="etc/init.d"
BATH_DIR="var/lib/bath"

cp -r ${SITES_AVAILABLE}/port443 /${SITES_AVAILABLE}/
cp -r ${INIT_D}/bath /${INIT_D}/

mkdir -p /${BATH_DIR}
cp -r ${BATH_DIR}/bath.conf /${BATH_DIR}/
cp -r ${BATH_DIR}/app /${BATH_DIR}/

chown -R www-data:www-data /${BATH_DIR}

# SSL
echo "Enabling SSL..."
cd /${APACHE_DIR}
a2enmod ssl

# Clear out ports.conf
echo "Removing everything in ports.conf (original saved as ports.conf.orig)..."
cp ports.conf ports.conf.orig
if [[ $? -ne 0 ]]
then
	echo ${PWD}
	exit 1
fi
echo > ports.conf

# Enable/disable sites
echo "Disabling 000-default and enabling port443..."
a2dissite 000-default
a2ensite port443

# Reload/restart apache
echo "Restarting Apache..."
/${INIT_D}/apache2 reload
/${INIT_D}/apache2 restart

cd ${START_DIR}