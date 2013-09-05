#!/usr/bin/env bash

# TODO:
# - Check for required packages
# - Include Apache setup

# Check if root
if [[ $(whoami) != 'root' ]]; then
  echo "You must run this script as root."
  exit 1
fi

# Prepare
CODE_DIR=$(dirname $(readlink -en $0))
BATH_DIR="/var/lib/bath"
cd ${CODE_DIR}

sudo_version=$(sudo -V | awk '/Sudo version/ {print $3}')
if [[ ${sudo_version} < "1.7.8p2" ]]; then
  echo "You must use a version of sudo >= 1.7.8p2"
  exit 1
fi

apache_version=$(dpkg-query --show --showformat='${Version}' apache2 2>/dev/null)
apache_mod_python_version=$(dpkg-query --show --showformat='${Version}' libapache2-mod-python 2>/dev/null)
if [[ -z ${apache_version} || -z ${apache_mod_python_version} ]]; then
  echo "Apache >= 2.2 and libapache2-mod-python must be installed."
  exit 1
fi

if ! id -u www-data &> /dev/null; then
  echo "The www-data user does not exist."
  exit 1
fi

# Check sudoers file
SECURE_PATH_REGEX='Defaults(\s+)secure_path'
CREATESSH_ALIAS_REGEX='Cmnd_Alias(\s+)CREATESSH'
ADDSSH_ALIAS_REGEX='Cmnd_Alias(\s+)ADDSSH'
DELSSH_ALIAS_REGEX='Cmnd_Alias(\s+)DELSSH'
SHOWSSH_ALIAS_REGEX='Cmnd_Alias(\s+)SHOWSSH'

if ! grep -qE "${SECURE_PATH_REGEX}" /etc/sudoers &&
     grep -qE "${CREATESSH_ALIAS_REGEX}" /etc/sudoers &&
     grep -qE "${ADDSSH_ALIAS_REGEX}" /etc/sudoers &&
     grep -qE "${DELSSH_ALIAS_REGEX}" /etc/sudoers &&
     grep -qE "${SHOWSSH_ALIAS_REGEX}" /etc/sudoers; then
  echo "The sudoers file needs to be modified. See the README for what must be changed."
  exit 1
fi

# Check hosts file
invalid_hosts=false
for h in $(grep ${HOSTNAME} /etc/hosts | awk '{ print $1 }'); do
  if [[ ${h} =~ ^127\. ]]; then
    echo "Invalid hosts file entry: ${h}"
    invalid_hosts=true
  fi
done
if [[ ${invalid_hosts} == true ]]; then
  echo "The hosts file needs to be modified. See the README for what must be changed."
  exit 1
fi

echo "Copying files..."
rsync -rv ${CODE_DIR}/etc/ /
rsync -rv ${CODE_DIR}/var /

chown -R www-data:www-data ${BATH_DIR}

echo "Enabling Apache modules..."
a2enmod ssl
a2enmod python

# Ensure Apache listens on 443
if ! grep -qE 'Listen +443' /${APACHE_DIR}/ports.conf || \
  echo 'Listen 443' >> /${APACHE_DIR}/ports.conf

echo "Disabling 000-default and enabling bath-ssl vhosts..."
a2dissite 000-default
a2ensite bath-ssl

echo "Reloading Apache..."
service apache2 reload

echo "Starting bathd..."
service bathd start
