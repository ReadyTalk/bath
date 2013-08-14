#! /usr/bin/env bash

# Must be root
who=`whoami`
if [[ $who != 'root' ]]
then
	echo "You must run this script as root."
    exit 1
fi

SITES_AVAIL="etc/apache2/sites-available"
INIT_D="etc/init.d"
BATH_DIR="var/lib/bath"

# Copy files to correct locations
cp -r ${SITES_AVAIL}/port443 /${SITES_AVAIL}/
cp -r ${INIT_D}/bath /${INIT_D}/

mkdir -p /${BATH_DIR}
cp -r ${BATH_DIR}/bath.conf /${BATH_DIR}/
cp -r ${BATH_DIR}/app /${BATH_DIR}/

chown -R www-data:www-data /${BATH_DIR}

# Reload/restart apache
/${INIT_D}/apache2 reload
/${INIT_D}/apache2 restart