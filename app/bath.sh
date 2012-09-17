#!/bin/bash

set -e

# you can define username here
# if this line is commented, you will be prompted for user
user="$(whoami)"
ip=
comment=
service='ssh'
host=''

##################################################
# Hit the bath web service from the command line #
##################################################

function usage() {
  cat <<EOF
usage: $(basename ${0}) options

This script will authenticate to the bath webservice

OPTIONS:
  -h  Show this message
  -d  host to connect to
  -c  comment
  -i  ip address to allow in authentication
  -l  execute connection to service if authenticated
  -u  user for authentication (defaults to whoami)
	-k  curl insecure mode
EOF
	
	exit 99
}

while getopts "hld:c:i:u:k" OPTION
do
	case ${OPTION} in
		h)
			usage
			;;
		d)
			host=$OPTARG
			;;
		c)
			comment=$OPTARG
			;;
		i)
			ip=$OPTARG
			;;
		l)
			login=true
			;;
		u)
			user=$OPTARG
			;;
		k)
			secure="--insecure"
	esac
done

if [[ -z "$(command -v curl)" ]]; then
	echo "curl not found. Please ensure that curl is installed an in your path"
	exit 2
fi 

if [[ -z "${host}" ]]; then
  echo -e "host: \c "
  read host
fi

# URL for the service
url="https://${host}/"

if [[ -z "${comment}" ]]; then
	echo -e "comment: \c "
	read comment
fi

if [[ -z "${user}" ]]; then
  echo -e "user: \c "
  read user
fi

content="--data-urlencode output=text"

if [[ ! -z "${comment}" ]]; then
	content="${content} --data-urlencode \"comment=${comment}\""
fi

if [[ ! -z "${ip}" ]]; then
	content="${content} --data-urlencode ip=${ip}"
fi

echo "where:    ${host}"
echo "for:      ${ip}"
echo "using:    ${user}"
echo "comments: ${comment}"

eval $(command -pv curl) ${secure} --silent --show-error --user ${user} ${content} "${url}"

if [[ $? != 0 ]]; then
	echo "########"
	echo "# FAIL #"
	echo "########"
	exit 1;
fi
