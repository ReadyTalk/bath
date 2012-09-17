#!/bin/bash

function usage() {
  cat <<EOF
usage: $(basename ${0}) options

Monitor script for Bath

OPTIONS:
  -h  Show this message
  -t  last check time in seconds since the epoch
EOF

  exit 2
}

lastTime=0

while getopts "ht:" OPTION
do
  case ${OPTION} in
    h)
      usage
      ;;
    t)
      lastTime=$OPTARG
      ;;
  esac
done

if [[ -z "$(command -v curl)" ]]; then
	echo "curl not found"
  exit 2
fi 

return=$($(command -pv curl) --silent --insecure "https://localhost/bath/index.py?time=${lastTime}")
echo $return

if [[ $return =~ '^SUCCESS' ]]; then
	exit 0
else
	exit 2
fi
