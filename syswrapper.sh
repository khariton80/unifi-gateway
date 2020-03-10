#!/bin/sh
log=/usr/local/share/unifi/logs/log_file.txt
#/usr/bin/syswrapper.sh
echo "=================================" >>$log

echo "Quoted DOLLAR-AT" >>$log
for ARG in "$@"; do
    echo $ARG >>$log
done

echo "=================================" >>$log
python2 /usr/local/share/unifi/unifi_console.py $1 -s $2 -k $3   >>$log