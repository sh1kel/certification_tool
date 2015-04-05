#!/bin/sh
set -x
set -e 
set -o pipefail

function on_fuel() {
	cd /tmp
	NAILGUN_CONT_ID=`docker ps | grep nailgun | awk '{print $1}'`
	rm -rf /tmp/certification_script
	docker cp $NAILGUN_CONT_ID:/usr/lib/python2.6/site-packages/certification_script /tmp
	export PYTHONPATH="$PYTHONPATH:/tmp"
	python certification_script/main.py -s AUTO
	python certification_script/main.py -r
}

function copy_code_and_run() {
	FNAME=/tmp/cert.exp
	echo "set timeout 120" > $FNAME
	echo "spawn scp $0 root@10.20.0.2:/tmp" >> $FNAME
	echo 'expect "password:"' >> $FNAME
	echo "send r00tme\n;" >> $FNAME
	echo "interact" >> $FNAME
	echo 'spawn ssh root@10.20.0.2 bash /tmp/dump.sh' >> $FNAME
	echo 'expect "password:"' >> $FNAME
	echo "send r00tme\n;" >> $FNAME
	echo "interact" >> $FNAME
	expect $FNAME
	rm $FNAME
}

if [ "$HOSTNAME" == "fuel.domain.tld" ] ; then
	on_fuel
else
	copy_code_and_run
fi

