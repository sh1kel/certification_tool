#!/bin/bash
set -e

function clean {
	local dirname=$1
	if test -e "$dirname" ; then
		rm -rf "$dirname"
	fi
}

function extract {
	local tempo_folder=$1

	ARCHIVE=`awk '/^__ARCHIVE_BELOW__/ {print NR + 1; exit 0; }' $0`

	mkdir "$tempo_folder"

	tail -n+$ARCHIVE $0 > /tmp/bin.tgz
	tail -n+$ARCHIVE $0 | tar xzv -C $tempo_folder >/dev/null
}

function usage {
	echo "CERT_TOOL_SHELL FUEL_URL FUEL_CREDENTIALS"
}

# function check_params {
# 	local fuel_url="$1"
# 	local credentials="$2"

# 	if test -z "$fuel_url" || -z "$credentials" ; then
# 		echo "Some parameter missing"
# 		usage "$app_name"
# 		exit 1
# 	fi

# 	# move this test to python code
# 	if [[ ${fuel_url:0:7} != "http://" ]] ; then
# 		echo "Fuel url should be http://IP:PORT"
# 		usage "$app_name"
# 		exit 1
# 	fi

# 	# move this test to python code
# 	local fuel_ip=$(echo "${fuel_url:7}" | sed 's/:.*//')
# 	if ! wget -qS -O- "$fuel_url" &> /dev/null ; then
# 		echo "Fuel isn't available. Cant ping $fuel_ip"
# 		usage "$app_name"
# 		exit 1
# 	fi

# 	# test python available
# }

function main {
	# local fuel_url="$1"
	# local credentials="$2"

	echo "Using fuel installation $1 with credentials $2"

	local tempo_folder=$(tempfile -p "fuel-")
	rm $tempo_folder

	# check_params $@

	clean "$tempo_folder"
	extract "$tempo_folder"

	# PYTHONPATH="$tempo_folder:$PYTHONPATH" python -m certification_tool -a "$credentials" "$fuel_url"
	PYTHONPATH="$tempo_folder:$PYTHONPATH" python -m certification_tool $@

	clean "$tempo_folder"
}

main $@


__ARCHIVE_BELOW__
