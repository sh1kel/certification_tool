#!/bin/sh
set -e
set -o pipefail

function clean() {
	local dirname=$1
	if test -e "$dirname" ; then
		rm -rf "$dirname"
	fi
}

function extract() {
	local tempo_folder=$1
	local archive=$2
	mkdir "$tempo_folder"
	pushd "$tempo_folder"
	tar -xjf "$archive"
	popd
}

function usage() {
	echo "CERT_TOOL_SHELL FUEL_URL FUEL_CREDENTIALS"
}

function check_params() {
	local app_name="$1"
	local archive="$2"
	local fuel_url="$3"
	local credentials="$4"

	if test -z "$archive" || -z "$fuel_url" || -z "$credentials" ; then
		echo "Some parameter missing"
		usage "$app_name"
		exit 1
	fi

	if ! test -r "$archive" ; then
		echo "$archive not found. Should be a file"
		usage "$app_name"
		exit 1
	fi

	# move this test to python code
	if [[ ${fuel_url:0:7} != "http://" ]] ; then
		echo "Fuel url should be http://IP:PORT"
		usage "$app_name"
		exit 1
	fi

	# move this test to python code
	local fuel_ip=$(echo "${fuel_url:7}" | sed 's/:.*//'
	if ! ping -n 3 "$fuel_ip" ; then
		echo "Fuel isn't available. Cant ping $fuel_ip"
		usage "$app_name"
		exit 1
	fi

	# test python available
}

function main() {
	local archive="$1"
	local fuel_url="$2"
	local credentials="$3"

	local tempo_folder=$(tempfile -p "fuel-")

	check_params $@
	rm $tempo_folder

	clean "$tempo_folder"
	extract "$tempo_folder" "$archive"

	PYTHONPATH="$tempo_folder:$PYTHONPATH" python -m certification_tool -a "$credentials" "$fuel_url"

	clean "$tempo_folder"
}

main $@
