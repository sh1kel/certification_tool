#!/bin/bash

set -o errexit

# -----BEGIN_BUNDLE_BODY-----
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
    tail -n+$ARCHIVE $0 | tar xzv -C $tempo_folder >/dev/null
}

function extract_base64 {
    local bundle=$0
    local tempo_folder=$1
    mkdir -p "$tempo_folder"
    awk '
$2 == "-----END_BUNDLE_ARCHIVE-----" {exit}
f == 1 {print $2; next}
$2 == "-----BEGIN_BUNDLE_ARCHIVE-----" {f=1;next}
' "${bundle}" | base64 -d | tar xzv -C "${tempo_folder}"
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
    local tempo_folder=$(mktemp -p /tmp fuel-XXXXXXXX)
    rm $tempo_folder

    # check_params $@

    clean "$tempo_folder"
    extract_base64 "$tempo_folder"

    PYTHONPATH="$tempo_folder:$PYTHONPATH" python $tempo_folder/certification_tool/main.py $@

    clean "$tempo_folder"
}

main $@

exit 0
# -----END_BUNDLE_BODY-----

__ARCHIVE_BELOW__
