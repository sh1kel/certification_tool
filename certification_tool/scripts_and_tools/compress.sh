#!/bin/sh

set -o errexit

CERT_PATH=${1:-../src}

if [ -z "${CERT_PATH}" ]; then
    exit
fi

SCRIPT_TEMPL='run_tool.sh'
RESULT=$(mktemp -p /tmp fuel-XXXXXXXX.sh)

{
    cat << EOF
#!/bin/bash

set -o errexit

EOF

    awk '
$2 == "-----END_BUNDLE_BODY-----" {print $0; exit}
f == 1 {print $0; next}
$2 == "-----BEGIN_BUNDLE_BODY-----" {f=1; print $0; next}
' "${SCRIPT_TEMPL}"

    echo ''
    echo '# -----BEGIN_CHANGELOG-----'
    git log --pretty=format:"[%an]%n%h  %cd%n*  %s%n" -n 10 \
      | awk '{print "# " $0}'
    echo '# -----END_CHANGELOG-----'

    echo ''
    echo '# -----BEGIN_BUNDLE_ARCHIVE-----'
    tar -cz -C "${CERT_PATH}" . | base64 \
      | awk '{print "# " $0}'
    echo '# -----END_BUNDLE_ARCHIVE-----'
} > "${RESULT}"

echo "store result in '${RESULT}'"

