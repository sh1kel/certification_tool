#!/bin/sh
set -e
set -x

CERT_PATH=$1

SCRIPT_TEMPL='run_tool.sh'
RESULT=`mktemp -p /tmp fuel-XXXXXXXX.sh`
TMP_ARCHIVE_PATH=`mktemp -p /tmp fuel-XXXXXXXX`

cd `dirname $CERT_PATH`
tar -pczf "$TMP_ARCHIVE_PATH" `basename $CERT_PATH`
cd -

cp "$SCRIPT_TEMPL" "$RESULT"
cat "$TMP_ARCHIVE_PATH" >> "$RESULT"

rm "$TMP_ARCHIVE_PATH"
echo "store result in $RESULT"
