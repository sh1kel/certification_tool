#!/bin/sh
set -e
set -x

CERT_PATH=$1

SCRIPT_TEMPL='run_tool.sh'
RESULT=`tempfile`
TMP_ARCHIVE_PATH=`tempfile`

cd `dirname $CERT_PATH`
tar -pczf "$TMP_ARCHIVE_PATH" `basename $CERT_PATH`
cd -

cp "$SCRIPT_TEMPL" "$RESULT"
cat "$TMP_ARCHIVE_PATH" >> "$RESULT"

# rm "$TMP_ARCHIVE_PATH"

echo "$TMP_ARCHIVE_PATH"
echo "store result in $RESULT"
