#!/bin/sh
set -e

SRC=$1
SCRIPT='run_tool.sh'
TMP_ARCHIVE_NAME='tmp.tar.gz'

tar -pczf $TMP_ARCHIVE_NAME $SRC
cat $TMP_ARCHIVE_NAME >> $SCRIPT

rm $TMP_ARCHIVE_NAME