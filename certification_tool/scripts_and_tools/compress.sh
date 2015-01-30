#!/bin/sh
set -e
set -x

SRC=$1
PATH_TO_SRC=$2
SCRIPT='run_tool.sh'
TMP_ARCHIVE_NAME='tmp.tar.gz'

cd $PATH_TO_SRC

tar -pczf $TMP_ARCHIVE_NAME $SRC

cd -
cat "$2/$TMP_ARCHIVE_NAME" >> $SCRIPT

rm "$2/$TMP_ARCHIVE_NAME"
