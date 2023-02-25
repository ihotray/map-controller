#!/bin/bash

DIRS="src/core src/include src/ipc src/utils "

rm -rf coding_style.log
touch coding_style.log
for dir in $DIRS; do
	scripts/checkpatch.pl -f --no-tree --no-signoff --ignore CONST_STRUCT,SPDX_LICENSE_TAG,LINE_CONTINUATIONS $dir/*.h $dir/*.c >> coding_style.log 2>1
done

cat coding_style.log

cat coding_style.log | grep -q "ERROR: "

[ "$?" == 0 ] && exit 1

exit 0
