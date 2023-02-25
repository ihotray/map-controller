#!/bin/bash
set -e
echo "compile warns stage"

pwd

cd src/
make "CFLAGS+=-I/usr/include/libnl3 -Werror -Wall -DCONTROLLER_SYNC_DYNAMIC_CNTLR_CONFIG -DEASYMESH_VERSION=4 -Wno-deprecated-declarations"
