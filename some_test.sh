#!/bin/bash

# WARNING!  This file is auto updated from the node manager.  Any changes will
# be lost when the client disconnects and reconnects.
#
# Grab the specified git source tree or rpm (when functionality added),
# build it and run the specified plugin with the supplied uri and password

if [ "$#" -ne 5 ]; then
    echo "syntax: ci_unit_test.sh [git|rpm] path/repo ver/branch <array uri> <array password>"
    exit 1
fi

what=$1
loc=$2
ver=$3
uri=$4
pw=$5

echo "$what : $loc : $ver : $uri : $pw"

sleep 5

exit 0
