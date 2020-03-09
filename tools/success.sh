#!/bin/bash

/bin/dd if=/dev/urandom bs=512 count=1 | xxd
sleep 10
/bin/dd if=/dev/urandom bs=512 count=1 | xxd

exit 0
