#!/bin/sh

rm -f $1.enc
sync
../userspace_test/basic/basic $1 $1.enc A 1
sync

