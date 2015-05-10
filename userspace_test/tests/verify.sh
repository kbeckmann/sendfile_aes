#!/bin/sh

echo Verifying...

for i in $(ls -1 rand.*.bin) A.bin 100M.bin
do
#	echo "  Verifying $i"
	$SHELL test_basic.sh $i
	$SHELL test_openssl.sh $i
	diff $i.enc $i.openssl &> /dev/null || echo -e "\n    ERROR: $i differ\n"
done

