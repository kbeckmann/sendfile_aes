#!/bin/sh

echo Setting up...

echo "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" > A.bin

for i in $(seq 0 128) $(seq 1024 1124)
do
	dd if=/dev/urandom of=rand.$i.bin bs=1 count=$i > /dev/null 2>&1
done

for i in $(seq 100 135)
do
	dd if=/dev/zero of=zero.$i.bin bs=1024000 count=$i > /dev/null 2>&1
done

sync

