#!/bin/sh

echo Setting up...

dd if=/dev/zero of=100M.bin bs=1024 count=102400 &> /dev/null
echo "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" > A.bin

for i in $(seq 64 128)
do
	dd if=/dev/urandom of=rand.$i.bin bs=1 count=$i &> /dev/null
done

sync

