#!/bin/sh

for i in $(seq 100 105)
do
	dd if=/dev/zero of=zero.$i.bin bs=1024000 count=$i > /dev/null 2>&1
done

sync

