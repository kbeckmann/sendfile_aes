#!/bin/sh

make && ./aes_test A

echo "A" > _A.txt

openssl enc -aes-256-cbc -in _A.txt -out encrypted.bin -K 4293209e7a4638be35c2c291533a3c0be4867b6bd766980458c02b3b029e7df6 -iv 09caa19c3940620b6b97a50a7e2a971d

xxd encrypted.bin

