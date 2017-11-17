#!/usr/bin/env bash

path="../RSA_RW-20171114"

for file in "$path"/*; do
    echo $file
    openssl rsa -inform PEM -pubin  -in $file -modulus > $file$".key"
done
