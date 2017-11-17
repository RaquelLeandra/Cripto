#!/usr/bin/env bash

openssl rsautl -decrypt -in raquel.leandra.perez_RSA_RW.enc -out raquel.leandra.perez_RSA_RW -inkey raquel.leandra.perez_RSA_RW.pem -pkcs

openssl rsautl -decrypt -in raquel.leandra.perez_RSA_pseudo.enc -out raquel.leandra.perez_RSA_pseudo -inkey raquel.leandra.perez_RSA_pseudo.pem -pkcs
