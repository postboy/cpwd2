#!/bin/sh
#compilation for long-time use just for me!

gcc -Wall -march=native -O1 main.c scrypt/readpass.c scrypt/crypto_scrypt-sse.c scrypt/sha256.c -o cpwd
