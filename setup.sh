#!/bin/bash

WDIR=$(pwd);

echo $WDIR;

#clone repos
git clone https://github.com/intel/isa-l_crypto.git $WDIR/isa-l_crypto;
cd $WDIR/isa-l_crypto/;
git checkout 800e7f8;

git clone https://github.com/agl/curve25519-donna.git $WDIR/curve25519-donna;
cd $WDIR/curve25519-donna/;
git checkout f7837ad;


#build intel crypto library
cd $WDIR/isa-l_crypto/;
./autogen.sh;
$WDIR/isa-l_crypto/configure;
make;
make check;


#compiling curve25519-donna
cd $WDIR/curve25519-donna;
make curve25519-donna-c64.o;
mkdir $WDIR/isa-l_crypto/curve25519;
cp $WDIR/curve25519-donna/curve25519-donna-c64.o $WDIR/isa-l_crypto/curve25519/;

# compile dphi
cp $WDIR/dphi.sh $WDIR/isa-l_crypto/;
cp $WDIR/dphi.c $WDIR/isa-l_crypto/aes/;
chmod +x $WDIR/isa-l_crypto/dphi.sh;

cd $WDIR/isa-l_crypto/;
./dphi.sh;
