# dPHI
This repository is related to the paper __dPHI: An improved high-speed network-layer anonymity protocol__ published at PETS 2020.
It serves the purpose of enabling others to reproduce our findings with regard to:

1. performance measuring of the cryptographic operations of our anonymous routing protocol 
2. the Matlab code and data for the quantitative anonymity analysis of dPHI, LAP and HORNET (see paper for all related measures)

While instructions on how to get the C-implementation up and running _(i.)_ are presented in the following, the Matlab scripts for analysis _(ii.)_, including a dedicated readme-file on how to use them, can be found in the subfolder _analysis_. 

___Note:___ When using this code or parts of it, please cite our related publication!


The code for performance measuring of cryptographic operations is not self-contained but requires other libraries to work. In the following we will provide an outline on how to setup an environment in which our code may be compiled and the resulting binary executed.



## Prerequisites
The following instructions assume that you run a fresh installation of Ubuntu 18.04 Desktop (either native or virtualized) and have these packages installed:

* build-essential
* nasm
* autoconf
* libtool

If not, install them via:
```
sudo apt update
sudo apt install build-essential nasm autoconf libtool git
```
Of course, you are not forced to use Ubuntu or any other Linux for that matter. However, our instructions have been tested and verified to work in this setting.

## Automated setup
You may choose to have everything setup automatically, instead of downloading and compiling things yourself.
In the repository's main directory, there is a shell-script `setup.sh`. Call this to download all needed files and perform operations needed to run our sample.

```
./setup.sh
```
If you took the automated setup, you may scroll down to the end of the readme file and proceed with __"Running our sample"__.
Otherwise, if you want to do things manually, just go on with the next steps.

## Get Intel's ISA-L crypto Library
The cryptographic operations that are performed in our sample code rely on this library for the performance advantages that result from using Intel's cryptographic coprocessor. It can be found on Github via [https://github.com/intel/isa-l_crypto/](https://github.com/intel/isa-l_crypto/). Clone it or download and unpack the ZIP archive from there. The following command line instructions assume that you unpacked or cloned the repository to `/home/demo/isa-l_crypto/`. If not, please adapt commands accordingly.

Configure and compile with the follwoing commands:
```
cd /home/demo/isa-l_crypto/
# optional: git checkout 800e7f8
./autogen.sh
./configure
make
make check
```
`make check` will compile some additional files that we will need (e.g. SHA256 reference implementation).
___Should the above operations fail, retry after checking out the specified commit!___

## Get curve25519-donna Library
This library is used for Diffie-Hellman key agreement and is also hosted on Github [https://github.com/agl/curve25519-donna](https://github.com/agl/curve25519-donna). Again, either clone the repository or download and unpack the ZIP archive. Either way, the following command line instructions assume you cloned or unpacked to `/home/demo/curve25519-donna/`.

Now we compile and copy the library to the location where our build script expects it:
```
cd /home/demo/curve25519-donna
# optional: git checkout f7837ad;
make curve25519-donna-c64.o
mkdir /home/demo/isa-l_crypto/curve25519
cp /home/demo/curve25519-donna/curve25519-donna-c64.o /home/demo/isa-l_crypto/curve25519/
```
___Should the above operations fail, retry after checking out the specified commit!___
## Compiling our sample

Compiling is done with help of the provided shell script `dphi.sh`. Copy this to `/home/demo/isa-l_crypto/`, that is, if you followed our recommendation with regard to folder naming. Please make sure, that this script is executable. The file containing our sample code `dphi.c` must be copied to `/home/demo/isa-l_crypto/aes/`.
```
cp dphi.sh /home/demo/isa-l_crypto/
cp dphi.c /home/demo/isa-l_crypto/aes/
chmod +x /home/demo/isa-l_crypto/dphi.sh
```

As soon as this is done, compile our sample code with:
```
/home/demo/isa-l_crypto/dphi.sh
```
Warnings that are shown during compilation refer to unused variables. These can be used to extend what is being measured. However, they are not used in this version as respective operations are commented out.

## Running our sample
Now you can run our sample by calling:
_(Adapt the path to fit your environment.)_
```
/home/demo/isa-l_crypto/aes/dphi
```
The only output that will be produced when calling this, is a line like:
```
AVG of middle quarter: 463
```
This line gives the averaged number of cycles for the middle quartile of measurements for performing the first operation of our protocol for 1,000,000 times. How to measure other steps in the protocol is documented within `dphi.c` and requires manually changing the code at designated positions.

## Remarks
From a technical point of view, there is no need to copy any files into any other folder structure. However, our build script is not very sophisticated so that manually copying files appeared simpler.
