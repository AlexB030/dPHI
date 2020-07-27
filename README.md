# dPHI
This repository is related to the paper __dPHI: An improved high-speed network-layer anonymity protocol__ published at PETS 2020.
It serves the purpose of enabling others to reproduce our findings with regard to:

1. performance measuring of the cryptographic operations of our anonymous routing protocol
2. the Matlab code and data for the quantitative anonymity analysis of dPHI, LAP and HORNET (see paper for all related measures)

While instructions on how to get the C-implementation up and running _(i.)_ are presented in the following, the Matlab scripts for analysis _(ii.)_, including a dedicated readme-file on how to use them, can be found in the subfolder _analysis_.

___Note:___ When using this code or parts of it, please cite our related [publication](https://www.petsymposium.org/2020/files/papers/issue3/popets-2020-0054.pdf)!


The code for performance measuring of cryptographic operations is not self-contained but requires other libraries to work. In the following we will provide an outline on how to setup an environment in which our code may be compiled and the resulting binary executed.

## Using Docker
Should you do not feel like setting up a build environment, downloading all sources and compiling them, you can take a shortcut and download the ready-made docker image and run our code from wihtin a container. However, keep in mind, that the performance measurement results are impacted by the additional layer of abstraction introduced by docker.

If you want to use our docker image, proceed as follows. Otherwise, for the manual setup, skip this section and proceed directly to the next section "Prerequisites".
### Download and setup
It is assumed that you have docker up and running:

1. Download the docker image [file](https://www.dropbox.com/s/w8gb2d532c2pi45/ubuntu_dphi.7z?dl=0)
2. Unzip the archive `7za x ubuntu_dphi.7z`
3. Load the image into your list of available docker images with 
`docker load < ubuntu_dphi.tar`
4. Create and run container through `docker run -it ubuntu_dphi`
5. Go to subfolder where build script is located `cd /root/dPHI/isa-l_crypto/`
6. Compile dPHI through `./dphi.sh`
7. Run tests with `aes/dphi`

The plain sequence of commands is:
```
7za x ubuntu_dphi.7z
docker load < ubuntu_dphi.tar
docker run -it ubuntu_dphi
cd /root/dPHI/isa-l_crypto/
./dphi.sh
aes/dphi
```




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
1. Following are tests for the GCM operations of isa-l_crypto:
SEED: 4660
AES-GCM standard test vectors new api:
Standard vector new api 0/10  Keylen:16 IVlen:12 PTLen:48 AADlen:28 Tlen:16
Standard vector new api 1/10  Keylen:16 IVlen:12 PTLen:42 AADlen:20 Tlen:16
Standard vector new api 2/10  Keylen:16 IVlen:12 PTLen:16 AADlen:16 Tlen:16
Standard vector new api 3/10  Keylen:16 IVlen:12 PTLen:32 AADlen:16 Tlen:16
Standard vector new api 4/10  Keylen:16 IVlen:12 PTLen:32 AADlen:16 Tlen:16
Standard vector new api 5/10  Keylen:16 IVlen:12 PTLen:16 AADlen:0 Tlen:16
Standard vector new api 6/10  Keylen:16 IVlen:12 PTLen:64 AADlen:0 Tlen:16
Standard vector new api 7/10  Keylen:16 IVlen:12 PTLen:60 AADlen:20 Tlen:16
Standard vector new api 8/10  Keylen:32 IVlen:12 PTLen:16 AADlen:0 Tlen:16
Standard vector new api 9/10  Keylen:32 IVlen:12 PTLen:64 AADlen:0 Tlen:16
Standard vector new api 10/10  Keylen:32 IVlen:12 PTLen:60 AADlen:20 Tlen:16

...Pass


2. Session establishment with help of the dPHI protocol for one pre-determined path:
M: SID and PubS fit
M: auth tags ok
S and M derived identical Session Key
M: correct Destination recovered
M: correct Nonce recovered
Node 6: valid auth tag
Node 5: valid auth tag
Node 4: valid auth tag
Node 3: valid auth tag
Node 2: valid auth tag
Node 1: valid auth tag
S and W have identical Nonce
S got Midway_Reply with correct SID
S got Midway_Reply with correct H.pos
S could verify H.midway
Node 1: correct posV1 recovered
Node 2: correct posV1 recovered
Node 3: correct posV1 recovered
W: H.dest successfully reconstructed
D: SID and PubS fit
D: Decrypt V1 with correct Tag
D: Assert V1 OK
W: Pos ok
Node 3: valid auth tag
Node 2: valid auth tag
Node 1: valid auth tag
S: TAG from V1||V2 ok
S: V1 is correct
S: V2 is correct
Node 1: correct posV1 recovered
Node 2: correct posV1 recovered
Node 3: correct posV1 recovered
W: correct posV1 recovered
W: MAC V1||V2 correct
Node 8: correct posV2 recovered
Node 9: correct posV2 recovered
Node 10: correct posV2 recovered
Node 11: correct posV2 recovered
Node 12: correct posV2 recovered


3. Performance measurement of the single operations as presented in the paper:
(All values represent averages of the middle quarter of all measurements for said protocol step)

Midway Request for A != M:	 424
Midway Request for A == M:	 149981
Backtracking for A != W:	 151
Backtracking for A == W:	 1779
Handshake to d for A == W:	 1593
Handshake to d for A != W:	 434
Handshake reply to s for A != W: 149
Handshake reply to s for A == W: 1298
Transmission phase for A != W:	 155
Transmission phase for A == W:	 320
```
This performs (1) tests of the underlying cryptographic operations provided by Intel's library, (2) executes one complete handshake of our protocol and (3) gives the averaged number of cycles for the middle quartile of measurements for performing the respective operation of the protocol for 1,000,000 times.

## Remarks
From a technical point of view, there is no need to copy any files into any other folder structure. However, our build script is not very sophisticated so that manually copying files appeared simpler.
