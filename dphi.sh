#!/bin/bash

rm -f aes/dphi;
rm -f aes/dphi.o;

depbase=`echo aes/dphi.o | sed 's|[^/]*$|.deps/&|;s|\.o$||'`;

gcc -DPACKAGE_NAME=\"libisal_crypto\" -DPACKAGE_TARNAME=\"isa-l_crypto\" -DPACKAGE_VERSION=\"2.22.0\" -DPACKAGE_STRING=\"libisal_crypto\ 2.22.0\" -DPACKAGE_BUGREPORT=\"sg.support.isal@intel.com\" -DPACKAGE_URL=\"http://01.org/storage-acceleration-library\" -DPACKAGE=\"isa-l_crypto\" -DVERSION=\"2.22.0\" -DSTDC_HEADERS=1 -DHAVE_SYS_TYPES_H=1 -DHAVE_SYS_STAT_H=1 -DHAVE_STDLIB_H=1 -DHAVE_STRING_H=1 -DHAVE_MEMORY_H=1 -DHAVE_STRINGS_H=1 -DHAVE_INTTYPES_H=1 -DHAVE_STDINT_H=1 -DHAVE_UNISTD_H=1 -D__EXTENSIONS__=1 -D_ALL_SOURCE=1 -D_GNU_SOURCE=1 -D_POSIX_PTHREAD_SEMANTICS=1 -D_TANDEM_SOURCE=1 -DHAVE_DLFCN_H=1 -DLT_OBJDIR=\".libs/\" -DHAVE_AS_KNOWS_AVX512=1 -DHAVE_AS_KNOWS_SHANI=1 -DHAVE_LIMITS_H=1 -DHAVE_STDINT_H=1 -DHAVE_STDLIB_H=1 -DHAVE_STRING_H=1 -DHAVE_STDLIB_H=1 -DHAVE_MALLOC=1 -DHAVE_MEMMOVE=1 -DHAVE_MEMSET=1 -I.    -Wall -Wchar-subscripts -Wformat-security -Wnested-externs -Wpointer-arith -Wshadow -Wstrict-prototypes -Wtype-limits  -I ./include/ -I ./sha1_mb -I ./mh_sha1 -I ./md5_mb -I ./sha256_mb -I ./sha512_mb -I ./mh_sha1_murmur3_x64_128 -I ./mh_sha256 -I ./rolling_hash -I ./sm3_mb -I ./aes   -g -O2 -MT aes/dphi.o -MD -MP -MF $depbase.Tpo -c -o aes/dphi.o aes/dphi.c;

mv -f $depbase.Tpo $depbase.Po;



/bin/bash ./libtool --silent --tag=CC   --mode=link gcc -Wall -Wchar-subscripts -Wformat-security -Wnested-externs -Wpointer-arith -Wshadow -Wstrict-prototypes -Wtype-limits  -I ./include/ -I ./sha1_mb -I ./mh_sha1 -I ./md5_mb -I ./sha256_mb -I ./sha512_mb -I ./mh_sha1_murmur3_x64_128 -I ./mh_sha256 -I ./rolling_hash -I ./sm3_mb -I ./aes   -g -O2   -o aes/dphi aes/dphi.o sha256_mb/sha256_ref.o curve25519/curve25519-donna-c64.o libisal_crypto.la;
