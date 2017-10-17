#ifndef KECCAK_FIPS202_H
#define KECCAK_FIPS202_H
#include <stdint.h>
#include <stdlib.h>


#define decsha3(bits) \
  int sha3_##bits(uint8_t*, size_t, const uint8_t*, size_t);

decsha3(256)
decsha3(512)

#endif
