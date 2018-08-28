// Copyright (c) 2016-2018 The LoMoCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef  WALLEVE_BIGUINT_H
#define  WALLEVE_BIGUINT_H

#include <stdlib.h>
#include <stdint.h>

typedef union
{
    uint8_t u8[160/8];
    uint8_t u32[160/32];
}uint160_t;

typedef union
{
    uint8_t u8[256/8];
    uint8_t u32[256/32];
    uint64_t u64[256/64];
}uint256_t;

#define UINT160_ZERO ((uint160_t) { .u32 = { 0, 0, 0, 0, 0 } })
#define UINT256_ZERO ((uint256_t) { .u64 = { 0, 0, 0, 0 } })
#define UINT160_ISZERO(u) ((u).u32[0] == 0 && (u).u32[1] == 0 && (u).u32[2] == 0 && (u).u32[3] == 0 && (u).u32[4] == 0)
#define UINT256_ISZERO(u) ((u).u64[0] == 0 && (u).u64[1] == 0 && (u).u64[2] == 0 && (u).u64[3] == 0)

inline int wl_uint160_compare(uint160_t a,uint160_t b)
{
    int i = 0,d = 0;
    while (i < 20 && (d = a.u8[i] - b.u8[i]) == 0) i++;
    return d;
}

inline int wl_uint256_compare(uint256_t a,uint256_t b)
{
    int i = 0,d = 0;
    while (i < 32 && (d = a.u8[i] - b.u8[i]) == 0) i++;
    return d;
}

inline uint256_t wl_uint256_rshift(uint256_t a)
{
    int i = 0;
    uint256_t r;

    r.u8[i] = a.u8[i] >> 1; i++;
    while (i < 32)
    {
        r.u8[i] = (a.u8[i] >> 1) | (a.u8[i - 1] << 7); i++;
    }
    return r;
}

inline uint256_t wl_uint256_minus(uint256_t a,uint256_t b)
{
    int i,d,carry = 0;
    uint256_t r;

    for (i = 31;i >= 0;i--)
    {
        d = 0x100 + a.u8[i] - b.u8[i] - carry;
        r.u8[i] = d & 0xff;
        carry = (d >> 8) ^ 1;
    }
    return r;
}

void wl_uint160_fromhex(uint160_t *u,const char *hex);
void wl_uint256_fromhex(uint256_t *u,const char *hex);

int wl_uint160_tohex(uint160_t *u,char *hex,size_t size);
int wl_uint256_tohex(uint256_t *u,char *hex,size_t size);

int wl_uint160_tohex_compact(uint160_t *u,char *hex,size_t size);
int wl_uint256_tohex_compact(uint256_t *u,char *hex,size_t size);
int wl_uintx_tohex(uint8_t *u, size_t len, char *hex, size_t size);
#endif //WALLEVE_BIGUINT_H
