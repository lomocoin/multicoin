// Copyright (c) 2016-2018 The LoMoCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "biguint.h"
#include "hex.h"

static inline void wl_uint_fromhex(uint8_t *u,size_t len,const char *hex)
{
    const char *c = hex;
    uint8_t *p = u + len - 1;    
    
    if (hex != NULL)
    {
        while (wl_hex_to_int(*c) >= 0)
        {
            c++;
        }
    }
    while (--c >= hex && p >= u)
    {
        int l = wl_hex_to_int(*c--);
        int h = (c >= hex ? wl_hex_to_int(*c) : 0);
        *p-- = (h << 4) + l;
    }
    while (p >= u)
    {
        *p-- = 0;
    }
}

static inline int wl_uint_tohex(uint8_t *u,size_t len,char *hex,size_t size)
{
    if (size < len * 2 + 1)
    {
        return -1;
    }
   
    while (len--)
    {
        *hex++ = wl_hex_to_char(*u >> 4); 
        *hex++ = wl_hex_to_char(*u & 15);
        u++;
    } 
    *hex = '\0';
    return 0;
}

void wl_uint160_fromhex(uint160_t *u,const char *hex)
{
    wl_uint_fromhex(u->u8,20,hex);
}

void wl_uint256_fromhex(uint256_t *u,const char *hex)
{
    wl_uint_fromhex(u->u8,32,hex);
}

int wl_uint160_tohex(uint160_t *u,char *hex,size_t size)
{
    return wl_uint_tohex(u->u8,20,hex,size);
}

int wl_uint256_tohex(uint256_t *u,char *hex,size_t size)
{
    return wl_uint_tohex(u->u8,32,hex,size);
}

int wl_uint160_tohex_compact(uint160_t *u,char *hex,size_t size)
{
    uint8_t *p = u->u8;
    while (p < u->u8 + 19 && *p == 0)
    {
        p++;
    }
    return wl_uint_tohex(p,20 - (p - u->u8),hex,size);
}

int wl_uint256_tohex_compact(uint256_t *u,char *hex,size_t size)
{
    uint8_t *p = u->u8;
    while (p < u->u8 + 31 && *p == 0)
    {
        p++;
    }
    return wl_uint_tohex(p,32 - (p - u->u8),hex,size);
}

int wl_uintx_tohex(uint8_t *u, size_t len, char *hex, size_t size)
{
    return wl_uint_tohex(u, len, hex, size);
}
