// Copyright (c) 2016-2018 The LoMoCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef  WALLEVE_HEX_H
#define  WALLEVE_HEX_H
#include <stdlib.h>
#include <stdint.h>

inline int wl_hex_to_int(const char c)
{
    if (c >= '0' && c <= '9')
    {
        return (c - '0');
    }
    if (c >= 'a' && c <= 'f')
    {
        return (c - 'a' + 10);
    }
    if (c >= 'A' && c <= 'F')
    {
        return (c - 'A' + 10);
    }
    return -1;
}

inline char wl_hex_to_char(const uint8_t u)
{
    uint8_t n = u & 15;
    return (n < 10 ? '0' + n : 'a' + (n - 10));
}

#endif //WALLEVE_HEX_H
