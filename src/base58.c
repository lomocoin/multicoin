// Copyright (c) 2016-2018 The LoMoCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <string.h>
#include "base58.h"
#include "crypto.h"

static const char b58_code[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
static const int8_t b58_map[] = 
{
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1, 0, 1, 2, 3, 4, 5, 6,  7, 8,-1,-1,-1,-1,-1,-1,
    -1, 9,10,11,12,13,14,15, 16,-1,17,18,19,20,21,-1,
    22,23,24,25,26,27,28,29, 30,31,32,-1,-1,-1,-1,-1,
    -1,33,34,35,36,37,38,39, 40,41,42,43,-1,44,45,46,
    47,48,49,50,51,52,53,54, 55,56,57,-1,-1,-1,-1,-1,
};

int wl_base58_encode(const void *data,size_t data_len,char *b58,size_t b58_len)
{
    const uint8_t *bytes = data;
    size_t i,j,size,zc = 0;
    uint32_t carry;

    while (zc < data_len && bytes[zc] == 0)
    {
        ++zc;
    }

    size = (data_len - zc) * 138 / 100 + 1;
    uint8_t buf[size];
    memset(buf,0,size);
    for (i = zc; i < data_len; i++)
    {
        carry = bytes[i];
        for (j = size; j > 0 ; j--)
        {
            carry += ((uint32_t)buf[j - 1]) << 8;
            buf[j - 1] = carry % 58;
            carry /= 58;
        }
    }

    for (j = 0; j < size && !buf[j]; ++j);

    if (b58_len < (zc + size - j) + 1)
    {
        return -1;
    }

    while (zc-- > 0)
    {
        *(b58++) = '1';
    }
    while (j < size)
    {
        *(b58++) = b58_code[buf[j++]];
    }
    *b58 = '\0';

    return 0;
}

int wl_base58_decode(const char *b58,void *data,size_t *data_len)
{
    uint8_t *bytes = data;
    size_t j,size,zc = 0;
    uint32_t carry;
    while (*b58 == '1')
    {
        b58++;
        zc++;
    }
    size = strlen(b58) * 733 / 1000 + 1;
    uint8_t buf[size];
    memset(buf,0,size);

    while (*b58)
    {
        carry = b58_map[*(const uint8_t *)(b58++)];
        if (carry < 0)
        {
            return -1;
        }
        for (j = size; j > 0; j--)
        {
            carry += (uint32_t)buf[j - 1] * 58;
            buf[j - 1] = carry & 0xff;
            carry >>= 8;
        }
    }
    for (j = 0; j < size && !buf[j]; ++j);
    
    if (*data_len < zc + size - j)
    {
        return -1;
    }
    memset(bytes,0,zc);
    memcpy(bytes + zc,&buf[j],size - j);
    *data_len = zc + size - j;
    return 0;
}

int wl_base58_checkencode(const void *data,size_t data_len,char *b58,size_t b58_len)
{
    uint8_t buf[data_len + 32];
    memcpy(buf,data,data_len);
    wl_hash256d(buf,data_len,&buf[data_len]);
    return wl_base58_encode(buf,data_len + 4,b58,b58_len);
}

int wl_base58_checkdecode(const char *b58,void *data,size_t *data_len)
{
    size_t len = strlen(b58);
    uint8_t buf[len],md[32];
    if (wl_base58_decode(b58,buf,&len) < 0 || len < 4 + 1 || *data_len < len - 4)
    {
        return -1;
    }
    len -= 4;

    wl_hash256d(buf,len,md);
    if (memcmp(md,&buf[len],4) != 0)
    {
        return -1;
    }
    memcpy(data,buf,len);
    *data_len = len;
    return 0; 
}

